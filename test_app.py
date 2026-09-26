import base64
import json
import tempfile
import threading
import unittest
from datetime import date, timedelta
from http.client import HTTPConnection
from pathlib import Path

from app import BusinessError, PreservationServer, PreservationStore


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.archive = self.store.create_archive("owner", "城市测绘档案", (date.today() + timedelta(days=3650)).isoformat())
        self.raw = b"<record><id>1</id></record>"
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "records/one.xml", "content_b64": base64.b64encode(self.raw).decode()},
            {"path": "README.txt", "content_b64": base64.b64encode(b"archive readme").decode()},
        ])
        self.copy1 = self.store.add_copy("owner", self.version["id"], "offline-disk-a")["id"]
        self.copy2 = self.store.add_copy("owner", self.version["id"], "offline-disk-b")["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_integrity_repair_and_format_migration(self):
        self.store.simulate_corruption("owner", self.copy1, "records/one.xml")
        result = self.store.verify_copy("owner", self.copy1)
        self.assertEqual(result["state"], "healthy")
        self.assertTrue(result["repaired"])
        self.assertEqual(result["corrupt_paths"], ["records/one.xml"])
        migrated = self.store.migrate(
            "owner", self.version["id"], "records/one.xml", "records/one.html", "html",
            base64.b64encode(b"<html><body><p>1</p></body></html>").decode(),
        )
        detail = self.store.get_version("owner", migrated["id"])
        self.assertEqual(detail["version"]["version"], 2)
        self.assertTrue(any(f["path"] == "records/one.html" for f in detail["files"]))
        status = self.store.archive_status("owner", self.archive["id"])
        self.assertGreater(status["days_remaining"], 3000)

    def test_restricted_access_and_invalid_manifest_are_rejected(self):
        with self.assertRaises(BusinessError) as ctx:
            self.store.get_version("outsider", self.version["id"])
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.ingest_version("owner", self.archive["id"], [{"path": "../escape.txt", "content_b64": "eA=="}])
        self.assertEqual(ctx.exception.code, "unsafe_path")
        with self.assertRaises(BusinessError) as ctx:
            self.store.add_copy("owner", self.version["id"], "offline-disk-a")
        self.assertEqual(ctx.exception.code, "copy_exists")

    def _expired_archive(self, files, name):
        # create_archive 不允许过去的保留期限；到期场景直接按到期日写库构造。
        retention = (date.today() - timedelta(days=10)).isoformat()
        with self.store.connect() as conn:
            cur = conn.execute(
                "INSERT INTO archives(name,owner_id,retention_until,restricted,created_at) VALUES(?,?,?,1,?)",
                (name, "owner", retention, "2020-01-01T00:00:00+00:00"),
            )
            archive_id = cur.lastrowid
            conn.execute(
                "INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,'owner','write')", (archive_id,)
            )
        self.store.ingest_version("owner", archive_id, files)
        self.store.grant("owner", archive_id, "archivist", "write")
        return {"id": archive_id, "name": name, "retention_until": retention, "restricted": True}

    def test_only_expired_archives_enter_queue(self):
        future = self.store.create_archive("owner", "未到期档案X", (date.today() + timedelta(days=1)).isoformat())
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_declassification("owner", future["id"], "公开")
        self.assertEqual(ctx.exception.code, "retention_active")
        expired = self._expired_archive([{"path": "ok.csv",
                                          "content_b64": base64.b64encode(b"a\n1\n").decode()}], "已到期档案X")
        req = self.store.submit_declassification("owner", expired["id"], "公开")
        self.assertEqual(req["state"], "pending")

    def test_unmigrated_files_block_submission_and_are_listed(self):
        archive = self._expired_archive([
            {"path": "scan/page.tif", "content_b64": base64.b64encode(b"tif-bytes").decode()},
            {"path": "records/meta.xml", "content_b64": base64.b64encode(b"<meta/>").decode()},
            {"path": "notes.txt", "content_b64": base64.b64encode(b"ok").decode()},
        ], "到期旧格式档案X")
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_declassification("archivist", archive["id"], "保密到期")
        err = ctx.exception
        self.assertEqual(err.code, "unmigrated_files")
        listed = {f["path"] for f in err.details["files"]}
        self.assertEqual(listed, {"scan/page.tif", "records/meta.xml"})

        # 迁移全部旧格式文件后，申请可受理。
        self.store.migrate("archivist", self.store.archive_status("archivist", archive["id"])["versions"][-1]["id"],
                           "scan/page.tif", "scan/page.png", "png",
                           base64.b64encode(b"png-bytes").decode())
        latest = self.store.archive_status("archivist", archive["id"])["versions"][-1]["id"]
        self.store.migrate("archivist", latest, "records/meta.xml", "records/meta.json", "json",
                           base64.b64encode(b'{"meta":1}').decode())
        req = self.store.submit_declassification("archivist", archive["id"], "保密到期")
        self.assertEqual(req["state"], "pending")
        self.assertEqual(req["attempt"], 1)

    def test_single_pending_request_per_archive(self):
        archive = self._expired_archive([
            {"path": "a.md", "content_b64": base64.b64encode(b"new format").decode()},
        ], "到期新格式档案X")
        self.store.submit_declassification("archivist", archive["id"], "公开")
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_declassification("owner", archive["id"], "再提一次")
        self.assertEqual(ctx.exception.code, "pending_exists")

    def test_self_review_forbidden_and_approval_opens_catalog(self):
        archive = self._expired_archive([
            {"path": "doc.json", "content_b64": base64.b64encode(b'{"k":1}').decode()},
        ], "到期复核档案X")
        req = self.store.submit_declassification("archivist", archive["id"], "公众需要目录")
        # 提出人不能复核自己
        with self.assertRaises(BusinessError) as ctx:
            self.store.review_declassification("archivist", req["id"], True, "同意")
        self.assertEqual(ctx.exception.code, "self_review_forbidden")

        # 另一名同事（owner）批准后不再受限
        result = self.store.review_declassification("owner", req["id"], True, "到期同意公开")
        self.assertEqual(result["state"], "approved")
        catalog = self.store.public_catalog()
        self.assertIn(archive["id"], {a["id"] for a in catalog["public"]})
        # 公众可查清单
        manifest = self.store.public_manifest(archive["id"])
        self.assertEqual([f["path"] for f in manifest["files"]], ["doc.json"])
        # 正文仍要成员权限
        with self.assertRaises(BusinessError) as ctx:
            self.store.get_file_content("outsider", archive["id"], "doc.json")
        self.assertEqual(ctx.exception.status, 403)
        content = self.store.get_file_content("owner", archive["id"], "doc.json")
        self.assertEqual(base64.b64decode(content["content_b64"]), b'{"k":1}')
        # 已解密档案无需再提申请
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_declassification("owner", archive["id"], "重复")
        self.assertEqual(ctx.exception.code, "already_public")

    def test_reject_requires_comment_and_resubmission_counts_attempts(self):
        archive = self._expired_archive([
            {"path": "v2/table.csv", "content_b64": base64.b64encode(b"a,b\n1,2\n").decode()},
        ], "到期驳回档案X")
        req_id = self.store.submit_declassification("archivist", archive["id"], "申请公开")["id"]
        with self.assertRaises(BusinessError) as ctx:
            self.store.review_declassification("owner", req_id, False, "  ")
        self.assertEqual(ctx.exception.code, "comment_required")
        self.store.review_declassification("owner", req_id, False, "清单描述不完整，请补充说明")
        # 该档案的待处理申请已清空（队列里其他档案的申请不受影响）
        pending_ids = {p["id"] for p in self.store.list_pending_requests("archivist")["pending"]}
        self.assertNotIn(req_id, pending_ids)
        again = self.store.submit_declassification("archivist", archive["id"], "已补充描述")
        self.assertEqual(again["attempt"], 2)
        history = self.store.list_archive_requests("owner", archive["id"])["requests"]
        self.assertEqual([r["state"] for r in history], ["rejected", "pending"])
        self.assertEqual(history[0]["review_comment"], "清单描述不完整，请补充说明")
        self.assertEqual(history[0]["reviewer_id"], "owner")


class PublicCatalogHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        store = PreservationStore(Path(cls.tmp.name) / "http.db")
        store.seed()
        cls.server = PreservationServer(("127.0.0.1", 0), store)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.tmp.cleanup()

    def test_public_catalog_anonymous_and_restricted_hidden(self):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/api/public/catalog")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        payload = json.loads(resp.read())
        names = [a["name"] for a in payload["public"]]
        self.assertIn("已公开历史测绘档案", names)
        self.assertNotIn("到期待解密-含旧格式", names)
        # 受限档案的公开清单返回 403
        conn.request("GET", "/api/public/archives/2/manifest")
        self.assertEqual(conn.getresponse().status, 403)
        conn.close()


if __name__ == "__main__":
    unittest.main()
