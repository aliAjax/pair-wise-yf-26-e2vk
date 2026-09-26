import base64
import hashlib
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, PreservationStore


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


class DeclassificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        # 保密期限今天到期，可进解密队列
        self.archive = self.store.create_archive("owner", "到期解密档案", date.today().isoformat())
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "records/one.xml", "content_b64": base64.b64encode(b"<record><id>1</id></record>").decode()},
            {"path": "README.txt", "content_b64": base64.b64encode(b"archive readme").decode()},
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def _migrate_xml(self):
        return self.store.migrate(
            "owner", self.version["id"], "records/one.xml", "records/one.html", "html",
            base64.b64encode(b"<html><body><p>1</p></body></html>").decode(),
        )

    def test_only_expired_archives_enter_queue(self):
        future = self.store.create_archive("owner", "未到期档案", (date.today() + timedelta(days=30)).isoformat())
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_declassification("owner", future["id"], "申请公开")
        self.assertEqual(ctx.exception.code, "not_expired")

    def test_unmigrated_files_block_submission_until_migrated(self):
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_declassification("owner", self.archive["id"], "申请公开")
        self.assertEqual(ctx.exception.code, "pending_migration")
        self.assertEqual(ctx.exception.extra["files"], ["records/one.xml"])
        self._migrate_xml()
        req = self.store.submit_declassification("owner", self.archive["id"], "申请公开")
        self.assertEqual(req["status"], "pending")
        self.assertEqual(req["round"], 1)

    def test_single_pending_request_and_review_flow(self):
        self._migrate_xml()
        req = self.store.submit_declassification("owner", self.archive["id"], "首次申请")
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_declassification("owner", self.archive["id"], "重复申请")
        self.assertEqual(ctx.exception.code, "request_pending")
        # 提出人不能复核自己的申请
        with self.assertRaises(BusinessError) as ctx:
            self.store.review_declassification("owner", req["id"], "approve", "")
        self.assertEqual(ctx.exception.code, "self_review_forbidden")
        # 驳回必须写明意见
        with self.assertRaises(BusinessError) as ctx:
            self.store.review_declassification("archivist", req["id"], "reject", "")
        self.assertEqual(ctx.exception.code, "comment_required")
        rejected = self.store.review_declassification("archivist", req["id"], "reject", "请补充解密依据")
        self.assertEqual(rejected["status"], "rejected")
        with self.assertRaises(BusinessError) as ctx:
            self.store.review_declassification("archivist", req["id"], "approve", "")
        self.assertEqual(ctx.exception.code, "already_reviewed")
        # 补充后重提，轮次记为 2
        req2 = self.store.submit_declassification("owner", self.archive["id"], "补充依据后重提")
        self.assertEqual(req2["round"], 2)
        approved = self.store.review_declassification("archivist", req2["id"], "approve", "同意公开")
        self.assertEqual(approved["status"], "approved")
        status = self.store.archive_status("owner", self.archive["id"])
        self.assertEqual(status["archive"]["restricted"], 0)
        self.assertEqual([r["round_no"] for r in status["declassification_requests"]], [1, 2])
        self.assertEqual(status["declassification_requests"][0]["review_comment"], "请补充解密依据")
        # 已公开的档案不能再次进入队列
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_declassification("owner", self.archive["id"], "再次申请")
        self.assertEqual(ctx.exception.code, "already_public")

    def test_public_catalog_and_member_only_content(self):
        self._migrate_xml()
        # 批准前公众查不到目录和清单
        self.assertEqual(self.store.public_catalog()["archives"], [])
        with self.assertRaises(BusinessError) as ctx:
            self.store.public_archive(self.archive["id"])
        self.assertEqual(ctx.exception.status, 404)
        req = self.store.submit_declassification("owner", self.archive["id"], "申请公开")
        self.store.review_declassification("archivist", req["id"], "approve", "同意")
        catalog = self.store.public_catalog()["archives"]
        self.assertEqual([a["name"] for a in catalog], ["到期解密档案"])
        self.assertTrue(catalog[0]["declassified_at"])
        detail = self.store.public_archive(self.archive["id"])
        latest = detail["versions"][-1]
        paths = {f["path"] for f in latest["files"]}
        self.assertEqual(paths, {"records/one.html", "README.txt"})
        self.assertTrue(all(set(f) == {"path", "sha256", "size"} for f in latest["files"]))
        # 正文仍要成员权限：非成员 403，成员可取回原文
        with self.assertRaises(BusinessError) as ctx:
            self.store.get_file_content("outsider", latest["id"], "records/one.html")
        self.assertEqual(ctx.exception.status, 403)
        content, _ = self.store.get_file_content("owner", latest["id"], "records/one.html")
        self.assertEqual(content, b"<html><body><p>1</p></body></html>")


if __name__ == "__main__":
    unittest.main()
