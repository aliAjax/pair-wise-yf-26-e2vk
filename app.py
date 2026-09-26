"""数字档案长期保存服务：SQLite 多副本、哈希校验、修复与迁移。"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "preservation.db"
MAX_FILE_SIZE = 10 * 1024 * 1024
# 这些扩展名属于旧格式：最新版本中仍存在这些文件时，解密申请暂不受理。
LEGACY_EXTENSIONS = {".xml", ".tif", ".tiff", ".gif", ".bmp", ".doc", ".rtf"}


class BusinessError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request", details: dict | None = None):
        super().__init__(message)
        self.message, self.status, self.code, self.details = message, status, code, details


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def verify_manifest(files: object) -> list[dict]:
    if not isinstance(files, list) or not files:
        raise BusinessError("files 必须是非空数组", 422, "invalid_manifest")
    result, seen = [], set()
    for item in files:
        if not isinstance(item, dict):
            raise BusinessError("文件条目必须是对象", 422, "invalid_manifest")
        raw_path = str(item.get("path", "")).strip().replace("\\", "/")
        pure = PurePosixPath(raw_path)
        if not raw_path or pure.is_absolute() or ".." in pure.parts or pure.name in {"", ".", ".."}:
            raise BusinessError(f"档案路径不安全: {raw_path}", 422, "unsafe_path")
        if raw_path in seen:
            raise BusinessError(f"档案路径重复: {raw_path}", 409, "duplicate_path")
        seen.add(raw_path)
        encoded = item.get("content_b64")
        if not isinstance(encoded, str):
            raise BusinessError(f"{raw_path} 缺少 content_b64", 422, "content_required")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise BusinessError(f"{raw_path} 不是合法 Base64", 422, "invalid_base64")
        if len(content) > MAX_FILE_SIZE:
            raise BusinessError(f"{raw_path} 超过单文件大小限制", 413, "file_too_large")
        result.append(
            {"path": raw_path, "content": content, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        )
    return result


class PreservationStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = str(db_path)
        self._lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def init_schema(self) -> None:
        with self._lock, self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner','archivist','auditor'))
                );
                CREATE TABLE IF NOT EXISTS archives(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    owner_id TEXT NOT NULL REFERENCES users(id),
                    retention_until TEXT NOT NULL,
                    restricted INTEGER NOT NULL DEFAULT 1 CHECK(restricted IN (0,1)),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS archive_members(
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    user_id TEXT NOT NULL REFERENCES users(id),
                    permission TEXT NOT NULL CHECK(permission IN ('read','write')),
                    PRIMARY KEY(archive_id,user_id)
                );
                CREATE TABLE IF NOT EXISTS archive_versions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'verified' CHECK(state IN ('verified','degraded')),
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    UNIQUE(archive_id,version)
                );
                CREATE TABLE IF NOT EXISTS archive_files(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    UNIQUE(version_id,path)
                );
                CREATE TABLE IF NOT EXISTS copies(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    location TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'healthy' CHECK(state IN ('healthy','corrupt','degraded')),
                    created_at TEXT NOT NULL,
                    last_verified_at TEXT,
                    UNIQUE(version_id,location)
                );
                CREATE TABLE IF NOT EXISTS copy_files(
                    copy_id INTEGER NOT NULL REFERENCES copies(id),
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    PRIMARY KEY(copy_id,path)
                );
                CREATE TABLE IF NOT EXISTS migrations(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    target_version_id INTEGER NOT NULL UNIQUE REFERENCES archive_versions(id),
                    source_path TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    target_format TEXT NOT NULL,
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS declassification_requests(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    requested_by TEXT NOT NULL REFERENCES users(id),
                    reason TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL CHECK(state IN ('pending','approved','rejected')),
                    attempt INTEGER NOT NULL DEFAULT 1,
                    reviewer_id TEXT REFERENCES users(id),
                    review_comment TEXT,
                    reviewed_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_declass_archive ON declassification_requests(archive_id,id);
                CREATE UNIQUE INDEX IF NOT EXISTS uq_declass_pending_archive
                    ON declassification_requests(archive_id) WHERE state='pending';
                """
            )

    def seed(self) -> None:
        self.init_schema()
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO users(id,name,role) VALUES(?,?,?)",
                [
                    ("owner", "机构档案负责人", "owner"),
                    ("archivist", "档案管理员", "archivist"),
                    ("auditor", "独立审计员", "auditor"),
                    ("outsider", "未授权访客", "auditor"),
                ],
            )
        self._seed_demo()

    def _seed_demo(self) -> None:
        """写入演示用解密场景数据，已存在同名档案时跳过。"""
        today = date.today()
        with self.connect() as conn:
            if conn.execute("SELECT COUNT(*) FROM archives").fetchone()[0]:
                return
            past = (today - timedelta(days=30)).isoformat()
            future = (today + timedelta(days=3650)).isoformat()

            def add_archive(name: str, retention: str, restricted: int) -> int:
                cur = conn.execute(
                    "INSERT INTO archives(name,owner_id,retention_until,restricted,created_at) VALUES(?,?,?,?,?)",
                    (name, "owner", retention, restricted, now()),
                )
                aid = cur.lastrowid
                conn.execute(
                    "INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,'owner','write')", (aid,)
                )
                return aid

            def add_version(aid: int, version_no: int, actor: str, files: list[tuple[str, bytes]]) -> int:
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (aid, version_no, actor, now()),
                )
                vid = cur.lastrowid
                for path, content in files:
                    conn.execute(
                        "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                        (vid, path, hashlib.sha256(content).hexdigest(), len(content), content),
                    )
                return vid

            def grant_archivist(aid: int) -> None:
                conn.execute(
                    "INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,'archivist','write')", (aid,)
                )

            # A：已解密公开的到期档案。
            a = add_archive("已公开历史测绘档案", past, 0)
            v1 = add_version(a, 1, "owner", [("maps/overview.html", b"<html><body>overview</body></html>"),
                                              ("README.txt", b"public archive readme")])
            self._audit(conn, a, "owner", "declassify.approve",
                        {"request_id": 0, "reviewer_id": "archivist", "restricted": 0})

            # B：已到期但最新版本仍含旧格式 .tif/.xml，迁移前申请不受理。
            grant_archivist(a)
            b = add_archive("到期待解密-含旧格式", past, 1)
            add_version(b, 1, "archivist", [("scan/page.tif", b"\x49\x49\x2a\x00legacy-tif"),
                                             ("records/meta.xml", b"<meta/>"),
                                             ("notes.txt", b"needs migration")])

            # C：已到期且全部为新格式，且已有一份由 archivist 提交的待处理申请（等 owner 复核）。
            grant_archivist(b)
            c = add_archive("到期待解密-可受理", past, 1)
            cv1 = add_version(c, 1, "archivist", [("scan/page.tif", b"\x49\x49\x2a\x00old"),
                                                   ("index/data.xml", b"<index>data</index>")])
            cv2 = add_version(c, 2, "archivist", [("scan/page.png", b"\x89PNG new-format"),
                                                   ("index/data.json", b'{"index":"data"}')])
            conn.execute(
                "INSERT INTO migrations(source_version_id,target_version_id,source_path,target_path,target_format,actor_id,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (cv1, cv2, "scan/page.tif", "scan/page.png", "png", "archivist", now()),
            )
            conn.execute(
                "INSERT INTO declassification_requests(archive_id,requested_by,reason,state,attempt,created_at)"
                " VALUES(?,?,?,?,1,?)",
                (c, "archivist", "保密期限已过，公众目录应可检索", "pending", now()),
            )

            # D：尚未到期，不能进队列。
            grant_archivist(c)
            d = add_archive("未到期受限档案", future, 1)
            grant_archivist(d)

    def _user(self, conn, user_id: str | None, roles: set[str] | None = None) -> sqlite3.Row:
        if not user_id:
            raise BusinessError("缺少 X-User-Id", 401, "authentication_required")
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            raise BusinessError("用户不存在", 401, "unknown_user")
        if roles and user["role"] not in roles:
            raise BusinessError("当前角色无权执行此操作", 403, "forbidden")
        return user

    def _access(self, conn, archive_id: int, user: sqlite3.Row, require_write: bool = False) -> None:
        archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
        if not archive:
            raise BusinessError("档案不存在", 404, "not_found")
        if archive["owner_id"] == user["id"]:
            return
        row = conn.execute(
            "SELECT permission FROM archive_members WHERE archive_id=? AND user_id=?", (archive_id, user["id"])
        ).fetchone()
        if not row or (require_write and row["permission"] != "write"):
            raise BusinessError("没有该受限档案的访问权限", 403, "forbidden")

    def _audit(self, conn, archive_id: int, actor: str, action: str, detail: dict) -> None:
        conn.execute(
            "INSERT INTO audit_log(archive_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)",
            (archive_id, actor, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), now()),
        )

    def create_archive(self, user_id: str, name: str, retention_until: str, restricted: bool = True) -> dict:
        name = name.strip()
        if len(name) < 2:
            raise BusinessError("档案名称至少 2 字", 422, "invalid_name")
        try:
            deadline = date.fromisoformat(retention_until)
        except ValueError:
            raise BusinessError("retention_until 必须是 YYYY-MM-DD", 422, "invalid_retention")
        if deadline < date.today():
            raise BusinessError("保留期限不能早于今天", 422, "retention_in_past")
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            try:
                cur = conn.execute(
                    "INSERT INTO archives(name,owner_id,retention_until,restricted,created_at) VALUES(?,?,?,?,?)",
                    (name, user_id, retention_until, int(bool(restricted)), now()),
                )
            except sqlite3.IntegrityError:
                raise BusinessError("档案名称已存在", 409, "archive_exists")
            archive_id = cur.lastrowid
            conn.execute(
                "INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,'write')", (archive_id, user_id)
            )
            self._audit(conn, archive_id, user_id, "archive.create", {"retention_until": retention_until, "restricted": restricted})
            return {"id": archive_id, "name": name, "retention_until": retention_until, "restricted": restricted}

    def grant(self, actor_id: str, archive_id: int, user_id: str, permission: str) -> dict:
        if permission not in {"read", "write"}:
            raise BusinessError("permission 必须是 read 或 write", 422, "invalid_permission")
        with self.connect() as conn:
            actor = self._user(conn, actor_id)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            if archive["owner_id"] != actor_id:
                raise BusinessError("只有档案所有者可以授权", 403, "forbidden")
            self._user(conn, user_id)
            conn.execute(
                """INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,?)
                   ON CONFLICT(archive_id,user_id) DO UPDATE SET permission=excluded.permission""",
                (archive_id, user_id, permission),
            )
            self._audit(conn, archive_id, actor_id, "access.grant", {"user_id": user_id, "permission": permission})
            return {"archive_id": archive_id, "user_id": user_id, "permission": permission}

    def ingest_version(self, actor_id: str, archive_id: int, files: object) -> dict:
        manifest = verify_manifest(files)
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            self._access(conn, archive_id, actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (archive_id,)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (archive_id, version_no, actor_id, now()),
                )
                version_id = cur.lastrowid
                for item in manifest:
                    conn.execute(
                        "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                        (version_id, item["path"], item["sha256"], item["size"], item["content"]),
                    )
                self._audit(
                    conn, archive_id, actor_id, "version.ingest",
                    {"version_id": version_id, "version": version_no, "files": len(manifest),
                     "manifest": [{"path": x["path"], "sha256": x["sha256"], "size": x["size"]} for x in manifest]},
                )
                return {"id": version_id, "archive_id": archive_id, "version": version_no, "file_count": len(manifest)}
            except Exception:
                conn.rollback()
                raise

    def add_copy(self, actor_id: str, version_id: int, location: str) -> dict:
        location = location.strip()
        if len(location) < 2:
            raise BusinessError("副本位置不能为空", 422, "invalid_location")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "INSERT INTO copies(version_id,location,created_at,last_verified_at) VALUES(?,?,?,?)",
                    (version_id, location, now(), now()),
                )
                copy_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
                    (copy_id, version_id),
                )
                self._audit(conn, version["archive_id"], actor_id, "copy.create", {"copy_id": copy_id, "version_id": version_id, "location": location})
                return {"id": copy_id, "version_id": version_id, "location": location, "state": "healthy"}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("该版本的副本位置已存在", 409, "copy_exists")
            except Exception:
                conn.rollback()
                raise

    def get_version(self, user_id: str, version_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], user)
            files = conn.execute(
                "SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path", (version_id,)
            ).fetchall()
            copies = conn.execute(
                "SELECT id,location,state,last_verified_at FROM copies WHERE version_id=? ORDER BY id", (version_id,)
            ).fetchall()
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
            return {"version": dict(version), "archive": dict(archive), "files": [dict(x) for x in files], "copies": [dict(x) for x in copies]}

    def verify_copy(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user)
                stored = conn.execute(
                    "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (copy_id,)
                ).fetchall()
                corrupt_paths = [r["path"] for r in stored if hashlib.sha256(r["content"]).hexdigest() != r["sha256"] or len(r["content"]) != r["size"]]
                repaired = False
                if not corrupt_paths:
                    conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                    result_state = "healthy"
                else:
                    conn.execute("UPDATE copies SET state='corrupt',last_verified_at=? WHERE id=?", (now(), copy_id))
                    healthy = conn.execute(
                        "SELECT id FROM copies WHERE version_id=? AND id<>? AND state='healthy' ORDER BY last_verified_at DESC LIMIT 1",
                        (copy["version_id"], copy_id),
                    ).fetchone()
                    result_state = "degraded"
                    if healthy:
                        donor = conn.execute(
                            "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (healthy["id"],)
                        ).fetchall()
                        donor_by_path = {r["path"]: r for r in donor}
                        expected = {r["path"]: r for r in conn.execute(
                            "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (copy["version_id"],)
                        ).fetchall()}
                        if set(donor_by_path) == set(expected) and all(
                            hashlib.sha256(donor_by_path[p]["content"]).hexdigest() == expected[p]["sha256"] for p in expected
                        ):
                            conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
                            conn.execute(
                                """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                                   SELECT ?,path,sha256,size,content FROM copy_files WHERE copy_id=?""",
                                (copy_id, healthy["id"]),
                            )
                            conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                            repaired, result_state = True, "healthy"
                    if result_state == "degraded":
                        conn.execute("UPDATE archive_versions SET state='degraded' WHERE id=?", (copy["version_id"],))
                self._audit(
                    conn, version["archive_id"], user_id, "copy.verify",
                    {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths, "repaired": repaired},
                )
                return {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths, "repaired": repaired}
            except Exception:
                conn.rollback()
                raise

    def simulate_corruption(self, user_id: str, copy_id: int, path: str) -> dict:
        """仅用于演示和测试，在受控环境中模拟底层介质损坏。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user, require_write=True)
            row = conn.execute("SELECT content FROM copy_files WHERE copy_id=? AND path=?", (copy_id, path)).fetchone()
            if not row:
                raise BusinessError("副本文件不存在", 404, "not_found")
            damaged = bytes([row["content"][0] ^ 0xFF]) + row["content"][1:] if row["content"] else b"corrupt"
            conn.execute("UPDATE copy_files SET content=? WHERE copy_id=? AND path=?", (damaged, copy_id, path))
            conn.execute("UPDATE copies SET state='corrupt' WHERE id=?", (copy_id,))
            self._audit(conn, version["archive_id"], user_id, "copy.simulate_corruption", {"copy_id": copy_id, "path": path})
            return {"copy_id": copy_id, "path": path, "state": "corrupt"}

    def migrate(self, actor_id: str, version_id: int, source_path: str, target_path: str, target_format: str, content_b64: str) -> dict:
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            source_version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not source_version:
                raise BusinessError("源档案版本不存在", 404, "not_found")
            self._access(conn, source_version["archive_id"], actor, require_write=True)
            source = conn.execute(
                "SELECT * FROM archive_files WHERE version_id=? AND path=?", (version_id, source_path)
            ).fetchone()
            if not source:
                raise BusinessError("源文件不存在", 404, "source_not_found")
            converted = verify_manifest([{"path": target_path, "content_b64": content_b64}])[0]
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (source_version["archive_id"],)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (source_version["archive_id"], version_no, actor_id, now()),
                )
                target_version_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO archive_files(version_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files
                       WHERE version_id=? AND path<>?""",
                    (target_version_id, version_id, source_path),
                )
                conn.execute(
                    "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                    (target_version_id, converted["path"], converted["sha256"], converted["size"], converted["content"]),
                )
                conn.execute(
                    "INSERT INTO migrations(source_version_id,target_version_id,source_path,target_path,target_format,actor_id,created_at) VALUES(?,?,?,?,?,?,?)",
                    (version_id, target_version_id, source_path, converted["path"], target_format.strip(), actor_id, now()),
                )
                self._audit(
                    conn, source_version["archive_id"], actor_id, "format.migrate",
                    {"source_version_id": version_id, "target_version_id": target_version_id,
                     "source_path": source_path, "target_path": converted["path"], "target_format": target_format.strip()},
                )
                return {"id": target_version_id, "version": version_no, "source_version_id": version_id, "target_path": converted["path"]}
            except Exception:
                conn.rollback()
                raise

    def archive_status(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            versions = conn.execute("SELECT id,version,state,created_at FROM archive_versions WHERE archive_id=? ORDER BY version", (archive_id,)).fetchall()
            deadline = date.fromisoformat(archive["retention_until"])
            return {
                "archive": dict(archive),
                "days_remaining": (deadline - date.today()).days,
                "versions": [dict(v) | {"file_count": conn.execute("SELECT COUNT(*) FROM archive_files WHERE version_id=?", (v["id"],)).fetchone()[0],
                                         "copy_count": conn.execute("SELECT COUNT(*) FROM copies WHERE version_id=?", (v["id"],)).fetchone()[0]}
                             for v in versions],
                "audit": [dict(r) | {"detail": json.loads(r["detail"])} for r in conn.execute("SELECT * FROM audit_log WHERE archive_id=? ORDER BY id", (archive_id,)).fetchall()],
            }

    def _latest_version(self, conn, archive_id: int) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM archive_versions WHERE archive_id=? ORDER BY version DESC LIMIT 1", (archive_id,)
        ).fetchone()

    def _unmigrated_files(self, conn, archive_id: int) -> list[dict]:
        """最新版本中扩展名称属于旧格式、仍未迁移到新格式的文件。"""
        latest = self._latest_version(conn, archive_id)
        if not latest:
            return []
        rows = conn.execute("SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path",
                            (latest["id"],)).fetchall()
        return [dict(r) for r in rows if PurePosixPath(r["path"]).suffix.lower() in LEGACY_EXTENSIONS]

    def _request_row(self, conn, request_id: int) -> sqlite3.Row:
        req = conn.execute("SELECT * FROM declassification_requests WHERE id=?", (request_id,)).fetchone()
        if not req:
            raise BusinessError("解密申请不存在", 404, "not_found")
        return req

    def submit_declassification(self, user_id: str, archive_id: int, reason: str) -> dict:
        reason = (reason or "").strip()
        with self.connect() as conn:
            user = self._user(conn, user_id)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            # 解密申请是 owner/archivist 的职责行为，无需事先被加为成员；其他身份须有访问权。
            if user["role"] not in {"owner", "archivist"}:
                self._access(conn, archive_id, user)
            if archive["restricted"] == 0:
                raise BusinessError("该档案已解密，无需再次申请", 409, "already_public")
            deadline = date.fromisoformat(archive["retention_until"])
            if deadline >= date.today():
                raise BusinessError(
                    f"保密期限未到（{archive['retention_until']}），到期档案才能提交解密", 409, "retention_active"
                )
            pending = conn.execute(
                "SELECT id FROM declassification_requests WHERE archive_id=? AND state='pending'", (archive_id,)
            ).fetchone()
            if pending:
                raise BusinessError(
                    "该档案已有一份待处理的解密申请，一个档案只能保留一份待处理申请", 409, "pending_exists"
                )
            unmigrated = self._unmigrated_files(conn, archive_id)
            if unmigrated:
                raise BusinessError(
                    "档案中仍有文件未迁移到新格式，迁移完成后再提交",
                    422, "unmigrated_files", {"files": unmigrated},
                )
            try:
                conn.execute("BEGIN IMMEDIATE")
                prior = conn.execute(
                    "SELECT COALESCE(MAX(attempt),0) FROM declassification_requests WHERE archive_id=?", (archive_id,)
                ).fetchone()[0]
                attempt = prior + 1
                cur = conn.execute(
                    "INSERT INTO declassification_requests(archive_id,requested_by,reason,state,attempt,created_at)"
                    " VALUES(?,?,?,'pending',?,?)",
                    (archive_id, user_id, reason, attempt, now()),
                )
                request_id = cur.lastrowid
                self._audit(conn, archive_id, user_id, "declassify.submit",
                            {"request_id": request_id, "attempt": attempt, "reason": reason})
                return {"id": request_id, "archive_id": archive_id, "requested_by": user_id,
                        "state": "pending", "attempt": attempt}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError(
                    "该档案已有一份待处理的解密申请，一个档案只能保留一份待处理申请", 409, "pending_exists"
                )
            except Exception:
                conn.rollback()
                raise

    def review_declassification(self, reviewer_id: str, request_id: int, approve: bool, comment: str) -> dict:
        comment = (comment or "").strip()
        if not approve and not comment:
            raise BusinessError("驳回必须写明意见", 422, "comment_required")
        with self.connect() as conn:
            reviewer = self._user(conn, reviewer_id, {"owner", "archivist"})
            req = self._request_row(conn, request_id)
            if req["requested_by"] == reviewer["id"]:
                raise BusinessError("提出人不能复核自己的申请，请由另一名同事处理", 403, "self_review_forbidden")
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (req["archive_id"],)).fetchone()
            self._access(conn, archive["id"], reviewer)
            if req["state"] != "pending":
                raise BusinessError(f"该申请已{('批准' if req['state']=='approved' else '驳回')}", 409, "request_closed")
            new_state = "approved" if approve else "rejected"
            conn.execute(
                "UPDATE declassification_requests SET state=?,reviewer_id=?,review_comment=?,reviewed_at=? WHERE id=?",
                (new_state, reviewer_id, comment, now(), request_id),
            )
            detail = {"request_id": request_id, "comment": comment, "attempt": req["attempt"]}
            if approve:
                conn.execute("UPDATE archives SET restricted=0 WHERE id=?", (archive["id"],))
                detail["restricted"] = 0
            self._audit(conn, archive["id"], reviewer_id,
                        "declassify.approve" if approve else "declassify.reject", detail)
            return {"id": request_id, "archive_id": archive["id"], "state": new_state,
                    "reviewer_id": reviewer_id, "review_comment": comment}

    def list_pending_requests(self, user_id: str) -> dict:
        with self.connect() as conn:
            self._user(conn, user_id, {"owner", "archivist"})
            rows = conn.execute(
                """SELECT r.id,r.archive_id,a.name AS archive_name,r.requested_by,r.reason,r.attempt,r.created_at
                   FROM declassification_requests r JOIN archives a ON a.id=r.archive_id
                   WHERE r.state='pending' ORDER BY r.id"""
            ).fetchall()
            return {"pending": [dict(r) for r in rows]}

    def list_archive_requests(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id)
            self._access(conn, archive_id, user)
            rows = conn.execute(
                """SELECT id,archive_id,requested_by,reason,state,attempt,reviewer_id,review_comment,reviewed_at,created_at
                   FROM declassification_requests WHERE archive_id=? ORDER BY id""",
                (archive_id,),
            ).fetchall()
            return {"archive_id": archive_id, "requests": [dict(r) for r in rows]}

    def public_catalog(self) -> dict:
        """公开目录：任何访客（无需登录）都能查到已解密档案的名称与期限。"""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id,name,retention_until FROM archives WHERE restricted=0 ORDER BY id"
            ).fetchall()
            return {"public": [dict(r) for r in rows]}

    def public_manifest(self, archive_id: int) -> dict:
        """公开清单：已解密档案的最新版本文件列表（哈希、大小），不含正文内容。"""
        with self.connect() as conn:
            archive = conn.execute("SELECT id,name,retention_until,restricted FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            if archive["restricted"]:
                raise BusinessError("该档案仍受限，公众无法查看", 403, "restricted")
            latest = self._latest_version(conn, archive_id)
            if not latest:
                files, version_info = [], None
            else:
                files = [dict(r) for r in conn.execute(
                    "SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path", (latest["id"],)
                ).fetchall()]
                version_info = {"version": latest["version"], "state": latest["state"]}
            return {"archive": dict(archive), "version": version_info, "files": files}

    def get_file_content(self, user_id: str, archive_id: int, path: str) -> dict:
        """正文读取：即使档案已解密，正文仍要求成员权限。"""
        with self.connect() as conn:
            user = self._user(conn, user_id)
            self._access(conn, archive_id, user)
            latest = self._latest_version(conn, archive_id)
            if not latest:
                raise BusinessError("档案尚无文件版本", 404, "no_version")
            row = conn.execute(
                "SELECT path,sha256,size,content FROM archive_files WHERE version_id=? AND path=?",
                (latest["id"], path),
            ).fetchone()
            if not row:
                raise BusinessError("文件不存在", 404, "not_found")
            return {"archive_id": archive_id, "version": latest["version"], "path": row["path"],
                    "sha256": row["sha256"], "size": row["size"],
                    "content_b64": base64.b64encode(row["content"]).decode()}


class Handler(BaseHTTPRequestHandler):
    server_version = "Preservation/1.0"

    def _store(self):
        return self.server.store  # type: ignore[attr-defined]

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise BusinessError("请求体必须是合法 JSON", 400, "invalid_json")
        if not isinstance(data, dict):
            raise BusinessError("JSON 顶层必须是对象", 422, "invalid_json")
        return data

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method: str) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        parts = [p for p in path.split("/") if p]
        user = self.headers.get("X-User-Id", "")
        if method == "GET" and path == "/":
            body = (BASE_DIR / "web" / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if method == "GET" and path == "/health":
            return self._send(200, {"ok": True})
        store = self._store()
        if parts == ["api", "archives"] and method == "POST":
            d = self._body()
            return self._send(201, store.create_archive(user, d.get("name", ""), d.get("retention_until", ""), bool(d.get("restricted", True))))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and method == "POST":
            archive_id = int(parts[2])
            if parts[3] == "versions":
                d = self._body()
                return self._send(201, store.ingest_version(user, archive_id, d.get("files")))
            if parts[3] == "members":
                d = self._body()
                return self._send(201, store.grant(user, archive_id, d.get("user_id", ""), d.get("permission", "")))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "status" and method == "GET":
            return self._send(200, store.archive_status(user, int(parts[2])))
        if parts == ["api", "public", "catalog"] and method == "GET":
            return self._send(200, store.public_catalog())
        if len(parts) == 5 and parts[:3] == ["api", "public", "archives"] and parts[4] == "manifest" and method == "GET":
            return self._send(200, store.public_manifest(int(parts[3])))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "declassification":
            if method == "POST":
                d = self._body()
                return self._send(201, store.submit_declassification(user, int(parts[2]), d.get("reason", "")))
            if method == "GET":
                return self._send(200, store.list_archive_requests(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "files" and method == "GET":
            query = parse_qs(urlparse(self.path).query)
            path = query.get("path", [""])[0]
            return self._send(200, store.get_file_content(user, int(parts[2]), path))
        if parts == ["api", "declassification", "requests"] and method == "GET":
            return self._send(200, store.list_pending_requests(user))
        if len(parts) == 3 and parts[:2] == ["api", "declassification"] and method == "POST":
            d = self._body()
            return self._send(200, store.review_declassification(
                user, int(parts[2]), bool(d.get("approve")), d.get("comment", "")))
        if len(parts) == 3 and parts[:2] == ["api", "versions"] and method == "GET":
            return self._send(200, store.get_version(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "copies" and method == "POST":
            d = self._body()
            return self._send(201, store.add_copy(user, int(parts[2]), d.get("location", "")))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "migrate" and method == "POST":
            d = self._body()
            return self._send(201, store.migrate(user, int(parts[2]), d.get("source_path", ""), d.get("target_path", ""), d.get("target_format", ""), d.get("content_b64", "")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "verify" and method == "POST":
            return self._send(200, store.verify_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "simulate-corruption" and method == "POST":
            d = self._body()
            return self._send(200, store.simulate_corruption(user, int(parts[2]), d.get("path", "")))
        raise BusinessError("接口不存在", 404, "not_found")

    def _handle(self, method: str) -> None:
        try:
            self._dispatch(method)
        except BusinessError as exc:
            error = {"code": exc.code, "message": exc.message}
            if exc.details:
                error["details"] = exc.details
            self._send(exc.status, {"error": error})
        except (ValueError, TypeError):
            self._send(400, {"error": {"code": "invalid_path", "message": "路径参数格式错误"}})
        except Exception as exc:
            self._send(500, {"error": {"code": "internal_error", "message": str(exc)}})

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_DELETE(self): self._handle("DELETE")
    def log_message(self, fmt, *args): print(f"{self.address_string()} - {fmt % args}")


class PreservationServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, store):
        self.store = store
        super().__init__(address, Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="数字档案长期保存服务")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--port", type=int, default=8102)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    store = PreservationStore(args.db)
    store.init_schema()
    if args.seed:
        store.seed()
    if args.init or args.seed:
        print(f"数据库已初始化: {args.db}")
        return
    print(f"数字档案服务运行于 http://127.0.0.1:{args.port}")
    server = PreservationServer(("127.0.0.1", args.port), store)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
