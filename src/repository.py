from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ENTITY, ID_PREFIX, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS seal_cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    status TEXT NOT NULL CHECK(status IN ('open','confirmed','resolved')),
                    broken_event_id INTEGER NOT NULL,
                    break_detail TEXT NOT NULL,
                    discovered_by TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    evidence_summary TEXT NOT NULL,
                    scope_note TEXT,
                    confirmed_by TEXT,
                    confirmed_at TEXT,
                    locked_through_event_id INTEGER,
                    resolution_note TEXT,
                    resolved_by TEXT,
                    resolved_at TEXT,
                    resume_event_id INTEGER,
                    created_at TEXT NOT NULL
                );
            """)

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def find_chain_breaks(self, after_event_id: int = 0) -> List[Dict[str, Any]]:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM audit_events WHERE id>? ORDER BY id", (after_event_id,)
            ).fetchall()
            boundary = None
            if after_event_id:
                boundary = self.conn.execute(
                    "SELECT entry_hash FROM audit_events WHERE id=?", (after_event_id,)
                ).fetchone()
        previous = boundary["entry_hash"] if boundary else "GENESIS"
        breaks: List[Dict[str, Any]] = []
        for row in rows:
            if row["previous_hash"] != previous:
                breaks.append({
                    "event_id": row["id"], "reason": "previous_hash与前一事件不衔接",
                    "expected_previous": previous, "actual_previous": row["previous_hash"],
                })
            else:
                payload = {
                    "action": row["action"], "entity_type": row["entity_type"],
                    "entity_id": row["entity_id"], "actor": row["actor"],
                    "detail": json.loads(row["detail"]), "created_at": row["created_at"],
                }
                digest = calculate_hash(previous, payload)
                if digest != row["entry_hash"]:
                    breaks.append({
                        "event_id": row["id"], "reason": "entry_hash校验失败",
                        "expected_hash": digest, "actual_hash": row["entry_hash"],
                    })
            previous = row["entry_hash"]
        return breaks

    def verify_audit_chain(self) -> bool:
        return not self.find_chain_breaks()

    def last_audit_event_id(self) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT id FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return int(row["id"]) if row else 0

    def affected_item_ids(self, broken_event_id: int,
                          through_event_id: Optional[int] = None) -> List[int]:
        sql = """SELECT DISTINCT entity_id FROM audit_events
                 WHERE entity_type=? AND id>=?"""
        params: list = [ENTITY, broken_event_id]
        if through_event_id:
            sql += " AND id<=?"
            params.append(through_event_id)
        sql += " ORDER BY entity_id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [int(row["entity_id"]) for row in rows]

    @staticmethod
    def _seal(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        item["break_detail"] = json.loads(item["break_detail"])
        return item

    def create_seal_case(self, broken_event_id: int, break_detail: Dict[str, Any],
                         discovered_by: str, reason: str,
                         evidence_summary: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """INSERT INTO seal_cases(status, broken_event_id, break_detail, discovered_by,
                   reason, evidence_summary, created_at) VALUES('open',?,?,?,?,?,?)""",
                (broken_event_id,
                 json.dumps(break_detail, ensure_ascii=False, sort_keys=True),
                 discovered_by, reason, evidence_summary, now),
            )
            case_id = int(cur.lastrowid)
        return self.get_seal_case(case_id)

    def get_seal_case(self, case_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM seal_cases WHERE id=?", (case_id,)).fetchone()
        if row is None:
            raise NotFoundError("处置单不存在")
        return self._seal(row)

    def list_seal_cases(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM seal_cases ORDER BY id DESC").fetchall()
        return [self._seal(row) for row in rows]

    def active_seal_case(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                """SELECT * FROM seal_cases WHERE status IN ('open','confirmed')
                   ORDER BY id DESC LIMIT 1""").fetchone()
        return self._seal(row) if row else None

    def latest_resolved_seal_case(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                """SELECT * FROM seal_cases WHERE status='resolved'
                   ORDER BY id DESC LIMIT 1""").fetchone()
        return self._seal(row) if row else None

    def confirm_seal_case(self, case_id: int, scope_note: str, confirmer: str,
                          locked_through_event_id: int) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE seal_cases SET status='confirmed', scope_note=?, confirmed_by=?,
                   confirmed_at=?, locked_through_event_id=? WHERE id=? AND status='open'""",
                (scope_note, confirmer, now, locked_through_event_id, case_id),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute(
                    "SELECT 1 FROM seal_cases WHERE id=?", (case_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("处置单不存在")
                raise ConflictError("处置单状态已变化，请刷新后重试")
        return self.get_seal_case(case_id)

    def resolve_seal_case(self, case_id: int, resolution_note: str,
                          resolver: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE seal_cases SET status='resolved', resolution_note=?, resolved_by=?,
                   resolved_at=? WHERE id=? AND status='confirmed'""",
                (resolution_note, resolver, now, case_id),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute(
                    "SELECT 1 FROM seal_cases WHERE id=?", (case_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("处置单不存在")
                raise ConflictError("处置单状态已变化，请刷新后重试")
        return self.get_seal_case(case_id)

    def set_seal_resume_event(self, case_id: int, event_id: int) -> Dict[str, Any]:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE seal_cases SET resume_event_id=? WHERE id=?", (event_id, case_id))
        return self.get_seal_case(case_id)

    def close(self) -> None:
        with self._lock:
            self.conn.close()
