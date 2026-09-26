import json
import tempfile
import unittest
from pathlib import Path

from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES


class SealTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _item(self, ref):
        return self.service.create_item(
            {"title": f"item {ref}", "description": "seal test item",
             "severity": "major", "quantity": 5, "threshold": 10,
             "external_ref": ref}, "creator", "inspector")

    def _tamper(self, event_id):
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE audit_events SET detail=? WHERE id=?",
                (json.dumps({"tampered": True}), event_id))

    def test_report_requires_break_and_valid_role(self):
        self._item("SEAL-0")
        with self.assertRaises(ConflictError):
            self.service.report_seal_case(
                {"reason": "夜巡例行校验", "evidence_summary": "无"},
                "night", "inspector")
        self._tamper(1)
        with self.assertRaises(PermissionDenied):
            self.service.report_seal_case(
                {"reason": "r", "evidence_summary": "e"}, "night", "viewer")
        with self.assertRaises(ValidationError):
            self.service.report_seal_case(
                {"reason": "", "evidence_summary": "e"}, "night", "inspector")
        case = self.service.report_seal_case(
            {"reason": "夜巡发现历史事件被改动", "evidence_summary": "事件1哈希不符"},
            "night", "inspector")
        self.assertEqual(case["break_event_id"], 1)
        self.assertEqual(case["status"], "open")
        self.assertEqual(case["discovered_by"], "night")

    def test_freeze_confirm_resolve_lifecycle(self):
        item = self._item("SEAL-1")
        self._tamper(1)
        self.assertFalse(self.repo.verify_audit_chain())
        case = self.service.report_seal_case(
            {"reason": "夜巡发现历史事件被改动", "evidence_summary": "事件1哈希不符"},
            "mgr1", "emergency_manager")
        self.assertIn(item["id"], case["frozen_items"])
        self.assertEqual(case["progress"], {"step": 1, "total": 3, "label": "待确认影响范围"})
        with self.assertRaises(ConflictError):
            self.service.add_record(item["id"], {"kind": "evidence", "detail": "x"},
                                    "recorder", "inspector")
        with self.assertRaises(ConflictError):
            self.service.transition(item["id"], STATES[1], item["version"],
                                    "reviewer", TRANSITION_ROLES[STATES[1]][0])
        with self.assertRaises(ConflictError):
            self.service.report_seal_case(
                {"reason": "r", "evidence_summary": "e"}, "night", "inspector")
        with self.assertRaises(PermissionDenied):
            self.service.confirm_seal_case(case["id"], {"scope_note": "s"},
                                           "mgr1", "emergency_manager")
        with self.assertRaises(PermissionDenied):
            self.service.confirm_seal_case(case["id"], {"scope_note": "s"},
                                           "mgr2", "inspector")
        with self.assertRaises(ConflictError):
            self.service.resolve_seal_case(case["id"], {"resolution_note": "r"},
                                           "mgr2", "emergency_manager")
        confirmed = self.service.confirm_seal_case(
            case["id"], {"scope_note": "影响范围限于事件1之后"},
            "mgr2", "emergency_manager")
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertTrue(self.repo.is_item_frozen(item["id"]))
        resolved = self.service.resolve_seal_case(
            case["id"], {"resolution_note": "已核对纸质台账，恢复写入"},
            "mgr2", "emergency_manager")
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(resolved["progress"]["label"], "已恢复写入")
        record = self.service.add_record(
            item["id"], {"kind": "evidence", "detail": "恢复后补录"},
            "recorder", "inspector")
        self.assertEqual(record["item_id"], item["id"])
        current = self.service.get_item(item["id"], "viewer")
        self.assertFalse(current["frozen"])
        current = self.service.transition(current["id"], STATES[1], current["version"],
                                          "reviewer", TRANSITION_ROLES[STATES[1]][0])
        self.assertEqual(current["status"], STATES[1])
        events = self.service.audit("viewer")
        actions = [e["action"] for e in events]
        self.assertLess(actions.index("seal_open"), actions.index("seal_confirm"))
        self.assertLess(actions.index("seal_confirm"), actions.index("seal_resolve"))
        seal_events = [e for e in events if e["entity_type"] == "seal_case"]
        self.assertEqual(len(seal_events), 3)
        resolve_event = [e for e in events if e["action"] == "seal_resolve"][0]
        self.assertEqual(resolve_event["detail"]["resolution_note"], "已核对纸质台账，恢复写入")
        cases = self.service.list_seal_cases("viewer")
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["progress"]["step"], 3)
        with self.assertRaises(ConflictError):
            self.service.report_seal_case(
                {"reason": "r", "evidence_summary": "e"}, "night", "inspector")

    def test_freeze_scoped_to_affected_items(self):
        first = self._item("SEAL-A")
        second = self._item("SEAL-B")
        self._tamper(2)
        case = self.service.report_seal_case(
            {"reason": "r", "evidence_summary": "e"}, "night", "inspector")
        self.assertEqual(case["break_event_id"], 2)
        self.assertEqual(case["frozen_items"], [second["id"]])
        current = self.service.transition(first["id"], STATES[1], first["version"],
                                          "reviewer", TRANSITION_ROLES[STATES[1]][0])
        self.assertEqual(current["status"], STATES[1])
        with self.assertRaises(ConflictError):
            self.service.transition(second["id"], STATES[1], second["version"],
                                    "reviewer", TRANSITION_ROLES[STATES[1]][0])


if __name__ == "__main__":
    unittest.main()
