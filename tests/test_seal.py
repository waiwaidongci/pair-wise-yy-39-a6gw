import json
import tempfile
import unittest
from pathlib import Path

from src.domain import ConflictError, FrozenError, PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES


class SealTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item1 = self.service.create_item(
            {"title": "seal item one", "description": "first defect", "severity": "major",
             "quantity": 5, "threshold": 10, "external_ref": "SEAL-1"}, "creator", "inspector")
        self.item2 = self.service.create_item(
            {"title": "seal item two", "description": "second defect", "severity": "minor",
             "quantity": 1, "threshold": 2, "external_ref": "SEAL-2"}, "creator", "inspector")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def tamper(self, event_id):
        with self.repo.conn:
            self.repo.conn.execute(
                "UPDATE audit_events SET detail=? WHERE id=?",
                (json.dumps({"forged": True}), event_id))

    def report(self, actor="patrol", role="inspector"):
        return self.service.report_seal(
            {"reason": "夜巡发现历史审计记录被改动", "evidence_summary": "事件哈希与内容不符"},
            actor, role)

    def test_verify_reports_break_point(self):
        self.assertTrue(self.service.verify_audit("viewer")["intact"])
        self.assertTrue(self.repo.verify_audit_chain())
        self.tamper(1)
        result = self.service.verify_audit("viewer")
        self.assertFalse(result["intact"])
        self.assertEqual(result["breaks"][0]["event_id"], 1)
        self.assertIsNone(result["active_case_id"])
        self.assertFalse(self.repo.verify_audit_chain())

    def test_report_requires_actual_break_and_role(self):
        with self.assertRaises(ConflictError):
            self.report()
        self.tamper(1)
        with self.assertRaises(PermissionDenied):
            self.report(role="viewer")

    def test_seal_lifecycle_freezes_and_resumes(self):
        self.tamper(1)
        case = self.report()
        self.assertEqual(case["status"], "open")
        self.assertEqual(case["broken_event_id"], 1)
        self.assertEqual(case["discovered_by"], "patrol")
        self.assertEqual({i["id"] for i in case["frozen_items"]},
                         {self.item1["id"], self.item2["id"]})
        with self.assertRaises(FrozenError):
            self.service.create_item(
                {"title": "x", "description": "y", "severity": "minor",
                 "quantity": 1, "threshold": 2}, "creator", "inspector")
        with self.assertRaises(FrozenError):
            self.service.add_record(self.item1["id"], {"kind": "evidence", "detail": "d"},
                                    "rec", "inspector")
        with self.assertRaises(FrozenError):
            self.service.transition(self.item1["id"], STATES[1], self.item1["version"],
                                    "rev", TRANSITION_ROLES[STATES[1]][0])
        with self.assertRaises(ConflictError):
            self.report(actor="other", role="emergency_manager")
        with self.assertRaises(PermissionDenied):
            self.service.confirm_seal(case["id"], {"scope_note": "s"}, "patrol",
                                      "emergency_manager")
        with self.assertRaises(ConflictError):
            self.service.resolve_seal(case["id"], {"resolution_note": "r"}, "mgr-b",
                                      "emergency_manager")
        confirmed = self.service.confirm_seal(
            case["id"], {"scope_note": "两个缺陷的审计事件均受影响"}, "mgr-a",
            "emergency_manager")
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(confirmed["confirmed_by"], "mgr-a")
        self.assertGreaterEqual(confirmed["locked_through_event_id"], 1)
        with self.assertRaises(FrozenError):
            self.service.transition(self.item1["id"], STATES[1], self.item1["version"],
                                    "rev", TRANSITION_ROLES[STATES[1]][0])
        with self.assertRaises(ValidationError):
            self.service.resolve_seal(case["id"], {"resolution_note": "  "}, "mgr-b",
                                      "emergency_manager")
        resolved = self.service.resolve_seal(
            case["id"], {"resolution_note": "已核实影响范围，原事件保留只读，恢复写入"},
            "mgr-b", "emergency_manager")
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(resolved["resolved_by"], "mgr-b")
        self.assertIsNotNone(resolved["resume_event_id"])
        steps = {p["step"]: p["done"] for p in resolved["progress"]}
        self.assertEqual(steps, {"report": True, "confirm": True, "resolve": True})
        events = [e for e in self.service.audit("viewer") if e["action"] == "seal_resolve"]
        self.assertEqual(len(events), 1)
        self.assertIn("恢复写入", events[0]["detail"]["resolution_note"])
        created = self.service.create_item(
            {"title": "after", "description": "writes resumed", "severity": "observation",
             "quantity": 0, "threshold": 1}, "creator", "inspector")
        self.assertEqual(created["status"], STATES[0])
        verify = self.service.verify_audit("viewer")
        self.assertFalse(verify["intact"])
        self.assertIsNone(verify["active_case_id"])
        self.assertTrue(verify["post_recovery"]["intact"])
        with self.assertRaises(ConflictError):
            self.report(actor="mgr-a", role="emergency_manager")

    def test_frozen_items_scope_and_confirm_role(self):
        self.service.add_record(self.item2["id"], {"kind": "evidence", "detail": "d2"},
                                "rec", "inspector")
        event_id = self.service.audit("viewer", self.item2["id"])[0]["id"]
        self.tamper(event_id)
        case = self.report()
        self.assertEqual(case["broken_event_id"], event_id)
        self.assertEqual([i["id"] for i in case["frozen_items"]], [self.item2["id"]])
        with self.assertRaises(PermissionDenied):
            self.service.confirm_seal(case["id"], {"scope_note": "s"}, "mgr-a", "inspector")
        confirmed = self.service.confirm_seal(
            case["id"], {"scope_note": "仅缺陷二受影响"}, "mgr-a", "emergency_manager")
        self.assertEqual(confirmed["scope_note"], "仅缺陷二受影响")


if __name__ == "__main__":
    unittest.main()
