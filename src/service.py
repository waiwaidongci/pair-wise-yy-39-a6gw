from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, FrozenError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES,
                    SEAL_CONFIRM_ROLES, SEAL_ENTITY, SEAL_REPORT_ROLES,
                    SEAL_RESOLVE_ROLES, TITLE, VIEW_ROLES, completion_blockers,
                    ensure_independent_confirmer, escalation_required,
                    priority_score, response_deadline_hours, role_for_transition,
                    seal_writes_frozen, validate_seal_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def _ensure_writes_open(self) -> None:
        case = self.repository.active_seal_case()
        if seal_writes_frozen(case):
            raise FrozenError(f"审计封存处置中（处置单#{case['id']}），缺陷写入已冻结")

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        self._ensure_writes_open()
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        self._ensure_writes_open()
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        self._ensure_writes_open()
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    def verify_audit(self, role: str) -> Dict[str, Any]:
        self._view(role)
        breaks = self.repository.find_chain_breaks()
        active = self.repository.active_seal_case()
        resolved = self.repository.latest_resolved_seal_case()
        post_recovery = None
        if resolved is not None and resolved["resume_event_id"]:
            post_recovery = {
                "baseline_event_id": resolved["resume_event_id"],
                "intact": not self.repository.find_chain_breaks(resolved["resume_event_id"]),
            }
        return {
            "intact": not breaks,
            "breaks": breaks,
            "active_case_id": active["id"] if active else None,
            "post_recovery": post_recovery,
        }

    def report_seal(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, SEAL_REPORT_ROLES)
        actor = require_text(actor, "actor", 100)
        reason = require_text(payload.get("reason"), "reason", 500)
        evidence = require_text(payload.get("evidence_summary"), "evidence_summary")
        if self.repository.active_seal_case() is not None:
            raise ConflictError("已有未结清的封存处置单")
        breaks = self.repository.find_chain_breaks()
        if not breaks:
            raise ConflictError("审计链完整，无需封存")
        adjudicated = {case["broken_event_id"] for case in self.repository.list_seal_cases()
                       if case["status"] == "resolved"}
        pending = [b for b in breaks if b["event_id"] not in adjudicated]
        if not pending:
            raise ConflictError("断点均已完成处置，无需重复封存")
        brk = pending[0]
        case = self.repository.create_seal_case(brk["event_id"], brk, actor, reason, evidence)
        self.repository.append_audit("seal_report", SEAL_ENTITY, case["id"], actor, {
            "broken_event_id": brk["event_id"], "reason": reason,
            "evidence_summary": evidence,
            "frozen_item_ids": self.repository.affected_item_ids(brk["event_id"]),
        })
        return self._enrich_seal(self.repository.get_seal_case(case["id"]))

    def confirm_seal(self, case_id: int, payload: Dict[str, Any], actor: str,
                     role: str) -> Dict[str, Any]:
        ensure_role(role, SEAL_CONFIRM_ROLES)
        actor = require_text(actor, "actor", 100)
        scope_note = require_text(payload.get("scope_note"), "scope_note")
        case = self.repository.get_seal_case(case_id)
        validate_seal_transition(case["status"], "confirmed")
        ensure_independent_confirmer(case["discovered_by"], actor)
        locked = self.repository.last_audit_event_id()
        updated = self.repository.confirm_seal_case(case_id, scope_note, actor, locked)
        self.repository.append_audit("seal_confirm", SEAL_ENTITY, case_id, actor, {
            "scope_note": scope_note, "locked_through_event_id": locked,
            "frozen_item_ids": self.repository.affected_item_ids(updated["broken_event_id"]),
        })
        return self._enrich_seal(updated)

    def resolve_seal(self, case_id: int, payload: Dict[str, Any], actor: str,
                     role: str) -> Dict[str, Any]:
        ensure_role(role, SEAL_RESOLVE_ROLES)
        actor = require_text(actor, "actor", 100)
        note = require_text(payload.get("resolution_note"), "resolution_note")
        case = self.repository.get_seal_case(case_id)
        validate_seal_transition(case["status"], "resolved")
        updated = self.repository.resolve_seal_case(case_id, note, actor)
        event = self.repository.append_audit("seal_resolve", SEAL_ENTITY, case_id, actor, {
            "resolution_note": note, "writes_resumed": True,
        })
        updated = self.repository.set_seal_resume_event(case_id, event["id"])
        return self._enrich_seal(updated)

    def list_seals(self, role: str) -> list:
        self._view(role)
        return [self._enrich_seal(case) for case in self.repository.list_seal_cases()]

    def get_seal(self, case_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self._enrich_seal(self.repository.get_seal_case(case_id))

    def _enrich_seal(self, case: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(case)
        through = case["resume_event_id"] or case["locked_through_event_id"]
        result["frozen_items"] = [
            {"id": item["id"], "title": item["title"], "status": item["status"],
             "severity": item["severity"]}
            for item in (self.repository.get_item(item_id) for item_id in
                         self.repository.affected_item_ids(case["broken_event_id"], through))
        ]
        result["progress"] = [
            {"step": "report", "label": "断链上报", "done": True,
             "actor": case["discovered_by"], "at": case["created_at"]},
            {"step": "confirm", "label": "影响范围确认",
             "done": case["status"] in ("confirmed", "resolved"),
             "actor": case["confirmed_by"], "at": case["confirmed_at"]},
            {"step": "resolve", "label": "处置结清恢复写入",
             "done": case["status"] == "resolved",
             "actor": case["resolved_by"], "at": case["resolved_at"]},
        ]
        return result

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
