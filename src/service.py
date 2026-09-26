from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES,
                    SEAL_CONFIRM_ROLES, SEAL_ENTITY, SEAL_REPORT_ROLES,
                    SEAL_RESOLVE_ROLES, SEAL_VIEW_ROLES, TITLE, VIEW_ROLES,
                    completion_blockers, ensure_item_writable,
                    escalation_required, priority_score,
                    response_deadline_hours, role_for_transition, seal_progress,
                    validate_seal_confirm, validate_seal_resolve,
                    validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
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
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        ensure_item_writable(self.repository.is_item_frozen(item_id))
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
        ensure_item_writable(self.repository.is_item_frozen(item_id))
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
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
        item = self.enrich(self.repository.get_item(item_id))
        item["frozen"] = self.repository.is_item_frozen(item_id)
        return item

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        result = []
        for item in self.repository.list_items(status):
            enriched = self.enrich(item)
            enriched["frozen"] = self.repository.is_item_frozen(item["id"])
            result.append(enriched)
        return result

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    def report_seal_case(self, payload: Dict[str, Any], actor: str,
                         role: str) -> Dict[str, Any]:
        ensure_role(role, SEAL_REPORT_ROLES)
        actor = require_text(actor, "actor", 100)
        reason = require_text(payload.get("reason"), "reason")
        evidence_summary = require_text(payload.get("evidence_summary"), "evidence_summary")
        break_event_id = self.repository.undisposed_break()
        if break_event_id is None:
            raise ConflictError("审计链完整或断点已处置，无需封存")
        if self.repository.has_active_seal_case():
            raise ConflictError("存在未结清的封存处置单，请先结清")
        case = self.repository.create_seal_case(break_event_id, actor, reason,
                                                evidence_summary)
        self.repository.append_audit("seal_open", SEAL_ENTITY, case["id"], actor, {
            "break_event_id": break_event_id, "reason": reason,
            "frozen_items": self.repository.frozen_item_ids(case["id"]),
        })
        return self.enrich_seal(case)

    def confirm_seal_case(self, seal_id: int, payload: Dict[str, Any], actor: str,
                          role: str) -> Dict[str, Any]:
        ensure_role(role, SEAL_CONFIRM_ROLES)
        actor = require_text(actor, "actor", 100)
        scope_note = require_text(payload.get("scope_note"), "scope_note")
        case = self.repository.get_seal_case(seal_id)
        validate_seal_confirm(case, actor)
        updated = self.repository.confirm_seal_case(seal_id, actor, scope_note)
        self.repository.append_audit("seal_confirm", SEAL_ENTITY, seal_id, actor, {
            "scope_note": scope_note, "original_events": "read_only",
        })
        return self.enrich_seal(updated)

    def resolve_seal_case(self, seal_id: int, payload: Dict[str, Any], actor: str,
                          role: str) -> Dict[str, Any]:
        ensure_role(role, SEAL_RESOLVE_ROLES)
        actor = require_text(actor, "actor", 100)
        resolution_note = require_text(payload.get("resolution_note"), "resolution_note")
        case = self.repository.get_seal_case(seal_id)
        validate_seal_resolve(case)
        updated = self.repository.resolve_seal_case(seal_id, actor, resolution_note)
        self.repository.append_audit("seal_resolve", SEAL_ENTITY, seal_id, actor, {
            "resolution_note": resolution_note,
            "released_items": self.repository.frozen_item_ids(seal_id),
        })
        return self.enrich_seal(updated)

    def list_seal_cases(self, role: str) -> list:
        ensure_role(role, SEAL_VIEW_ROLES)
        return [self.enrich_seal(case) for case in self.repository.list_seal_cases()]

    def get_seal_case(self, seal_id: int, role: str) -> Dict[str, Any]:
        ensure_role(role, SEAL_VIEW_ROLES)
        return self.enrich_seal(self.repository.get_seal_case(seal_id))

    def enrich_seal(self, case: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(case)
        result["frozen_items"] = self.repository.frozen_item_ids(case["id"])
        result["progress"] = seal_progress(case["status"])
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
