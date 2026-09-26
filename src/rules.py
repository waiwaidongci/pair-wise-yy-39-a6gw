from __future__ import annotations
from .domain import ConflictError, PermissionDenied, ValidationError
TITLE='大坝巡检、缺陷与应急管理'; ENTITY='大坝缺陷'; ID_PREFIX='DS'
SEVERITIES=['observation', 'minor', 'major', 'emergency']; STATES=['planned', 'inspected', 'defect_confirmed', 'repair', 'verified', 'closed']; TRANSITIONS={'planned': ['inspected'], 'inspected': ['defect_confirmed'], 'defect_confirmed': ['repair'], 'repair': ['verified'], 'verified': ['closed'], 'closed': []}; TRANSITION_ROLES={'inspected': ['inspector'], 'defect_confirmed': ['dam_engineer'], 'repair': ['dam_engineer'], 'verified': ['inspector'], 'closed': ['emergency_manager']}
CREATE_ROLES=set(['inspector']); RECORD_ROLES=set(['inspector', 'dam_engineer']); AUDIT_ROLES=set(['emergency_manager', 'viewer']); VIEW_ROLES=set(['inspector', 'dam_engineer', 'emergency_manager', 'viewer'])
SEVERITY_WEIGHT={'observation': 1.0, 'minor': 3.0, 'major': 6.0, 'emergency': 9.0}; DEADLINE_HOURS={'observation': 72, 'minor': 24, 'major': 8, 'emergency': 4}; TERMINAL_STATES=set(['closed'])
def priority_score(severity,quantity=0.0,threshold=1.0,open_records=0):
    if severity not in SEVERITY_WEIGHT: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(0,min(10,int(round(SEVERITY_WEIGHT[severity]+min(4.0,ratio*4.0)+min(3.0,float(open_records))))))
def response_deadline_hours(severity,quantity=0.0,threshold=1.0):
    if severity not in DEADLINE_HOURS: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(1,int(DEADLINE_HOURS[severity]/max(1.0,ratio)))
def escalation_required(severity,quantity=0.0,threshold=1.0):
    return severity==SEVERITIES[-1] or (threshold>0 and quantity>=threshold)
def can_transition(current,target): return target in TRANSITIONS.get(current,[])
def validate_transition(current,target):
    if current not in STATES or target not in STATES: raise ValidationError("未知状态")
    if not can_transition(current,target): raise ConflictError(f"不能从{current}转换到{target}")
def completion_blockers(target,open_records): return ["仍有未关闭事项"] if target in TERMINAL_STATES and open_records>0 else []
def role_for_transition(target): return set(TRANSITION_ROLES.get(target,[]))
SEAL_ENTITY='seal_case'; SEAL_STATUSES=['open','confirmed','resolved']
SEAL_REPORT_ROLES=set(['inspector','dam_engineer','emergency_manager']); SEAL_CONFIRM_ROLES=set(['emergency_manager']); SEAL_RESOLVE_ROLES=set(['emergency_manager']); SEAL_VIEW_ROLES=VIEW_ROLES
SEAL_PROGRESS={'open': (1,'待确认影响范围'), 'confirmed': (2,'待结清恢复'), 'resolved': (3,'已恢复写入')}
def ensure_item_writable(frozen):
    if frozen: raise ConflictError("缺陷已被审计封存冻结，待处置单结清后恢复写入")
def validate_seal_confirm(case,actor):
    if case["status"]!=SEAL_STATUSES[0]: raise ConflictError("处置单当前状态不能确认影响范围")
    if actor==case["discovered_by"]: raise PermissionDenied("需由另一名应急经理确认影响范围")
def validate_seal_resolve(case):
    if case["status"]==SEAL_STATUSES[2]: raise ConflictError("处置单已结清")
    if case["status"]!=SEAL_STATUSES[1]: raise ConflictError("需先确认影响范围才能结清")
def seal_progress(status):
    step,label=SEAL_PROGRESS[status]; return {"step":step,"total":len(SEAL_STATUSES),"label":label}
