"""联合实训责任链的持久化与编排服务。

领域规则集中在 ``app.compliance.responsibility_chain``，本模块负责
SQLAlchemy 行与领域记录之间的转换、事务提交以及乐观并发控制。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Iterable

from sqlalchemy import select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from .compliance import responsibility_chain as rc
from .models import (
    Correction as CorrectionModel,
)
from .models import (
    ResponsibilityDelegation as DelegationModel,
)
from .models import (
    ResponsibilityGrant as GrantModel,
)
from .models import (
    SharedFieldConfig as SharedFieldConfigModel,
)


class GrantNotFoundError(Exception):
    pass


class CorrectionNotFoundError(Exception):
    pass


class RecordConflictError(Exception):
    """标识重复等写入冲突。"""


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(UTC)


def _fmt_dt(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _audit_to_dict(entry: rc.AuditEntry) -> dict[str, Any]:
    return {
        "sequence": entry.sequence,
        "action": entry.action,
        "actor_id": entry.actor_id,
        "occurred_at": _fmt_dt(entry.occurred_at),
        "before": entry.before,
        "after": entry.after,
        "reason": entry.reason,
        "fingerprint": entry.fingerprint,
    }


def _audit_from_dict(data: dict[str, Any]) -> rc.AuditEntry:
    return rc.AuditEntry(
        sequence=int(data["sequence"]),
        action=data["action"],
        actor_id=data["actor_id"],
        occurred_at=_parse_dt(data["occurred_at"]),
        before=data["before"],
        after=data["after"],
        reason=data["reason"],
        fingerprint=data["fingerprint"],
    )


def _audit_list(record: Any) -> list[dict[str, Any]]:
    return [_audit_to_dict(entry) for entry in record.audit]


def _audit_tuple(items: Iterable[dict[str, Any]]) -> tuple[rc.AuditEntry, ...]:
    return tuple(_audit_from_dict(item) for item in items)


# ---------------------------------------------------------------------------
# 行 <-> 领域记录
# ---------------------------------------------------------------------------


def _grant_to_row(grant: rc.Grant) -> GrantModel:
    return GrantModel(
        grant_id=grant.grant_id,
        activity_id=grant.activity_id,
        role=grant.role.value,
        party_id=grant.party_id,
        fields=sorted(grant.fields),
        effective_from=_fmt_dt(grant.effective_from),
        effective_to=_fmt_dt(grant.effective_to) if grant.effective_to else None,
        status=grant.status.value,
        version=grant.version,
        audit=_audit_list(grant),
    )


def _row_to_grant(row: GrantModel) -> rc.Grant:
    return rc.Grant(
        grant_id=row.grant_id,
        activity_id=row.activity_id,
        role=rc.Role(row.role),
        party_id=row.party_id,
        fields=frozenset(row.fields),
        effective_from=_parse_dt(row.effective_from),
        effective_to=_parse_dt(row.effective_to) if row.effective_to else None,
        status=rc.GrantStatus(row.status),
        version=row.version,
        audit=_audit_tuple(row.audit),
    )


def _delegation_to_row(delegation: rc.Delegation) -> DelegationModel:
    return DelegationModel(
        delegation_id=delegation.delegation_id,
        activity_id=delegation.activity_id,
        from_party_id=delegation.from_party_id,
        to_party_id=delegation.to_party_id,
        fields=sorted(delegation.fields),
        effective_from=_fmt_dt(delegation.effective_from),
        effective_to=(
            _fmt_dt(delegation.effective_to) if delegation.effective_to else None
        ),
        status=delegation.status.value,
        version=delegation.version,
        audit=_audit_list(delegation),
    )


def _row_to_delegation(row: DelegationModel) -> rc.Delegation:
    return rc.Delegation(
        delegation_id=row.delegation_id,
        activity_id=row.activity_id,
        from_party_id=row.from_party_id,
        to_party_id=row.to_party_id,
        fields=frozenset(row.fields),
        effective_from=_parse_dt(row.effective_from),
        effective_to=_parse_dt(row.effective_to) if row.effective_to else None,
        status=rc.DelegationStatus(row.status),
        version=row.version,
        audit=_audit_tuple(row.audit),
    )


def _countersigner_to_dict(item: rc.CountersignRequirement) -> dict[str, str]:
    return {"party_id": item.party_id, "role": item.role.value}


def _countersigner_from_dict(data: dict[str, str]) -> rc.CountersignRequirement:
    return rc.CountersignRequirement(
        party_id=data["party_id"], role=rc.Role(data["role"])
    )


def _signature_to_dict(item: rc.Countersignature) -> dict[str, Any]:
    return {
        "party_id": item.party_id,
        "role": item.role.value,
        "approve": item.approve,
        "signed_at": _fmt_dt(item.signed_at),
        "reason": item.reason,
    }


def _signature_from_dict(data: dict[str, Any]) -> rc.Countersignature:
    return rc.Countersignature(
        party_id=data["party_id"],
        role=rc.Role(data["role"]),
        approve=bool(data["approve"]),
        signed_at=_parse_dt(data["signed_at"]),
        reason=data["reason"],
    )


def _correction_to_row(correction: rc.Correction) -> CorrectionModel:
    return CorrectionModel(
        correction_id=correction.correction_id,
        activity_id=correction.activity_id,
        event_id=correction.event_id,
        field=correction.field,
        old_value=correction.old_value,
        new_value=correction.new_value,
        business_time=_fmt_dt(correction.business_time),
        requested_by=correction.requested_by,
        requested_at=_fmt_dt(correction.requested_at),
        emergency=correction.emergency,
        status=correction.status.value,
        required_countersigners=[
            _countersigner_to_dict(item)
            for item in correction.required_countersigners
        ],
        countersignatures=[
            _signature_to_dict(item) for item in correction.countersignatures
        ],
        review_deadline=(
            _fmt_dt(correction.review_deadline) if correction.review_deadline else None
        ),
        reviewed_by=correction.reviewed_by,
        reviewed_at=_fmt_dt(correction.reviewed_at) if correction.reviewed_at else None,
        review_outcome=correction.review_outcome,
        version=correction.version,
        audit=_audit_list(correction),
    )


def _row_to_correction(row: CorrectionModel) -> rc.Correction:
    return rc.Correction(
        correction_id=row.correction_id,
        activity_id=row.activity_id,
        event_id=row.event_id,
        field=row.field,
        old_value=row.old_value,
        new_value=row.new_value,
        business_time=_parse_dt(row.business_time),
        requested_by=row.requested_by,
        requested_at=_parse_dt(row.requested_at),
        emergency=row.emergency,
        status=rc.CorrectionStatus(row.status),
        required_countersigners=tuple(
            _countersigner_from_dict(item) for item in row.required_countersigners
        ),
        countersignatures=tuple(
            _signature_from_dict(item) for item in row.countersignatures
        ),
        review_deadline=(
            _parse_dt(row.review_deadline) if row.review_deadline else None
        ),
        reviewed_by=row.reviewed_by,
        reviewed_at=_parse_dt(row.reviewed_at) if row.reviewed_at else None,
        review_outcome=row.review_outcome,
        version=row.version,
        audit=_audit_tuple(row.audit),
    )


def _correction_row_values(correction: rc.Correction) -> dict[str, Any]:
    row = _correction_to_row(correction)
    return {
        column: getattr(row, column)
        for column in (
            "event_id",
            "field",
            "old_value",
            "new_value",
            "business_time",
            "requested_by",
            "requested_at",
            "emergency",
            "status",
            "required_countersigners",
            "countersignatures",
            "review_deadline",
            "reviewed_by",
            "reviewed_at",
            "review_outcome",
            "version",
            "audit",
        )
    }


def _config_to_record(row: SharedFieldConfigModel | None, activity_id: str) -> rc.SharedFieldConfig:
    if row is None:
        return rc.empty_shared_config(activity_id)
    return rc.SharedFieldConfig(
        activity_id=row.activity_id,
        shared_fields={
            field_name: tuple(rc.Role(item) for item in roles)
            for field_name, roles in (row.shared_fields or {}).items()
        },
        version=row.version,
        audit=_audit_tuple(row.audit),
    )


# ---------------------------------------------------------------------------
# 输出字典
# ---------------------------------------------------------------------------


def _grant_out(grant: rc.Grant) -> dict[str, Any]:
    return {
        "grant_id": grant.grant_id,
        "activity_id": grant.activity_id,
        "role": grant.role.value,
        "party_id": grant.party_id,
        "fields": sorted(grant.fields),
        "effective_from": _fmt_dt(grant.effective_from),
        "effective_to": _fmt_dt(grant.effective_to) if grant.effective_to else None,
        "status": grant.status.value,
        "version": grant.version,
    }


def _delegation_out(delegation: rc.Delegation) -> dict[str, Any]:
    return {
        "delegation_id": delegation.delegation_id,
        "activity_id": delegation.activity_id,
        "from_party_id": delegation.from_party_id,
        "to_party_id": delegation.to_party_id,
        "fields": sorted(delegation.fields),
        "effective_from": _fmt_dt(delegation.effective_from),
        "effective_to": (
            _fmt_dt(delegation.effective_to) if delegation.effective_to else None
        ),
        "status": delegation.status.value,
        "version": delegation.version,
    }


def _correction_out(correction: rc.Correction, as_of: datetime) -> dict[str, Any]:
    return {
        "correction_id": correction.correction_id,
        "activity_id": correction.activity_id,
        "event_id": correction.event_id,
        "field": correction.field,
        "old_value": correction.old_value,
        "new_value": correction.new_value,
        "business_time": _fmt_dt(correction.business_time),
        "requested_by": correction.requested_by,
        "requested_at": _fmt_dt(correction.requested_at),
        "emergency": correction.emergency,
        "status": correction.status.value,
        "required_countersigners": [
            _countersigner_to_dict(item)
            for item in correction.required_countersigners
        ],
        "countersignatures": [
            _signature_to_dict(item) for item in correction.countersignatures
        ],
        "review_deadline": (
            _fmt_dt(correction.review_deadline) if correction.review_deadline else None
        ),
        "reviewed_by": correction.reviewed_by,
        "reviewed_at": (
            _fmt_dt(correction.reviewed_at) if correction.reviewed_at else None
        ),
        "review_outcome": correction.review_outcome,
        "review_overdue": correction.review_overdue(as_of),
        "version": correction.version,
    }


def _shared_fields_out(config: rc.SharedFieldConfig) -> dict[str, Any]:
    return {
        "activity_id": config.activity_id,
        "shared_fields": {
            field_name: [role.value for role in roles]
            for field_name, roles in sorted(config.shared_fields.items())
        },
        "version": config.version,
    }


# ---------------------------------------------------------------------------
# 装载辅助
# ---------------------------------------------------------------------------


def _load_grants(db: Session, activity_id: str) -> list[rc.Grant]:
    stmt = (
        select(GrantModel)
        .where(GrantModel.activity_id == activity_id)
        .order_by(GrantModel.grant_id)
    )
    return [_row_to_grant(row) for row in db.execute(stmt).scalars().all()]


def _load_delegations(db: Session, activity_id: str) -> list[rc.Delegation]:
    stmt = (
        select(DelegationModel)
        .where(DelegationModel.activity_id == activity_id)
        .order_by(DelegationModel.delegation_id)
    )
    return [_row_to_delegation(row) for row in db.execute(stmt).scalars().all()]


def _load_config(db: Session, activity_id: str) -> rc.SharedFieldConfig:
    return _config_to_record(db.get(SharedFieldConfigModel, activity_id), activity_id)


# ---------------------------------------------------------------------------
# 责任配置
# ---------------------------------------------------------------------------


def create_grant(
    db: Session,
    *,
    activity_id: str,
    grant_id: str,
    role: str,
    party_id: str,
    fields: list[str],
    effective_from: datetime,
    effective_to: datetime | None,
    actor_id: str,
    reason: str,
) -> dict[str, Any]:
    if db.get(GrantModel, grant_id) is not None:
        raise RecordConflictError(f"授权 '{grant_id}' 已存在")
    grant = rc.create_grant(
        grant_id=grant_id,
        activity_id=activity_id,
        role=role,
        party_id=party_id,
        fields=fields,
        effective_from=effective_from,
        effective_to=effective_to,
        actor_id=actor_id,
        reason=reason,
        now=_utcnow(),
        existing=_load_grants(db, activity_id),
    )
    db.add(_grant_to_row(grant))
    db.commit()
    return _grant_out(grant)


def list_grants(
    db: Session, activity_id: str, at: datetime | None = None
) -> list[dict[str, Any]]:
    grants = _load_grants(db, activity_id)
    if at is not None:
        grants = [grant for grant in grants if grant.covers(at)]
    return [_grant_out(grant) for grant in grants]


def get_chain(
    db: Session, activity_id: str, at: datetime | None = None
) -> dict[str, Any]:
    moment = at or _utcnow()
    grants = _load_grants(db, activity_id)
    delegations = _load_delegations(db, activity_id)
    config = _load_config(db, activity_id)
    roles = [
        _grant_out(grant) for grant in grants if grant.covers(moment)
    ]
    roles.sort(key=lambda item: (item["role"], item["party_id"]))
    active_delegations = [
        delegation for delegation in delegations if delegation.covers(moment)
    ]
    return {
        "activity_id": activity_id,
        "at": _fmt_dt(moment),
        "roles": roles,
        "delegations": [_delegation_out(item) for item in active_delegations],
        "shared_fields": _shared_fields_out(config)["shared_fields"],
    }


def configure_shared_fields(
    db: Session,
    *,
    activity_id: str,
    changes: dict[str, list[str] | None],
    actor_id: str,
    reason: str,
) -> dict[str, Any]:
    row = db.get(SharedFieldConfigModel, activity_id)
    config = _config_to_record(row, activity_id)
    updated = rc.configure_shared_fields(
        config,
        changes=changes,
        actor_id=actor_id,
        reason=reason,
        now=_utcnow(),
    )
    payload = {
        "shared_fields": {
            field_name: [role.value for role in roles]
            for field_name, roles in updated.shared_fields.items()
        },
        "version": updated.version,
        "audit": _audit_list(updated),
    }
    if row is None:
        db.add(SharedFieldConfigModel(activity_id=activity_id, **payload))
    else:
        for key, value in payload.items():
            setattr(row, key, value)
    db.commit()
    return _shared_fields_out(updated)


def get_shared_fields(db: Session, activity_id: str) -> dict[str, Any]:
    return _shared_fields_out(_load_config(db, activity_id))


# ---------------------------------------------------------------------------
# 责任转移（乐观并发）
# ---------------------------------------------------------------------------


def transfer_responsibility(
    db: Session,
    *,
    activity_id: str,
    grant_id: str,
    to_party_id: str,
    to_role: str | None,
    new_grant_id: str,
    effective_at: datetime,
    expected_version: int,
    actor_id: str,
    reason: str,
) -> dict[str, Any]:
    row = db.get(GrantModel, grant_id)
    if row is None or row.activity_id != activity_id:
        raise GrantNotFoundError(f"活动 '{activity_id}' 不存在授权 '{grant_id}'")
    if db.get(GrantModel, new_grant_id) is not None:
        raise RecordConflictError(f"授权 '{new_grant_id}' 已存在")
    grant = _row_to_grant(row)
    closed, opened = rc.plan_transfer(
        grant,
        to_party_id=to_party_id,
        to_role=to_role,
        new_grant_id=new_grant_id,
        effective_at=effective_at,
        actor_id=actor_id,
        reason=reason,
        now=_utcnow(),
        existing=_load_grants(db, activity_id),
    )
    if grant.version != expected_version:
        raise rc.ConcurrencyError(
            f"授权版本已变更：期望 {expected_version}，当前 {grant.version}"
        )
    stmt = (
        update(GrantModel)
        .where(GrantModel.grant_id == grant.grant_id)
        .where(GrantModel.version == expected_version)
        .values(
            effective_to=_fmt_dt(closed.effective_to)
            if closed.effective_to
            else None,
            status=closed.status.value,
            version=closed.version,
            audit=_audit_list(closed),
        )
    )
    try:
        result = db.execute(stmt)
        if result.rowcount == 0:
            db.rollback()
            raise rc.ConcurrencyError("授权已被并发修改，请刷新后重试")
        db.add(_grant_to_row(opened))
        db.commit()
    except OperationalError as exc:
        db.rollback()
        raise rc.ConcurrencyError("授权转移发生并发冲突，请刷新后重试") from exc
    return {"closed": _grant_out(closed), "opened": _grant_out(opened)}


# ---------------------------------------------------------------------------
# 委托授权
# ---------------------------------------------------------------------------


def create_delegation(
    db: Session,
    *,
    activity_id: str,
    delegation_id: str,
    from_party_id: str,
    to_party_id: str,
    fields: list[str],
    effective_from: datetime,
    effective_to: datetime | None,
    actor_id: str,
    reason: str,
) -> dict[str, Any]:
    if db.get(DelegationModel, delegation_id) is not None:
        raise RecordConflictError(f"委托 '{delegation_id}' 已存在")
    delegation = rc.delegate(
        delegation_id=delegation_id,
        activity_id=activity_id,
        from_party_id=from_party_id,
        to_party_id=to_party_id,
        fields=fields,
        effective_from=effective_from,
        effective_to=effective_to,
        actor_id=actor_id,
        reason=reason,
        now=_utcnow(),
        grants=_load_grants(db, activity_id),
        existing=_load_delegations(db, activity_id),
    )
    db.add(_delegation_to_row(delegation))
    db.commit()
    return _delegation_out(delegation)


def list_delegations(db: Session, activity_id: str) -> list[dict[str, Any]]:
    return [_delegation_out(item) for item in _load_delegations(db, activity_id)]


# ---------------------------------------------------------------------------
# 授权判定
# ---------------------------------------------------------------------------


def authorize(
    db: Session,
    *,
    activity_id: str,
    party_id: str,
    field: str,
    business_time: datetime,
) -> dict[str, Any]:
    result = rc.authorize(
        _load_grants(db, activity_id),
        _load_delegations(db, activity_id),
        _load_config(db, activity_id),
        activity_id=activity_id,
        party_id=party_id,
        field=field,
        business_time=business_time,
    )
    return {
        "decision": result.decision.value,
        "reason": result.reason,
        "via_delegation_id": (
            result.authority.via_delegation_id if result.authority else None
        ),
        "required_countersigners": [
            _countersigner_to_dict(item) for item in result.required_countersigners
        ],
    }


# ---------------------------------------------------------------------------
# 事件更正、会签与补审
# ---------------------------------------------------------------------------


def open_correction(
    db: Session,
    *,
    activity_id: str,
    correction_id: str,
    event_id: str,
    field: str,
    old_value: str,
    new_value: str,
    business_time: datetime,
    party_id: str,
    reason: str,
    emergency: bool,
    review_window_hours: int,
    requested_at: datetime | None,
) -> dict[str, Any]:
    if db.get(CorrectionModel, correction_id) is not None:
        raise RecordConflictError(f"更正 '{correction_id}' 已存在")
    correction = rc.open_correction(
        correction_id=correction_id,
        activity_id=activity_id,
        event_id=event_id,
        field=field,
        old_value=old_value,
        new_value=new_value,
        business_time=business_time,
        party_id=party_id,
        reason=reason,
        now=requested_at or _utcnow(),
        grants=_load_grants(db, activity_id),
        delegations=_load_delegations(db, activity_id),
        shared_config=_load_config(db, activity_id),
        emergency=emergency,
        review_window=timedelta(hours=review_window_hours),
    )
    db.add(_correction_to_row(correction))
    db.commit()
    # 逾期标志以开单时刻为参照，历史补录时不受服务器当前时间影响
    return _correction_out(correction, correction.requested_at)


def _require_correction_row(
    db: Session, activity_id: str, correction_id: str
) -> CorrectionModel:
    row = db.get(CorrectionModel, correction_id)
    if row is None or row.activity_id != activity_id:
        raise CorrectionNotFoundError(
            f"活动 '{activity_id}' 不存在更正 '{correction_id}'"
        )
    return row


def _save_correction(db: Session, correction: rc.Correction) -> None:
    stmt = (
        update(CorrectionModel)
        .where(CorrectionModel.correction_id == correction.correction_id)
        .where(CorrectionModel.version == correction.version - 1)
        .values(**_correction_row_values(correction))
    )
    try:
        result = db.execute(stmt)
        if result.rowcount == 0:
            db.rollback()
            raise rc.ConcurrencyError("更正单已被并发修改，请刷新后重试")
        db.commit()
    except OperationalError as exc:
        db.rollback()
        raise rc.ConcurrencyError("更正单发生并发冲突，请刷新后重试") from exc


def get_correction(
    db: Session,
    activity_id: str,
    correction_id: str,
    as_of: datetime | None = None,
) -> dict[str, Any]:
    row = _require_correction_row(db, activity_id, correction_id)
    return _correction_out(_row_to_correction(row), as_of or _utcnow())


def list_corrections(
    db: Session,
    activity_id: str,
    as_of: datetime | None = None,
    status: str | None = None,
    overdue_only: bool = False,
) -> list[dict[str, Any]]:
    moment = as_of or _utcnow()
    stmt = (
        select(CorrectionModel)
        .where(CorrectionModel.activity_id == activity_id)
        .order_by(CorrectionModel.correction_id)
    )
    if status is not None:
        stmt = stmt.where(CorrectionModel.status == status)
    result = []
    for row in db.execute(stmt).scalars().all():
        correction = _row_to_correction(row)
        if overdue_only and not correction.review_overdue(moment):
            continue
        result.append(_correction_out(correction, moment))
    return result


def countersign_correction(
    db: Session,
    *,
    activity_id: str,
    correction_id: str,
    party_id: str,
    approve: bool,
    reason: str,
) -> dict[str, Any]:
    row = _require_correction_row(db, activity_id, correction_id)
    correction = rc.countersign(
        _row_to_correction(row),
        party_id=party_id,
        approve=approve,
        reason=reason,
        now=_utcnow(),
    )
    _save_correction(db, correction)
    return _correction_out(correction, _utcnow())


def review_correction(
    db: Session,
    *,
    activity_id: str,
    correction_id: str,
    party_id: str,
    outcome: str,
    reason: str,
    reviewed_at: datetime | None,
) -> dict[str, Any]:
    row = _require_correction_row(db, activity_id, correction_id)
    correction = rc.review(
        _row_to_correction(row),
        party_id=party_id,
        outcome=outcome,
        reason=reason,
        now=reviewed_at or _utcnow(),
        grants=_load_grants(db, activity_id),
    )
    _save_correction(db, correction)
    return _correction_out(correction, _utcnow())


# ---------------------------------------------------------------------------
# 审计查询
# ---------------------------------------------------------------------------


def audit_trail(
    db: Session,
    activity_id: str,
    *,
    action: str | None = None,
    actor_id: str | None = None,
    aggregate_type: str | None = None,
) -> dict[str, Any]:
    records: list[tuple[str, Any]] = [("grant", g) for g in _load_grants(db, activity_id)]
    records += [("delegation", d) for d in _load_delegations(db, activity_id)]
    config = _load_config(db, activity_id)
    records.append(("shared_fields", config))
    stmt = select(CorrectionModel).where(CorrectionModel.activity_id == activity_id)
    records += [
        ("correction", _row_to_correction(row))
        for row in db.execute(stmt).scalars().all()
    ]

    entries: list[dict[str, Any]] = []
    for kind, record in records:
        if aggregate_type is not None and kind != aggregate_type:
            continue
        for entry in record.audit:
            if action is not None and entry.action != action:
                continue
            if actor_id is not None and entry.actor_id != actor_id:
                continue
            item = _audit_to_dict(entry)
            item["aggregate_type"] = kind
            item["aggregate_id"] = record.identifier
            entries.append(item)
    entries.sort(
        key=lambda item: (
            item["occurred_at"],
            item["aggregate_type"],
            item["aggregate_id"],
            item["sequence"],
        )
    )
    return {
        "activity_id": activity_id,
        "total": len(entries),
        "entries": entries,
    }
