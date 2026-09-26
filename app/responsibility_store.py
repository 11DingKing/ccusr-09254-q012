"""多方责任链的持久化操作。

并发控制原则：
* 责任转移通过条件 UPDATE（``valid_until IS NULL``）+ rowcount 检查实现乐观锁，
  并发转移时只有一个请求能关闭当前在责段，其余收到 :class:`ConflictError`；
* 更正单带 ``version`` 字段，状态推进必须匹配期望版本；
* 审计序列号在事务内取 max+1，并由唯一约束兜底，冲突时重试。
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .compliance import responsibility as domain
from .models import (
    Correction,
    CorrectionSignature,
    Delegation,
    FieldScope,
    ResponsibilityAssignment,
    ResponsibilityAudit,
)


class NotFoundError(LookupError):
    pass


class ConflictError(RuntimeError):
    pass


def _utc(value: datetime) -> datetime:
    """SQLite 不保留时区，读回的 naive 时间按 UTC 补回。"""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# ---- 模型行 -> 领域对象 ----------------------------------------------------


def to_grant(row: ResponsibilityAssignment) -> domain.RoleGrant:
    return domain.RoleGrant(
        role=domain.Role(row.role),
        actor_id=row.actor_id,
        valid_from=_utc(row.valid_from),
        valid_until=_utc(row.valid_until) if row.valid_until is not None else None,
    )


def _parse_roles(raw: str) -> tuple[domain.Role, ...]:
    return tuple(domain.Role(value) for value in raw.split(",") if value)


def _encode_roles(roles: Sequence[domain.Role]) -> str:
    return ",".join(role.value for role in roles)


def to_scope(row: FieldScope) -> domain.FieldScope:
    return domain.FieldScope(
        field_name=row.field_name,
        roles=_parse_roles(row.roles),
        valid_from=_utc(row.valid_from),
        valid_until=_utc(row.valid_until) if row.valid_until is not None else None,
    )


def to_edge(row: Delegation) -> domain.DelegationEdge:
    return domain.DelegationEdge(
        delegator_actor_id=row.delegator_actor_id,
        delegatee_actor_id=row.delegatee_actor_id,
        valid_from=_utc(row.valid_from),
        valid_until=_utc(row.valid_until) if row.valid_until is not None else None,
    )


# ---- 责任角色段 ------------------------------------------------------------


def list_assignments(
    db: Session, activity_id: str, role: str | None = None
) -> list[ResponsibilityAssignment]:
    stmt = select(ResponsibilityAssignment).where(
        ResponsibilityAssignment.activity_id == activity_id
    )
    if role is not None:
        stmt = stmt.where(ResponsibilityAssignment.role == role)
    stmt = stmt.order_by(
        ResponsibilityAssignment.role, ResponsibilityAssignment.valid_from
    )
    return list(db.execute(stmt).scalars().all())


def get_open_assignment(
    db: Session, activity_id: str, role: str
) -> ResponsibilityAssignment | None:
    stmt = select(ResponsibilityAssignment).where(
        ResponsibilityAssignment.activity_id == activity_id,
        ResponsibilityAssignment.role == role,
        ResponsibilityAssignment.valid_until.is_(None),
    )
    return db.execute(stmt).scalar_one_or_none()


def insert_assignment(
    db: Session,
    *,
    activity_id: str,
    role: str,
    actor_id: str,
    valid_from: datetime,
    supersedes_id: int | None,
    note: str,
) -> ResponsibilityAssignment:
    row = ResponsibilityAssignment(
        activity_id=activity_id,
        role=role,
        actor_id=actor_id,
        valid_from=valid_from,
        valid_until=None,
        supersedes_id=supersedes_id,
        note=note,
    )
    db.add(row)
    db.flush()
    return row


def close_assignment(db: Session, assignment_id: int, valid_until: datetime) -> int:
    """条件关闭在责段；返回受影响行数（0 表示已被并发转移关闭）。"""
    result = db.execute(
        ResponsibilityAssignment.__table__.update()
        .where(
            ResponsibilityAssignment.id == assignment_id,
            ResponsibilityAssignment.valid_until.is_(None),
        )
        .values(valid_until=valid_until)
    )
    return result.rowcount


# ---- 字段授权范围 ----------------------------------------------------------


def list_field_scopes(
    db: Session, activity_id: str, field_name: str | None = None
) -> list[FieldScope]:
    stmt = select(FieldScope).where(FieldScope.activity_id == activity_id)
    if field_name is not None:
        stmt = stmt.where(FieldScope.field_name == field_name)
    stmt = stmt.order_by(FieldScope.field_name, FieldScope.valid_from)
    return list(db.execute(stmt).scalars().all())


def get_open_field_scope(
    db: Session, activity_id: str, field_name: str
) -> FieldScope | None:
    stmt = select(FieldScope).where(
        FieldScope.activity_id == activity_id,
        FieldScope.field_name == field_name,
        FieldScope.valid_until.is_(None),
    )
    return db.execute(stmt).scalar_one_or_none()


def close_field_scope(db: Session, scope_id: int, valid_until: datetime) -> int:
    result = db.execute(
        FieldScope.__table__.update()
        .where(FieldScope.id == scope_id, FieldScope.valid_until.is_(None))
        .values(valid_until=valid_until)
    )
    return result.rowcount


def insert_field_scope(
    db: Session,
    *,
    activity_id: str,
    field_name: str,
    roles: Sequence[domain.Role],
    valid_from: datetime,
) -> FieldScope:
    row = FieldScope(
        activity_id=activity_id,
        field_name=field_name,
        roles=_encode_roles(roles),
        valid_from=valid_from,
        valid_until=None,
    )
    db.add(row)
    db.flush()
    return row


# ---- 委托 ------------------------------------------------------------------


def list_delegations(db: Session, activity_id: str) -> list[Delegation]:
    stmt = (
        select(Delegation)
        .where(Delegation.activity_id == activity_id)
        .order_by(Delegation.valid_from)
    )
    return list(db.execute(stmt).scalars().all())


def insert_delegation(
    db: Session,
    *,
    activity_id: str,
    delegator_actor_id: str,
    delegatee_actor_id: str,
    valid_from: datetime,
    valid_until: datetime | None,
    reason: str,
) -> Delegation:
    row = Delegation(
        activity_id=activity_id,
        delegator_actor_id=delegator_actor_id,
        delegatee_actor_id=delegatee_actor_id,
        valid_from=valid_from,
        valid_until=valid_until,
        reason=reason,
    )
    db.add(row)
    db.flush()
    return row


# ---- 更正单与签名 ----------------------------------------------------------


def get_correction(db: Session, correction_id: str) -> Correction | None:
    stmt = select(Correction).where(Correction.correction_id == correction_id)
    return db.execute(stmt).scalar_one_or_none()


def list_corrections(
    db: Session, activity_id: str, status: str | None = None
) -> list[Correction]:
    stmt = select(Correction).where(Correction.activity_id == activity_id)
    if status is not None:
        stmt = stmt.where(Correction.status == status)
    stmt = stmt.order_by(Correction.created_at, Correction.id)
    return list(db.execute(stmt).scalars().all())


def list_all_corrections_by_status(db: Session, status: str) -> list[Correction]:
    stmt = (
        select(Correction)
        .where(Correction.status == status)
        .order_by(Correction.created_at, Correction.id)
    )
    return list(db.execute(stmt).scalars().all())


def insert_correction(
    db: Session,
    *,
    correction_id: str,
    activity_id: str,
    field_name: str,
    event_ref: str,
    old_value: str,
    new_value: str,
    reason: str,
    status: str,
    requester_actor_id: str,
    event_occurred_at: datetime,
    required_roles: Sequence[domain.Role],
    is_emergency: bool,
    review_deadline: datetime | None,
) -> Correction:
    row = Correction(
        correction_id=correction_id,
        activity_id=activity_id,
        field_name=field_name,
        event_ref=event_ref,
        old_value=old_value,
        new_value=new_value,
        reason=reason,
        status=status,
        requester_actor_id=requester_actor_id,
        event_occurred_at=event_occurred_at,
        required_roles=_encode_roles(required_roles),
        is_emergency=is_emergency,
        review_deadline=review_deadline,
        version=1,
    )
    db.add(row)
    db.flush()
    return row


def get_signature_for_role(
    db: Session, correction_pk: int, role: str
) -> CorrectionSignature | None:
    stmt = select(CorrectionSignature).where(
        CorrectionSignature.correction_pk == correction_pk,
        CorrectionSignature.role == role,
    )
    return db.execute(stmt).scalar_one_or_none()


def add_signature(
    db: Session,
    *,
    correction_pk: int,
    signer_actor_id: str,
    role: str,
    kind: str,
    signed_at: datetime,
    note: str,
) -> CorrectionSignature:
    """插入会签记录；同角色重复插入由唯一约束拒绝（IntegrityError）。"""
    row = CorrectionSignature(
        correction_pk=correction_pk,
        signer_actor_id=signer_actor_id,
        role=role,
        kind=kind,
        signed_at=signed_at,
        note=note,
    )
    db.add(row)
    db.flush()
    return row


def list_signatures(db: Session, correction_pk: int) -> list[CorrectionSignature]:
    stmt = (
        select(CorrectionSignature)
        .where(CorrectionSignature.correction_pk == correction_pk)
        .order_by(CorrectionSignature.signed_at, CorrectionSignature.id)
    )
    return list(db.execute(stmt).scalars().all())


def advance_correction(
    db: Session,
    correction: Correction,
    *,
    status: str,
    expected_version: int,
) -> int:
    """以乐观锁推进更正单状态，返回受影响行数。"""
    result = db.execute(
        Correction.__table__.update()
        .where(
            Correction.id == correction.id,
            Correction.version == expected_version,
        )
        .values(status=status, version=expected_version + 1)
    )
    return result.rowcount


# ---- 审计链 ----------------------------------------------------------------


def append_audit(
    db: Session,
    *,
    activity_id: str,
    entity_type: str,
    entity_id: str,
    action: str,
    actor_id: str,
    occurred_at: datetime,
    detail: dict[str, Any],
) -> ResponsibilityAudit:
    """追加链式审计条目。

    序列号在事务内取 max+1，并由 ``(activity_id, sequence)`` 唯一约束兜底；
    冲突时抛出 :class:`IntegrityError`，由外层服务回滚整个业务事务
    （绝不为抢号单独回滚，避免业务写入与审计写入出现半提交）。
    """
    last = db.execute(
        select(ResponsibilityAudit.sequence)
        .where(ResponsibilityAudit.activity_id == activity_id)
        .order_by(ResponsibilityAudit.sequence.desc())
        .limit(1)
    ).scalar_one_or_none()
    sequence = (last or 0) + 1
    previous = (
        db.execute(
            select(ResponsibilityAudit.fingerprint).where(
                ResponsibilityAudit.activity_id == activity_id,
                ResponsibilityAudit.sequence == sequence - 1,
            )
        ).scalar_one_or_none()
        if sequence > 1
        else ""
    )
    fingerprint = domain.audit_fingerprint(
        sequence=sequence,
        activity_id=activity_id,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        actor_id=actor_id,
        occurred_at=occurred_at,
        detail=detail,
        previous_fingerprint=previous or "",
    )
    row = ResponsibilityAudit(
        activity_id=activity_id,
        sequence=sequence,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        actor_id=actor_id,
        occurred_at=occurred_at,
        detail=detail,
        fingerprint=fingerprint,
        previous_fingerprint=previous or "",
    )
    db.add(row)
    db.flush()
    return row


def list_audit(
    db: Session,
    activity_id: str,
    *,
    entity_type: str | None = None,
    entity_id: str | None = None,
) -> list[ResponsibilityAudit]:
    stmt = select(ResponsibilityAudit).where(
        ResponsibilityAudit.activity_id == activity_id
    )
    if entity_type is not None:
        stmt = stmt.where(ResponsibilityAudit.entity_type == entity_type)
    if entity_id is not None:
        stmt = stmt.where(ResponsibilityAudit.entity_id == entity_id)
    stmt = stmt.order_by(ResponsibilityAudit.sequence)
    return list(db.execute(stmt).scalars().all())
