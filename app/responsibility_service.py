"""多方责任链应用服务。

关键规则：
* 更正授权按 *事件发生时刻* 的责任链判定，而非提交时刻；
* 责任转移只在新时点追加新段，旧段原样保留（不追溯改变旧授权）；
* 共有字段必须集齐全部责任角色的会签；
* 紧急更正先行进入 ``emergency_pending``，必须在补审期限内补签，否则失效。
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import responsibility_store as store
from .compliance import responsibility as domain

DEFAULT_REVIEW_SECONDS = 24 * 60 * 60


class ConfigError(ValueError):
    """责任配置本身不合法（区间、角色或循环授权）。"""


class AuthorizationError(PermissionError):
    """操作人在事件时刻的责任链上不具备授权。"""


class CorrectionStateError(RuntimeError):
    """更正单当前状态不允许该操作。"""


def _utc(value: datetime) -> datetime:
    try:
        return domain.normalize(value)
    except domain.DomainError as exc:
        raise ConfigError(str(exc)) from exc


def _load_context(db: Session, activity_id: str):
    grants = [store.to_grant(r) for r in store.list_assignments(db, activity_id)]
    scopes = [store.to_scope(r) for r in store.list_field_scopes(db, activity_id)]
    edges = [store.to_edge(r) for r in store.list_delegations(db, activity_id)]
    return grants, scopes, edges


# ---- 责任配置 --------------------------------------------------------------


def _assignment_dict(row) -> dict[str, Any]:
    return {
        "id": row.id,
        "activity_id": row.activity_id,
        "role": row.role,
        "actor_id": row.actor_id,
        "valid_from": store_utc(row.valid_from),
        "valid_until": store_utc(row.valid_until),
        "supersedes_id": row.supersedes_id,
        "note": row.note,
    }


def store_utc(value: datetime | None) -> datetime | None:
    """SQLite 不保留时区，读回的时间按 UTC 补回。"""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def configure_assignment(
    db: Session,
    *,
    activity_id: str,
    role: str,
    actor_id: str,
    valid_from: datetime,
    note: str = "",
) -> dict[str, Any]:
    """配置/转移某角色的责任归属；并发转移只有一个请求生效。"""
    try:
        role_enum = domain.Role(role)
    except ValueError as exc:
        raise ConfigError(f"未知责任角色: {role}") from exc
    actor_id = actor_id.strip()
    if not actor_id:
        raise ConfigError("责任人不能为空")
    moment = _utc(valid_from)

    current = store.get_open_assignment(db, activity_id, role_enum.value)
    if current is not None and current.actor_id == actor_id:
        # 同一责任人重复配置视为幂等。
        return _assignment_dict(current)
    if current is not None and moment <= store_utc(current.valid_from):
        raise ConfigError("责任转移不能早于或等于当前授权的生效时点（旧授权不被追溯改变）")

    try:
        if current is not None:
            changed = store.close_assignment(db, current.id, moment)
            if changed == 0:
                db.rollback()
                raise store.ConflictError("该角色责任已被并发转移，请重试")
            new_row = store.insert_assignment(
                db,
                activity_id=activity_id,
                role=role_enum.value,
                actor_id=actor_id,
                valid_from=moment,
                supersedes_id=current.id,
                note=note,
            )
            action = "responsibility_transfer"
            detail = {
                "role": role_enum.value,
                "from_actor": current.actor_id,
                "to_actor": actor_id,
                "valid_from": moment.isoformat(),
            }
        else:
            new_row = store.insert_assignment(
                db,
                activity_id=activity_id,
                role=role_enum.value,
                actor_id=actor_id,
                valid_from=moment,
                supersedes_id=None,
                note=note,
            )
            action = "responsibility_assign"
            detail = {
                "role": role_enum.value,
                "actor": actor_id,
                "valid_from": moment.isoformat(),
            }
        store.append_audit(
            db,
            activity_id=activity_id,
            entity_type="assignment",
            entity_id=str(new_row.id),
            action=action,
            actor_id=actor_id,
            occurred_at=moment,
            detail=detail,
        )
        db.commit()
    except store.ConflictError:
        raise
    except IntegrityError as exc:
        db.rollback()
        raise store.ConflictError("责任配置与并发请求冲突") from exc
    return _assignment_dict(new_row)


def _scope_dict(row) -> dict[str, Any]:
    return {
        "id": row.id,
        "activity_id": row.activity_id,
        "field_name": row.field_name,
        "roles": list(store._parse_roles(row.roles)),
        "valid_from": store_utc(row.valid_from),
        "valid_until": store_utc(row.valid_until),
    }


def configure_field_scope(
    db: Session,
    *,
    activity_id: str,
    field_name: str,
    roles: list[str],
    valid_from: datetime,
) -> dict[str, Any]:
    """配置字段授权范围；多角色即共有会签字段。"""
    field_name = field_name.strip()
    if not field_name:
        raise ConfigError("字段名不能为空")
    if not roles:
        raise ConfigError("授权角色范围不能为空")
    role_enums: list[domain.Role] = []
    for raw in roles:
        try:
            role_enum = domain.Role(raw)
        except ValueError as exc:
            raise ConfigError(f"未知责任角色: {raw}") from exc
        if role_enum not in role_enums:
            role_enums.append(role_enum)
    moment = _utc(valid_from)

    current = store.get_open_field_scope(db, activity_id, field_name)
    current_roles = store._parse_roles(current.roles) if current is not None else ()
    if current is not None and tuple(role_enums) == tuple(current_roles):
        return _scope_dict(current)
    if current is not None and moment <= store_utc(current.valid_from):
        raise ConfigError("授权范围调整不能早于或等于当前版本的生效时点")

    try:
        if current is not None:
            changed = store.close_field_scope(db, current.id, moment)
            if changed == 0:
                db.rollback()
                raise store.ConflictError("字段授权范围已被并发修改，请重试")
        new_row = store.insert_field_scope(
            db,
            activity_id=activity_id,
            field_name=field_name,
            roles=role_enums,
            valid_from=moment,
        )
        store.append_audit(
            db,
            activity_id=activity_id,
            entity_type="field_scope",
            entity_id=str(new_row.id),
            action="field_scope_configure",
            actor_id="system",
            occurred_at=moment,
            detail={
                "field": field_name,
                "roles": [r.value for r in role_enums],
                "valid_from": moment.isoformat(),
            },
        )
        db.commit()
    except store.ConflictError:
        raise
    except IntegrityError as exc:
        db.rollback()
        raise store.ConflictError("字段范围配置与并发请求冲突") from exc
    return _scope_dict(new_row)


def _delegation_dict(row) -> dict[str, Any]:
    return {
        "id": row.id,
        "activity_id": row.activity_id,
        "delegator_actor_id": row.delegator_actor_id,
        "delegatee_actor_id": row.delegatee_actor_id,
        "valid_from": store_utc(row.valid_from),
        "valid_until": store_utc(row.valid_until),
        "reason": row.reason,
    }


def configure_delegation(
    db: Session,
    *,
    activity_id: str,
    delegator_actor_id: str,
    delegatee_actor_id: str,
    valid_from: datetime,
    valid_until: datetime | None,
    reason: str = "",
) -> dict[str, Any]:
    """新增责任委托；若在生效时点形成循环授权则拒绝。"""
    delegator = delegator_actor_id.strip()
    delegatee = delegatee_actor_id.strip()
    if not delegator or not delegatee:
        raise ConfigError("委托双方不能为空")
    if delegator == delegatee:
        raise ConfigError("委托不能形成自环（循环授权）")
    moment = _utc(valid_from)
    end = _utc(valid_until) if valid_until is not None else None
    if end is not None and end <= moment:
        raise ConfigError("委托区间必须大于零")

    existing = [store.to_edge(r) for r in store.list_delegations(db, activity_id)]
    if domain.creates_cycle(existing, delegator, delegatee, moment):
        raise ConfigError("该委托会形成循环授权，已拒绝")

    try:
        row = store.insert_delegation(
            db,
            activity_id=activity_id,
            delegator_actor_id=delegator,
            delegatee_actor_id=delegatee,
            valid_from=moment,
            valid_until=end,
            reason=reason,
        )
        store.append_audit(
            db,
            activity_id=activity_id,
            entity_type="delegation",
            entity_id=str(row.id),
            action="delegation_create",
            actor_id=delegator,
            occurred_at=moment,
            detail={
                "delegator": delegator,
                "delegatee": delegatee,
                "valid_from": moment.isoformat(),
                "valid_until": end.isoformat() if end else None,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise store.ConflictError("委托配置与并发请求冲突") from exc
    return _delegation_dict(row)


def describe_chain(db: Session, activity_id: str) -> dict[str, Any]:
    assignments, scopes, delegations = _load_context(db, activity_id)
    return {
        "activity_id": activity_id,
        "assignments": [
            {
                "role": g.role.value,
                "actor_id": g.actor_id,
                "valid_from": g.valid_from,
                "valid_until": g.valid_until,
            }
            for g in assignments
        ],
        "field_scopes": [
            {
                "field_name": s.field_name,
                "roles": [r.value for r in s.roles],
                "valid_from": s.valid_from,
                "valid_until": s.valid_until,
            }
            for s in scopes
        ],
        "delegations": [
            {
                "delegator_actor_id": e.delegator_actor_id,
                "delegatee_actor_id": e.delegatee_actor_id,
                "valid_from": e.valid_from,
                "valid_until": e.valid_until,
            }
            for e in delegations
        ],
    }


# ---- 授权判定 --------------------------------------------------------------


def authorize(
    db: Session,
    *,
    activity_id: str,
    field_name: str,
    actor_id: str,
    at: datetime | None = None,
) -> dict[str, Any]:
    moment = _utc(at) if at is not None else datetime.now(timezone.utc)
    grants, scopes, edges = _load_context(db, activity_id)
    decision = domain.decide(
        field_name=field_name.strip(),
        actor_id=actor_id.strip(),
        at=moment,
        field_scopes=scopes,
        grants=grants,
        delegations=edges,
    )
    result = decision.to_dict()
    result.update(
        {
            "activity_id": activity_id,
            "field_name": field_name,
            "actor_id": actor_id,
            "at": moment,
        }
    )
    return result


# ---- 更正单与会签 ----------------------------------------------------------


def _signature_dict(row) -> dict[str, Any]:
    return {
        "signer_actor_id": row.signer_actor_id,
        "role": row.role,
        "kind": row.kind,
        "signed_at": store_utc(row.signed_at),
        "note": row.note,
    }


def _correction_dict(row, signatures: list | None = None) -> dict[str, Any]:
    required = store._parse_roles(row.required_roles)
    sigs = signatures if signatures is not None else []
    signed_roles = {s.role for s in sigs}
    return {
        "correction_id": row.correction_id,
        "activity_id": row.activity_id,
        "field_name": row.field_name,
        "event_ref": row.event_ref,
        "event_occurred_at": store_utc(row.event_occurred_at),
        "old_value": row.old_value,
        "new_value": row.new_value,
        "reason": row.reason,
        "status": row.status,
        "requester_actor_id": row.requester_actor_id,
        "required_roles": [r.value for r in required],
        "signed_roles": sorted(signed_roles),
        "missing_roles": [r.value for r in required if r.value not in signed_roles],
        "is_emergency": bool(row.is_emergency),
        "review_deadline": store_utc(row.review_deadline),
        "version": row.version,
        "signatures": [_signature_dict(s) for s in sigs],
    }


def _fresh_correction(db: Session, correction_id: str):
    row = store.get_correction(db, correction_id)
    if row is None:
        raise store.NotFoundError(f"更正单 '{correction_id}' 不存在")
    return row


def submit_correction(
    db: Session,
    *,
    activity_id: str,
    correction_id: str,
    field_name: str,
    event_ref: str,
    event_occurred_at: datetime,
    old_value: str,
    new_value: str,
    reason: str,
    actor_id: str,
    is_emergency: bool = False,
    review_seconds: int = DEFAULT_REVIEW_SECONDS,
    now: datetime | None = None,
) -> dict[str, Any]:
    correction_id = correction_id.strip()
    actor_id = actor_id.strip()
    if not correction_id or not actor_id:
        raise ConfigError("更正单编号与操作人不能为空")
    if not reason.strip():
        raise ConfigError("更正必须填写争议原因")
    if old_value == new_value:
        raise ConfigError("新旧值相同，无需更正")
    event_time = _utc(event_occurred_at)

    if store.get_correction(db, correction_id) is not None:
        raise store.ConflictError(f"更正单 '{correction_id}' 已存在")

    grants, scopes, edges = _load_context(db, activity_id)
    decision = domain.decide(
        field_name=field_name.strip(),
        actor_id=actor_id,
        at=event_time,
        field_scopes=scopes,
        grants=grants,
        delegations=edges,
    )
    if not decision.allowed:
        raise AuthorizationError(
            f"事件时刻责任链判定拒绝更正: {decision.reason}"
        )

    held_required = [
        role for role in decision.required_roles if role in decision.actor_roles
    ]
    missing = domain.remaining_roles(decision.required_roles, held_required)

    moment_now = _utc(now) if now is not None else datetime.now(timezone.utc)
    if not missing:
        status = domain.CorrectionStatus.EFFECTIVE.value
        deadline = None
    elif is_emergency:
        status = domain.CorrectionStatus.EMERGENCY_PENDING.value
        deadline = domain.review_deadline(moment_now, review_seconds)
    else:
        status = domain.CorrectionStatus.PENDING_COUNTERSIGN.value
        deadline = None

    submit_kind = (
        domain.SignatureKind.EMERGENCY.value
        if status == domain.CorrectionStatus.EMERGENCY_PENDING.value
        else domain.SignatureKind.SUBMIT.value
    )

    try:
        row = store.insert_correction(
            db,
            correction_id=correction_id,
            activity_id=activity_id,
            field_name=field_name,
            event_ref=event_ref,
            old_value=old_value,
            new_value=new_value,
            reason=reason,
            status=status,
            requester_actor_id=actor_id,
            event_occurred_at=event_time,
            required_roles=decision.required_roles,
            is_emergency=status == domain.CorrectionStatus.EMERGENCY_PENDING.value,
            review_deadline=deadline,
        )
        for role in held_required:
            store.add_signature(
                db,
                correction_pk=row.id,
                signer_actor_id=actor_id,
                role=role.value,
                kind=submit_kind,
                signed_at=moment_now,
                note="紧急更正先行生效" if is_emergency and missing else "",
            )
        store.append_audit(
            db,
            activity_id=activity_id,
            entity_type="correction",
            entity_id=correction_id,
            action="correction_emergency"
            if status == domain.CorrectionStatus.EMERGENCY_PENDING.value
            else "correction_submit",
            actor_id=actor_id,
            occurred_at=moment_now,
            detail={
                "field": field_name,
                "event_ref": event_ref,
                "event_occurred_at": event_time.isoformat(),
                "required_roles": [r.value for r in decision.required_roles],
                "missing_roles": [r.value for r in missing],
                "review_deadline": deadline.isoformat() if deadline else None,
            },
        )
        if status == domain.CorrectionStatus.EFFECTIVE.value:
            store.append_audit(
                db,
                activity_id=activity_id,
                entity_type="correction",
                entity_id=correction_id,
                action="correction_effective",
                actor_id=actor_id,
                occurred_at=moment_now,
                detail={"field": field_name, "via": "single_or_complete"},
            )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise store.ConflictError("更正单与并发请求冲突") from exc

    signatures = store.list_signatures(db, row.id)
    return _correction_dict(row, signatures)


def get_correction(db: Session, correction_id: str) -> dict[str, Any]:
    row = _fresh_correction(db, correction_id)
    return _correction_dict(row, store.list_signatures(db, row.id))


def list_corrections(
    db: Session, activity_id: str, status: str | None = None
) -> list[dict[str, Any]]:
    rows = store.list_corrections(db, activity_id, status)
    return [
        _correction_dict(row, store.list_signatures(db, row.id)) for row in rows
    ]


def _expire_if_due(db: Session, row, now: datetime) -> bool:
    """紧急更正超过补审期限则懒失效。返回是否已置为失效。"""
    if row.status != domain.CorrectionStatus.EMERGENCY_PENDING.value:
        return False
    deadline = store_utc(row.review_deadline)
    if deadline is None or now <= deadline:
        return False
    changed = store.advance_correction(
        db, row, status=domain.CorrectionStatus.EXPIRED.value, expected_version=row.version
    )
    if changed:
        store.append_audit(
            db,
            activity_id=row.activity_id,
            entity_type="correction",
            entity_id=row.correction_id,
            action="correction_expired",
            actor_id="system",
            occurred_at=now,
            detail={"review_deadline": deadline.isoformat()},
        )
        db.commit()
    return changed > 0


def expire_overdue_corrections(
    db: Session, *, activity_id: str | None = None, now: datetime | None = None
) -> list[str]:
    """批量清理超过补审期限仍未补签的紧急更正。"""
    moment = _utc(now) if now is not None else datetime.now(timezone.utc)
    if activity_id is None:
        rows = store.list_all_corrections_by_status(
            db, domain.CorrectionStatus.EMERGENCY_PENDING.value
        )
    else:
        rows = store.list_corrections(
            db, activity_id, domain.CorrectionStatus.EMERGENCY_PENDING.value
        )
    expired: list[str] = []
    for row in rows:
        if _expire_if_due(db, row, moment):
            expired.append(row.correction_id)
    return expired


def countersign(
    db: Session,
    *,
    correction_id: str,
    actor_id: str,
    note: str = "",
    at: datetime | None = None,
) -> dict[str, Any]:
    """对待会签更正补签；授权仍以事件时刻责任链为准。

    整个会签（签名行 + 审计条目 + 可能的状态推进）在单个事务内完成；
    遇到唯一约束/审计序列号/乐观锁竞争时整体回滚后重试，保证业务写入与
    审计写入要么同时落库、要么同时不存在。
    """
    actor_id = actor_id.strip()
    if not actor_id:
        raise ConfigError("会签人不能为空")
    now = _utc(at) if at is not None else datetime.now(timezone.utc)

    row = _fresh_correction(db, correction_id)
    if _expire_if_due(db, row, now):
        raise CorrectionStateError("补审期限已过，紧急更正已失效")

    for _ in range(10):
        try:
            row = _fresh_correction(db, correction_id)
            if row.status not in (
                domain.CorrectionStatus.PENDING_COUNTERSIGN.value,
                domain.CorrectionStatus.EMERGENCY_PENDING.value,
            ):
                raise CorrectionStateError(
                    f"更正单当前状态 {row.status} 不接受会签"
                )

            # 授权判定锚定事件发生时刻，而不是会签时刻。
            grants = [
                store.to_grant(g) for g in store.list_assignments(db, row.activity_id)
            ]
            edges = [
                store.to_edge(e) for e in store.list_delegations(db, row.activity_id)
            ]
            event_time = store_utc(row.event_occurred_at)
            held = domain.roles_for_actor(grants, edges, actor_id, event_time)
            required = store._parse_roles(row.required_roles)
            already = {s.role for s in store.list_signatures(db, row.id)}
            candidate = [
                role
                for role in required
                if role in held and role.value not in already
            ]
            if not candidate:
                if held:
                    raise AuthorizationError(
                        "操作人负责的角色已完成会签或不属于该更正单"
                    )
                raise AuthorizationError(
                    "操作人在事件时刻的责任链上不承担所需责任角色"
                )

            expected_version = row.version
            for role in candidate:
                store.add_signature(
                    db,
                    correction_pk=row.id,
                    signer_actor_id=actor_id,
                    role=role.value,
                    kind=domain.SignatureKind.COUNTERSIGN.value,
                    signed_at=now,
                    note=note,
                )
            store.append_audit(
                db,
                activity_id=row.activity_id,
                entity_type="correction",
                entity_id=correction_id,
                action="correction_countersign",
                actor_id=actor_id,
                occurred_at=now,
                detail={"roles": [r.value for r in candidate]},
            )

            signed_now = already | {r.value for r in candidate}
            if all(r.value in signed_now for r in required):
                changed = store.advance_correction(
                    db,
                    row,
                    status=domain.CorrectionStatus.EFFECTIVE.value,
                    expected_version=expected_version,
                )
                if changed == 0:
                    # 状态已被并发推进：整体回滚后重读再判定。
                    db.rollback()
                    continue
                store.append_audit(
                    db,
                    activity_id=row.activity_id,
                    entity_type="correction",
                    entity_id=correction_id,
                    action="correction_effective",
                    actor_id=actor_id,
                    occurred_at=now,
                    detail={"via": "countersign_complete"},
                )

            db.commit()
            break
        except IntegrityError:
            # 同角色并发会签或审计序列号竞争：整事务重试。
            db.rollback()
    else:
        raise store.ConflictError("并发会签冲突，多次重试后仍失败")

    _finalize_if_complete(db, correction_id, actor_id, now)

    row = _fresh_correction(db, correction_id)
    return _correction_dict(row, store.list_signatures(db, row.id))


def _finalize_if_complete(
    db: Session, correction_id: str, actor_id: str, now: datetime
) -> None:
    """提交后收尾：全部会签已落库（可能来自并发事务）则推进为生效。

    各并发会签事务无法读到对方未提交的签名，因此可能出现签名已齐但状态
    未推进的情况；由乐观锁保证多个收尾尝试中只有一个真正写入。
    """
    for _ in range(10):
        row = _fresh_correction(db, correction_id)
        if row.status not in (
            domain.CorrectionStatus.PENDING_COUNTERSIGN.value,
            domain.CorrectionStatus.EMERGENCY_PENDING.value,
        ):
            return
        if row.status == domain.CorrectionStatus.EMERGENCY_PENDING.value:
            deadline = store_utc(row.review_deadline)
            if deadline is not None and now > deadline:
                _expire_if_due(db, row, now)
                return
        required = store._parse_roles(row.required_roles)
        signed = {s.role for s in store.list_signatures(db, row.id)}
        if not all(r.value in signed for r in required):
            return
        try:
            changed = store.advance_correction(
                db,
                row,
                status=domain.CorrectionStatus.EFFECTIVE.value,
                expected_version=row.version,
            )
            if changed == 0:
                db.rollback()
                continue
            store.append_audit(
                db,
                activity_id=row.activity_id,
                entity_type="correction",
                entity_id=correction_id,
                action="correction_effective",
                actor_id=actor_id,
                occurred_at=now,
                detail={"via": "countersign_finalize"},
            )
            db.commit()
            return
        except IntegrityError:
            db.rollback()


# ---- 审计查询 --------------------------------------------------------------


def query_audit(
    db: Session,
    activity_id: str,
    *,
    entity_type: str | None = None,
    entity_id: str | None = None,
) -> dict[str, Any]:
    rows = store.list_audit(
        db, activity_id, entity_type=entity_type, entity_id=entity_id
    )
    entries = [
        {
            "sequence": r.sequence,
            "entity_type": r.entity_type,
            "entity_id": r.entity_id,
            "action": r.action,
            "actor_id": r.actor_id,
            "occurred_at": store_utc(r.occurred_at),
            "detail": r.detail,
            "fingerprint": r.fingerprint,
            "previous_fingerprint": r.previous_fingerprint,
        }
        for r in rows
    ]
    chain_valid = True
    broken_at: int | None = None
    previous = ""
    for r, entry in zip(rows, entries, strict=True):
        expected = domain.audit_fingerprint(
            sequence=entry["sequence"],
            activity_id=activity_id,
            entity_type=entry["entity_type"],
            entity_id=entry["entity_id"],
            action=entry["action"],
            actor_id=entry["actor_id"],
            occurred_at=entry["occurred_at"],
            detail=entry["detail"],
            previous_fingerprint=previous,
        )
        if expected != entry["fingerprint"] or entry["previous_fingerprint"] != previous:
            chain_valid = False
            broken_at = entry["sequence"]
            break
        previous = entry["fingerprint"]
    return {
        "activity_id": activity_id,
        "entries": entries,
        "chain_valid": chain_valid,
        "broken_at": broken_at,
    }
