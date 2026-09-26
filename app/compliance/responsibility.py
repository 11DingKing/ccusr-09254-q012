"""联合实训多方责任链领域逻辑。

一个联合实训活动可由学院、企业与第三方共同负责。出现数据争议时，需要依据
*事件发生时刻*生效的责任链判断谁有权更正哪类字段：

* 责任角色（:class:`Role`）在有效区间（半开区间 ``[valid_from, valid_until)``）
  内承担责任，责任转移只追加新区间、不修改旧区间；
* 字段授权范围可由单方独有或多方共有，共有字段必须完成会签；
* 授权可通过委托在区间内传导，但禁止形成循环授权；
* 紧急更正可先行生效，但必须在补审期限内由其余责任方补签，否则自动失效。

本模块只包含纯判定逻辑，不落库、不读取时钟，便于与存储层解耦测试。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import Iterable, Mapping, Sequence


class DomainError(ValueError):
    """封装责任链领域约束。"""


class Role(StrEnum):
    COLLEGE = "college"
    ENTERPRISE = "enterprise"
    THIRD_PARTY = "third_party"


class CorrectionStatus(StrEnum):
    PENDING_COUNTERSIGN = "pending_countersign"
    EFFECTIVE = "effective"
    EMERGENCY_PENDING = "emergency_pending"
    EXPIRED = "expired"
    REJECTED = "rejected"


class SignatureKind(StrEnum):
    SUBMIT = "submit"
    EMERGENCY = "emergency"
    COUNTERSIGN = "countersign"
    REVIEW = "review"


class DenyReason(StrEnum):
    FIELD_NOT_GOVERNED = "field_not_governed"
    CHAIN_GAP = "chain_gap"
    UNAUTHORIZED = "unauthorized"


def normalize(value: datetime) -> datetime:
    """统一为带时区的 UTC 时间。"""
    if value.tzinfo is None:
        raise DomainError("时间戳必须包含时区信息")
    return value.astimezone(UTC)


def in_window(
    valid_from: datetime, valid_until: datetime | None, at: datetime
) -> bool:
    """判断 ``at`` 是否落在半开有效区间内。"""
    moment = normalize(at)
    start = normalize(valid_from)
    if moment < start:
        return False
    if valid_until is not None and moment >= normalize(valid_until):
        return False
    return True


@dataclass(frozen=True)
class RoleGrant:
    """某角色在有效区间内的责任归属。"""

    role: Role
    actor_id: str
    valid_from: datetime
    valid_until: datetime | None = None

    def effective(self, at: datetime) -> bool:
        return in_window(self.valid_from, self.valid_until, at)


@dataclass(frozen=True)
class FieldScope:
    """字段在有效区间内的授权角色范围；多角色即共有会签字段。"""

    field_name: str
    roles: tuple[Role, ...]
    valid_from: datetime
    valid_until: datetime | None = None

    def effective(self, at: datetime) -> bool:
        return in_window(self.valid_from, self.valid_until, at)


@dataclass(frozen=True)
class DelegationEdge:
    """委托方在区间内授权受托方代为履职（``delegator -> delegatee``）。"""

    delegator_actor_id: str
    delegatee_actor_id: str
    valid_from: datetime
    valid_until: datetime | None = None

    def effective(self, at: datetime) -> bool:
        return in_window(self.valid_from, self.valid_until, at)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str | None
    required_roles: tuple[Role, ...]
    actor_roles: tuple[Role, ...]
    missing_roles: tuple[Role, ...]
    countersign_required: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "required_roles": [r.value for r in self.required_roles],
            "actor_roles": [r.value for r in self.actor_roles],
            "missing_roles": [r.value for r in self.missing_roles],
            "countersign_required": self.countersign_required,
        }


def _deny(
    reason: DenyReason,
    required: Iterable[Role] = (),
    actor_roles: Iterable[Role] = (),
) -> Decision:
    required_t = tuple(required)
    return Decision(
        allowed=False,
        reason=reason.value,
        required_roles=required_t,
        actor_roles=tuple(actor_roles),
        missing_roles=required_t,
        countersign_required=len(required_t) > 1,
    )


def select_current(
    records: Sequence[RoleGrant | FieldScope], at: datetime
) -> object | None:
    """取 ``at`` 时刻生效的最新版本；区间互不重叠时最多命中一条。"""
    hits = [r for r in records if r.effective(at)]
    if not hits:
        return None
    return max(hits, key=lambda r: normalize(r.valid_from))


def _reaches(edges: Sequence[tuple[str, str]], start: str, target: str) -> bool:
    """沿 ``delegator -> delegatee`` 方向判断 start 能否传导到 target。"""
    adjacency: dict[str, set[str]] = {}
    for source, dest in edges:
        adjacency.setdefault(source, set()).add(dest)
    pending = [start]
    seen = {start}
    while pending:
        current = pending.pop()
        if current == target:
            return True
        for nxt in adjacency.get(current, ()):
            if nxt not in seen:
                seen.add(nxt)
                pending.append(nxt)
    return False


def creates_cycle(
    existing: Iterable[DelegationEdge],
    delegator: str,
    delegatee: str,
    at: datetime,
) -> bool:
    """判断在 ``at`` 时刻加入新委托边是否构成循环授权（含自环）。"""
    if delegator == delegatee:
        return True
    edges = [
        (e.delegator_actor_id, e.delegatee_actor_id)
        for e in existing
        if e.effective(at)
    ]
    edges.append((delegator, delegatee))
    # 新增 u->v 后成环，当且仅当沿现有/新边 v 能回到 u。
    return _reaches(edges, delegatee, delegator)


def roles_for_actor(
    grants: Iterable[RoleGrant],
    delegations: Iterable[DelegationEdge],
    actor_id: str,
    at: datetime,
) -> frozenset[Role]:
    """返回 actor 在 ``at`` 时刻可履职的角色集合（含委托传导）。"""
    live_edges = [
        (e.delegator_actor_id, e.delegatee_actor_id)
        for e in delegations
        if e.effective(at)
    ]
    roles: set[Role] = set()
    for grant in grants:
        if not grant.effective(at):
            continue
        if grant.actor_id == actor_id or _reaches(
            live_edges, grant.actor_id, actor_id
        ):
            roles.add(grant.role)
    return frozenset(roles)


def decide(
    *,
    field_name: str,
    actor_id: str,
    at: datetime,
    field_scopes: Iterable[FieldScope],
    grants: Iterable[RoleGrant],
    delegations: Iterable[DelegationEdge],
) -> Decision:
    """依据事件时刻的责任链与授权范围给出更正授权判定。"""
    scope = select_current(
        [s for s in field_scopes if s.field_name == field_name], at
    )
    if scope is None:
        return _deny(DenyReason.FIELD_NOT_GOVERNED)
    assert isinstance(scope, FieldScope)
    required = tuple(dict.fromkeys(scope.roles))

    live_grants = [g for g in grants if g.effective(at)]
    held_roles = roles_for_actor(live_grants, delegations, actor_id, at)

    staffed = {g.role for g in live_grants}
    if any(role not in staffed for role in required):
        return _deny(DenyReason.CHAIN_GAP, required, held_roles)

    satisfied = tuple(role for role in required if role in held_roles)
    if not satisfied:
        return _deny(DenyReason.UNAUTHORIZED, required, held_roles)

    missing = tuple(role for role in required if role not in held_roles)
    return Decision(
        allowed=True,
        reason=None,
        required_roles=required,
        actor_roles=tuple(sorted(held_roles, key=lambda r: r.value)),
        missing_roles=missing,
        countersign_required=len(required) > 1,
    )


def remaining_roles(
    required: Iterable[Role], signed: Iterable[Role]
) -> tuple[Role, ...]:
    return tuple(role for role in required if role not in set(signed))


def review_deadline(now: datetime, review_seconds: int) -> datetime:
    if review_seconds <= 0:
        raise DomainError("补审期限必须大于零")
    return normalize(now) + timedelta(seconds=review_seconds)


def within_review_window(now: datetime, deadline: datetime) -> bool:
    return normalize(now) <= normalize(deadline)


def audit_fingerprint(
    *,
    sequence: int,
    activity_id: str,
    entity_type: str,
    entity_id: str,
    action: str,
    actor_id: str,
    occurred_at: datetime,
    detail: Mapping[str, object],
    previous_fingerprint: str,
) -> str:
    """计算审计条目的链式指纹（前一条指纹参与哈希）。"""
    timestamp = normalize(occurred_at).isoformat()
    raw = "|".join(
        [
            str(sequence),
            activity_id,
            entity_type,
            entity_id,
            action,
            actor_id,
            timestamp,
            repr(sorted((detail or {}).items())),
            previous_fingerprint,
        ]
    )
    return sha256(raw.encode("utf-8")).hexdigest()
