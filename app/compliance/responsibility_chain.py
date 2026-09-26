"""联合实训活动主办方责任链领域逻辑。

联合实训中的一个活动可能由学院、企业和第三方共同负责。出现数据争议时，
需要明确谁有权更正哪类字段。该模块以纯领域对象刻画责任角色、授权范围
（可更正的字段类别）和有效区间，并提供：

- 责任授权的建立与转移：转移只截断当前授权并向未来开启新授权，
  不追溯改写旧授权已经覆盖的历史区间；
- 委托授权及循环委托检测：同一时刻生效的委托关系不得成环；
- 基于“当时责任链”的事件更正授权判定：更正必须匹配事件业务时间
  所对应的责任链，而不是提交更正时刻的责任链；
- 多方共同字段的会签流转；
- 紧急更正的限期补审。

模块不触碰数据库，所有时间参数必须带时区，内部统一归一到 UTC。
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import Iterable, Mapping, Sequence


class Role(StrEnum):
    """责任角色：联合实训的三类主办方。"""

    COLLEGE = "college"
    ENTERPRISE = "enterprise"
    THIRD_PARTY = "third_party"


class GrantStatus(StrEnum):
    ACTIVE = "active"
    CLOSED = "closed"  # 因责任转移而关闭，既有区间仍然参与历史判定
    REVOKED = "revoked"  # 作废，不再参与任何授权判定


class DelegationStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class CorrectionStatus(StrEnum):
    PENDING_COUNTERSIGN = "pending_countersign"
    APPROVED = "approved"
    REJECTED = "rejected"
    EMERGENCY_EFFECTIVE = "emergency_effective"
    CONFIRMED = "confirmed"
    REVERTED = "reverted"


class Decision(StrEnum):
    ALLOWED = "allowed"
    REQUIRES_COUNTERSIGN = "requires_countersign"
    DENIED = "denied"


class DomainError(ValueError):
    """封装领域状态与业务约束。"""


class AuthorizationError(DomainError):
    """越权操作：参与方不在当时责任链中。"""


class ConflictError(DomainError):
    """状态冲突：重复生效授权、重复会签、并发修改等。"""


class CircularDelegationError(ConflictError):
    """委托关系形成循环授权。"""


class ConcurrencyError(ConflictError):
    """基于版本的乐观并发冲突。"""


DEFAULT_REVIEW_WINDOW = timedelta(hours=48)


@dataclass(frozen=True)
class AuditEntry:
    sequence: int
    action: str
    actor_id: str
    occurred_at: datetime
    before: str
    after: str
    reason: str
    fingerprint: str


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise DomainError("时间必须包含时区")
    return value.astimezone(UTC)


def _fingerprint(identifier: str, version: int, action: str, actor: str, reason: str) -> str:
    raw = f"{identifier}|{version}|{action}|{actor}|{reason}".encode("utf-8")
    return sha256(raw).hexdigest()


def _require_text(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise DomainError(f"{label}不能为空")
    return normalized


def _role(value: Role | str) -> Role:
    try:
        return Role(value)
    except ValueError as exc:
        raise DomainError(f"未知责任角色: {value}") from exc


def _normalize_fields(fields: Iterable[str]) -> frozenset[str]:
    normalized = frozenset(item.strip() for item in fields if item and item.strip())
    if not normalized:
        raise DomainError("授权范围至少包含一个字段类别")
    return normalized


def _check_interval(
    effective_from: datetime, effective_to: datetime | None
) -> tuple[datetime, datetime | None]:
    start = _utc(effective_from)
    end = _utc(effective_to) if effective_to is not None else None
    if end is not None and end <= start:
        raise DomainError("有效区间的结束必须晚于开始")
    return start, end


def _covers(start: datetime, end: datetime | None, moment: datetime) -> bool:
    """半开区间 [start, end) 判定，跨日边界上结束时刻不含在内。"""
    instant = _utc(moment)
    if instant < start:
        return False
    return end is None or instant < end


def _audit_entry(
    identifier: str,
    sequence: int,
    version: int,
    action: str,
    actor_id: str,
    reason: str,
    now: datetime,
    *,
    before: str,
    after: str,
) -> AuditEntry:
    return AuditEntry(
        sequence=sequence,
        action=action,
        actor_id=actor_id,
        occurred_at=_utc(now),
        before=before,
        after=after,
        reason=reason,
        fingerprint=_fingerprint(identifier, version, action, actor_id, reason),
    )


@dataclass(frozen=True)
class Grant:
    """责任授权：某参与方在有效区间内对授权范围内的字段拥有更正权。"""

    grant_id: str
    activity_id: str
    role: Role
    party_id: str
    fields: frozenset[str]
    effective_from: datetime
    effective_to: datetime | None
    status: GrantStatus
    version: int
    audit: tuple[AuditEntry, ...] = ()

    @property
    def identifier(self) -> str:
        return self.grant_id

    def covers(self, moment: datetime) -> bool:
        """该授权在 moment 时刻是否位于责任链上。

        已关闭（CLOSED）的授权仍覆盖其历史区间，用于匹配当时责任链；
        已作废（REVOKED）的授权不再参与判定。
        """
        if self.status == GrantStatus.REVOKED:
            return False
        return _covers(self.effective_from, self.effective_to, moment)


@dataclass(frozen=True)
class Delegation:
    """委托授权：责任方在有效区间内把部分字段的更正权委托给其他参与方。"""

    delegation_id: str
    activity_id: str
    from_party_id: str
    to_party_id: str
    fields: frozenset[str]
    effective_from: datetime
    effective_to: datetime | None
    status: DelegationStatus
    version: int
    audit: tuple[AuditEntry, ...] = ()

    @property
    def identifier(self) -> str:
        return self.delegation_id

    def covers(self, moment: datetime) -> bool:
        if self.status != DelegationStatus.ACTIVE:
            return False
        return _covers(self.effective_from, self.effective_to, moment)


@dataclass(frozen=True)
class SharedFieldConfig:
    """共同字段配置：字段类别 -> 需要会签的责任角色。"""

    activity_id: str
    shared_fields: Mapping[str, tuple[Role, ...]]
    version: int
    audit: tuple[AuditEntry, ...] = ()

    @property
    def identifier(self) -> str:
        return self.activity_id


@dataclass(frozen=True)
class Authority:
    """授权判定结果中的一次权责命中；via_delegation_id 非空表示受托行使。"""

    party_id: str
    role: Role
    grant_id: str
    via_delegation_id: str | None


@dataclass(frozen=True)
class CountersignRequirement:
    party_id: str
    role: Role


@dataclass(frozen=True)
class AuthorizationResult:
    decision: Decision
    reason: str
    authority: Authority | None
    required_countersigners: tuple[CountersignRequirement, ...]


@dataclass(frozen=True)
class Countersignature:
    party_id: str
    role: Role
    approve: bool
    signed_at: datetime
    reason: str


@dataclass(frozen=True)
class Correction:
    """事件更正单：针对某个事件在某个业务时间点的字段修正。"""

    correction_id: str
    activity_id: str
    event_id: str
    field: str
    old_value: str
    new_value: str
    business_time: datetime
    requested_by: str
    requested_at: datetime
    emergency: bool
    status: CorrectionStatus
    required_countersigners: tuple[CountersignRequirement, ...]
    countersignatures: tuple[Countersignature, ...]
    review_deadline: datetime | None
    reviewed_by: str | None
    reviewed_at: datetime | None
    review_outcome: str | None
    version: int
    audit: tuple[AuditEntry, ...] = ()

    @property
    def identifier(self) -> str:
        return self.correction_id

    def review_overdue(self, now: datetime) -> bool:
        """紧急更正是否已超出补审期限仍未补审。"""
        return (
            self.status == CorrectionStatus.EMERGENCY_EFFECTIVE
            and self.review_deadline is not None
            and _utc(now) > self.review_deadline
        )


def create_grant(
    *,
    grant_id: str,
    activity_id: str,
    role: Role | str,
    party_id: str,
    fields: Iterable[str],
    effective_from: datetime,
    effective_to: datetime | None,
    actor_id: str,
    reason: str,
    now: datetime,
    existing: Iterable[Grant] = (),
) -> Grant:
    """建立责任授权；同一活动同一角色同一时间只允许一个生效中的授权。"""
    grant_id = _require_text(grant_id, "授权标识")
    activity_id = _require_text(activity_id, "活动标识")
    party_id = _require_text(party_id, "责任方")
    actor = _require_text(actor_id, "操作人")
    note = _require_text(reason, "操作原因")
    resolved_role = _role(role)
    scope = _normalize_fields(fields)
    start, end = _check_interval(effective_from, effective_to)
    for other in existing:
        if (
            other.activity_id == activity_id
            and other.role == resolved_role
            and other.status == GrantStatus.ACTIVE
        ):
            raise ConflictError(
                f"活动 '{activity_id}' 的角色 {resolved_role} 已存在生效中的责任授权"
            )
    instant = _utc(now)
    entry = _audit_entry(
        grant_id,
        1,
        1,
        "grant.create",
        actor,
        note,
        instant,
        before="",
        after=GrantStatus.ACTIVE.value,
    )
    return Grant(
        grant_id=grant_id,
        activity_id=activity_id,
        role=resolved_role,
        party_id=party_id,
        fields=scope,
        effective_from=start,
        effective_to=end,
        status=GrantStatus.ACTIVE,
        version=1,
        audit=(entry,),
    )


def plan_transfer(
    grant: Grant,
    *,
    to_party_id: str,
    new_grant_id: str,
    effective_at: datetime,
    actor_id: str,
    reason: str,
    now: datetime,
    to_role: Role | str | None = None,
    existing: Iterable[Grant] = (),
) -> tuple[Grant, Grant]:
    """规划一次责任转移：在 effective_at 截断当前授权并开启新授权。

    旧授权仅把有效区间截断到 effective_at，既有区间保持不变，历史事件
    的更正仍匹配旧责任链（不追溯）；effective_at 不得早于当前授权起点，
    避免改写已经发生的责任归属。
    """
    if grant.status != GrantStatus.ACTIVE:
        raise ConflictError("仅可转移生效中的责任授权")
    to_party = _require_text(to_party_id, "接收方")
    new_id = _require_text(new_grant_id, "新授权标识")
    actor = _require_text(actor_id, "操作人")
    note = _require_text(reason, "操作原因")
    target_role = _role(to_role) if to_role is not None else grant.role
    moment = _utc(effective_at)
    instant = _utc(now)
    if to_party == grant.party_id and target_role == grant.role:
        raise DomainError("接收方与当前责任方相同，无需转移")
    if moment < grant.effective_from:
        raise DomainError("转移生效时间早于当前授权起点，禁止追溯改写")
    for other in existing:
        if (
            other.grant_id != grant.grant_id
            and other.activity_id == grant.activity_id
            and other.role == target_role
            and other.status == GrantStatus.ACTIVE
        ):
            raise ConflictError(f"角色 {target_role} 已存在生效中的责任授权")
    closed_entry = _audit_entry(
        grant.grant_id,
        len(grant.audit) + 1,
        grant.version + 1,
        "grant.close",
        actor,
        note,
        instant,
        before=grant.status.value,
        after=GrantStatus.CLOSED.value,
    )
    closed = replace(
        grant,
        effective_to=moment,
        status=GrantStatus.CLOSED,
        version=grant.version + 1,
        audit=grant.audit + (closed_entry,),
    )
    opened_entry = _audit_entry(
        new_id,
        1,
        1,
        "grant.open",
        actor,
        note,
        instant,
        before="",
        after=GrantStatus.ACTIVE.value,
    )
    opened = Grant(
        grant_id=new_id,
        activity_id=grant.activity_id,
        role=target_role,
        party_id=to_party,
        fields=grant.fields,
        effective_from=moment,
        effective_to=grant.effective_to,
        status=GrantStatus.ACTIVE,
        version=1,
        audit=(opened_entry,),
    )
    return closed, opened


def _active_delegation_edges(
    delegations: Iterable[Delegation], activity_id: str, moment: datetime
) -> dict[str, set[str]]:
    edges: dict[str, set[str]] = {}
    for delegation in delegations:
        if delegation.activity_id != activity_id:
            continue
        if not delegation.covers(moment):
            continue
        edges.setdefault(delegation.from_party_id, set()).add(delegation.to_party_id)
    return edges


def _reachable(edges: Mapping[str, set[str]], start: str, target: str) -> bool:
    stack = [start]
    seen: set[str] = set()
    while stack:
        node = stack.pop()
        if node == target:
            return True
        if node in seen:
            continue
        seen.add(node)
        stack.extend(edges.get(node, ()))
    return False


def creates_cycle(
    delegations: Iterable[Delegation],
    *,
    activity_id: str,
    from_party_id: str,
    to_party_id: str,
    moment: datetime,
) -> bool:
    """在 moment 时刻生效的委托图中，新增 from -> to 是否形成循环授权。"""
    if from_party_id == to_party_id:
        return True
    edges = _active_delegation_edges(delegations, activity_id, _utc(moment))
    return _reachable(edges, to_party_id, from_party_id)


def delegate(
    *,
    delegation_id: str,
    activity_id: str,
    from_party_id: str,
    to_party_id: str,
    fields: Iterable[str],
    effective_from: datetime,
    effective_to: datetime | None,
    actor_id: str,
    reason: str,
    now: datetime,
    grants: Iterable[Grant],
    existing: Iterable[Delegation],
) -> Delegation:
    """建立委托授权；委托方必须自己持有这些字段，且不得形成循环授权。"""
    delegation_id = _require_text(delegation_id, "委托标识")
    activity_id = _require_text(activity_id, "活动标识")
    from_party = _require_text(from_party_id, "委托方")
    to_party = _require_text(to_party_id, "受托方")
    actor = _require_text(actor_id, "操作人")
    note = _require_text(reason, "操作原因")
    scope = _normalize_fields(fields)
    start, end = _check_interval(effective_from, effective_to)
    for field_name in sorted(scope):
        held = any(
            grant.activity_id == activity_id
            and grant.party_id == from_party
            and field_name in grant.fields
            and grant.covers(start)
            for grant in grants
        )
        if not held:
            raise AuthorizationError(
                f"委托方在委托生效时不持有字段 '{field_name}' 的授权"
            )
    if creates_cycle(
        existing,
        activity_id=activity_id,
        from_party_id=from_party,
        to_party_id=to_party,
        moment=start,
    ):
        raise CircularDelegationError("委托关系形成循环授权")
    instant = _utc(now)
    entry = _audit_entry(
        delegation_id,
        1,
        1,
        "delegation.create",
        actor,
        note,
        instant,
        before="",
        after=DelegationStatus.ACTIVE.value,
    )
    return Delegation(
        delegation_id=delegation_id,
        activity_id=activity_id,
        from_party_id=from_party,
        to_party_id=to_party,
        fields=scope,
        effective_from=start,
        effective_to=end,
        status=DelegationStatus.ACTIVE,
        version=1,
        audit=(entry,),
    )


def revoke_delegation(
    delegation: Delegation, *, actor_id: str, reason: str, now: datetime
) -> Delegation:
    actor = _require_text(actor_id, "操作人")
    note = _require_text(reason, "操作原因")
    if delegation.status != DelegationStatus.ACTIVE:
        raise ConflictError("仅可撤销生效中的委托")
    instant = _utc(now)
    next_version = delegation.version + 1
    entry = _audit_entry(
        delegation.delegation_id,
        len(delegation.audit) + 1,
        next_version,
        "delegation.revoke",
        actor,
        note,
        instant,
        before=delegation.status.value,
        after=DelegationStatus.REVOKED.value,
    )
    return replace(
        delegation,
        status=DelegationStatus.REVOKED,
        version=next_version,
        audit=delegation.audit + (entry,),
    )


def empty_shared_config(activity_id: str) -> SharedFieldConfig:
    return SharedFieldConfig(
        activity_id=activity_id, shared_fields={}, version=0, audit=()
    )


def configure_shared_fields(
    config: SharedFieldConfig,
    *,
    changes: Mapping[str, Sequence[str] | None],
    actor_id: str,
    reason: str,
    now: datetime,
) -> SharedFieldConfig:
    """配置共同字段及其会签角色；值为 None 或空列表表示移除该字段。"""
    actor = _require_text(actor_id, "操作人")
    note = _require_text(reason, "操作原因")
    merged: dict[str, tuple[Role, ...]] = {
        field_name: tuple(roles) for field_name, roles in config.shared_fields.items()
    }
    for raw_field, raw_roles in changes.items():
        field_name = raw_field.strip()
        if not field_name:
            raise DomainError("字段类别不能为空")
        if raw_roles is None or len(raw_roles) == 0:
            merged.pop(field_name, None)
            continue
        roles = tuple(dict.fromkeys(_role(item) for item in raw_roles))
        if len(roles) < 2:
            raise DomainError("共同字段至少需要两个会签角色")
        merged[field_name] = roles
    instant = _utc(now)
    next_version = config.version + 1
    entry = _audit_entry(
        config.activity_id,
        len(config.audit) + 1,
        next_version,
        "shared_fields.configure",
        actor,
        note,
        instant,
        before=str(sorted(config.shared_fields.items())),
        after=str(sorted(merged.items())),
    )
    return SharedFieldConfig(
        activity_id=config.activity_id,
        shared_fields=merged,
        version=next_version,
        audit=config.audit + (entry,),
    )


def direct_authorities(
    grants: Iterable[Grant], *, activity_id: str, field: str, business_time: datetime
) -> tuple[Authority, ...]:
    """当时责任链上直接持有该字段授权的参与方。"""
    field_name = field.strip()
    moment = _utc(business_time)
    result = [
        Authority(g.party_id, g.role, g.grant_id, None)
        for g in grants
        if g.activity_id == activity_id
        and field_name in g.fields
        and g.covers(moment)
    ]
    result.sort(key=lambda item: (item.role.value, item.party_id))
    return tuple(result)


def authorities_for(
    grants: Iterable[Grant],
    delegations: Iterable[Delegation],
    *,
    activity_id: str,
    field: str,
    business_time: datetime,
) -> tuple[Authority, ...]:
    """当时责任链上的全部权责：直接持有 + 经委托获得（一跳）。"""
    field_name = field.strip()
    moment = _utc(business_time)
    direct = direct_authorities(
        grants, activity_id=activity_id, field=field_name, business_time=moment
    )
    delegated: list[Authority] = []
    for authority in direct:
        for delegation in delegations:
            if (
                delegation.activity_id == activity_id
                and delegation.from_party_id == authority.party_id
                and field_name in delegation.fields
                and delegation.covers(moment)
            ):
                delegated.append(
                    Authority(
                        delegation.to_party_id,
                        authority.role,
                        authority.grant_id,
                        delegation.delegation_id,
                    )
                )
    delegated.sort(key=lambda item: (item.role.value, item.party_id))
    return direct + tuple(delegated)


def authorize(
    grants: Iterable[Grant],
    delegations: Iterable[Delegation],
    shared_config: SharedFieldConfig,
    *,
    activity_id: str,
    party_id: str,
    field: str,
    business_time: datetime,
) -> AuthorizationResult:
    """授权判定：更正必须匹配事件业务时间对应的当时责任链。"""
    activity = _require_text(activity_id, "活动标识")
    party = _require_text(party_id, "参与方")
    field_name = _require_text(field, "字段类别")
    moment = _utc(business_time)
    authorities = authorities_for(
        grants,
        delegations,
        activity_id=activity,
        field=field_name,
        business_time=moment,
    )
    mine = tuple(item for item in authorities if item.party_id == party)
    if not mine:
        return AuthorizationResult(
            Decision.DENIED,
            "该参与方不在当时责任链中，或授权范围/有效区间不匹配",
            None,
            (),
        )
    my_roles = {item.role for item in mine}
    shared_roles = set(shared_config.shared_fields.get(field_name, ()))
    required = tuple(
        CountersignRequirement(item.party_id, item.role)
        for item in authorities
        if item.via_delegation_id is None
        and item.role in shared_roles
        and item.role not in my_roles
        and item.party_id != party
    )
    authority = mine[0]
    if required:
        return AuthorizationResult(
            Decision.REQUIRES_COUNTERSIGN,
            "共同字段需要其他责任方会签",
            authority,
            required,
        )
    return AuthorizationResult(Decision.ALLOWED, "授权有效", authority, ())


def open_correction(
    *,
    correction_id: str,
    activity_id: str,
    event_id: str,
    field: str,
    old_value: str,
    new_value: str,
    business_time: datetime,
    party_id: str,
    reason: str,
    now: datetime,
    grants: Iterable[Grant],
    delegations: Iterable[Delegation],
    shared_config: SharedFieldConfig,
    emergency: bool = False,
    review_window: timedelta = DEFAULT_REVIEW_WINDOW,
) -> Correction:
    """开立事件更正单；越权直接拒绝，共同字段进入会签，紧急单先生效后补审。"""
    correction_id = _require_text(correction_id, "更正标识")
    activity_id = _require_text(activity_id, "活动标识")
    event_id = _require_text(event_id, "事件标识")
    field_name = _require_text(field, "字段类别")
    party = _require_text(party_id, "操作参与方")
    note = _require_text(reason, "更正原因")
    moment = _utc(business_time)
    instant = _utc(now)
    result = authorize(
        grants,
        delegations,
        shared_config,
        activity_id=activity_id,
        party_id=party,
        field=field_name,
        business_time=moment,
    )
    if result.decision == Decision.DENIED:
        raise AuthorizationError(result.reason)
    if emergency:
        if review_window <= timedelta(0):
            raise DomainError("补审期限必须大于零")
        status = CorrectionStatus.EMERGENCY_EFFECTIVE
        required: tuple[CountersignRequirement, ...] = ()
        deadline = instant + review_window
    elif result.decision == Decision.REQUIRES_COUNTERSIGN:
        status = CorrectionStatus.PENDING_COUNTERSIGN
        required = result.required_countersigners
        deadline = None
    else:
        status = CorrectionStatus.APPROVED
        required = ()
        deadline = None
    entry = _audit_entry(
        correction_id,
        1,
        1,
        "correction.open",
        party,
        note,
        instant,
        before="",
        after=status.value,
    )
    return Correction(
        correction_id=correction_id,
        activity_id=activity_id,
        event_id=event_id,
        field=field_name,
        old_value=old_value.strip(),
        new_value=new_value.strip(),
        business_time=moment,
        requested_by=party,
        requested_at=instant,
        emergency=emergency,
        status=status,
        required_countersigners=required,
        countersignatures=(),
        review_deadline=deadline,
        reviewed_by=None,
        reviewed_at=None,
        review_outcome=None,
        version=1,
        audit=(entry,),
    )


def countersign(
    correction: Correction,
    *,
    party_id: str,
    approve: bool,
    reason: str,
    now: datetime,
) -> Correction:
    """会签：全部所需责任方同意才通过，任何一方拒绝即驳回。

    会签要求在开单时按照当时责任链固化，之后的责任转移不影响本单。
    """
    party = _require_text(party_id, "会签参与方")
    note = _require_text(reason, "会签意见")
    instant = _utc(now)
    if correction.status != CorrectionStatus.PENDING_COUNTERSIGN:
        raise ConflictError("当前更正不处于待会签状态")
    requirement = next(
        (item for item in correction.required_countersigners if item.party_id == party),
        None,
    )
    if requirement is None:
        raise AuthorizationError("该参与方不在会签要求中")
    if any(item.party_id == party for item in correction.countersignatures):
        raise ConflictError("该参与方已完成会签，请勿重复提交")
    signature = Countersignature(party, requirement.role, approve, instant, note)
    signatures = correction.countersignatures + (signature,)
    if not approve:
        status = CorrectionStatus.REJECTED
    else:
        signed = {item.party_id for item in signatures if item.approve}
        needed = {item.party_id for item in correction.required_countersigners}
        status = (
            CorrectionStatus.APPROVED
            if needed <= signed
            else CorrectionStatus.PENDING_COUNTERSIGN
        )
    next_version = correction.version + 1
    entry = _audit_entry(
        correction.correction_id,
        len(correction.audit) + 1,
        next_version,
        "correction.countersign",
        party,
        note,
        instant,
        before=correction.status.value,
        after=status.value,
    )
    return replace(
        correction,
        status=status,
        countersignatures=signatures,
        version=next_version,
        audit=correction.audit + (entry,),
    )


def review(
    correction: Correction,
    *,
    party_id: str,
    outcome: str,
    reason: str,
    now: datetime,
    grants: Iterable[Grant],
) -> Correction:
    """紧急更正的限期补审：确认则转正式，撤销则回滚生效状态。"""
    party = _require_text(party_id, "补审参与方")
    note = _require_text(reason, "补审意见")
    instant = _utc(now)
    if correction.status != CorrectionStatus.EMERGENCY_EFFECTIVE:
        raise ConflictError("当前更正不处于待补审状态")
    if correction.review_deadline is not None and instant > correction.review_deadline:
        raise DomainError("补审已超出期限")
    if party == correction.requested_by:
        raise AuthorizationError("紧急操作不得由本人补审")
    moment = correction.business_time
    eligible = any(
        grant.activity_id == correction.activity_id
        and grant.party_id == party
        and grant.covers(moment)
        for grant in grants
    )
    if not eligible:
        raise AuthorizationError("补审人不在当时责任链中")
    normalized = outcome.strip().lower()
    if normalized not in {"confirm", "revert"}:
        raise DomainError("补审结论必须为 confirm 或 revert")
    status = (
        CorrectionStatus.CONFIRMED
        if normalized == "confirm"
        else CorrectionStatus.REVERTED
    )
    next_version = correction.version + 1
    entry = _audit_entry(
        correction.correction_id,
        len(correction.audit) + 1,
        next_version,
        "correction.review",
        party,
        note,
        instant,
        before=correction.status.value,
        after=status.value,
    )
    return replace(
        correction,
        status=status,
        reviewed_by=party,
        reviewed_at=instant,
        review_outcome=normalized,
        version=next_version,
        audit=correction.audit + (entry,),
    )


def verify_audit(record: Grant | Delegation | SharedFieldConfig | Correction) -> bool:
    expected = 1
    seen: set[str] = set()
    for entry in record.audit:
        if entry.sequence != expected or entry.fingerprint in seen:
            return False
        seen.add(entry.fingerprint)
        expected += 1
    return True
