"""责任链领域逻辑测试：授权区间、当时责任链、循环授权、转移、会签与补审。"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.compliance import responsibility_chain as rc

CST = timezone(timedelta(hours=8))


def dt(day: int, hour: int = 0, minute: int = 0) -> datetime:
    return datetime(2024, 3, day, hour, minute, tzinfo=CST)


def _grant(
    grant_id: str = "G-1",
    party_id: str = "party-college",
    role: rc.Role = rc.Role.COLLEGE,
    fields=("hours",),
    start: datetime | None = None,
    end: datetime | None = None,
) -> rc.Grant:
    return rc.create_grant(
        grant_id=grant_id,
        activity_id="ACT-1",
        role=role,
        party_id=party_id,
        fields=list(fields),
        effective_from=start or dt(1),
        effective_to=end,
        actor_id="ops",
        reason="初始配置",
        now=dt(1),
    )


def _delegation(
    delegation_id: str,
    from_party: str,
    to_party: str,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    grants=(),
    existing=(),
) -> rc.Delegation:
    return rc.delegate(
        delegation_id=delegation_id,
        activity_id="ACT-1",
        from_party_id=from_party,
        to_party_id=to_party,
        fields=["hours"],
        effective_from=start or dt(10),
        effective_to=end,
        actor_id="ops",
        reason="值班委托",
        now=dt(9),
        grants=grants,
        existing=existing,
    )


def test_grant_interval_is_half_open():
    grant = _grant(start=dt(10, 8), end=dt(12, 0))
    assert not grant.covers(dt(10, 7, 59))
    assert grant.covers(dt(10, 8))
    assert grant.covers(dt(11, 23, 59))
    assert not grant.covers(dt(12, 0))  # 结束时刻不含在内
    closed = replace(grant, status=rc.GrantStatus.CLOSED)
    assert closed.covers(dt(11))  # 关闭后历史区间仍然有效
    revoked = replace(grant, status=rc.GrantStatus.REVOKED)
    assert not revoked.covers(dt(11))


def test_create_grant_requires_timezone_and_valid_interval():
    with pytest.raises(rc.DomainError):
        _grant(start=datetime(2024, 3, 1))  # 无时区
    with pytest.raises(rc.DomainError):
        _grant(start=dt(10), end=dt(9))  # 结束早于开始
    with pytest.raises(rc.DomainError):
        _grant(fields=())  # 授权范围为空


def test_create_grant_rejects_second_active_for_same_role():
    first = _grant(grant_id="G-1")
    with pytest.raises(rc.ConflictError):
        rc.create_grant(
            grant_id="G-2",
            activity_id="ACT-1",
            role=rc.Role.COLLEGE,
            party_id="party-other",
            fields=["hours"],
            effective_from=dt(2),
            effective_to=None,
            actor_id="ops",
            reason="重复配置",
            now=dt(2),
            existing=[first],
        )


def test_authorize_denied_without_matching_chain():
    grant = _grant(fields=("hours",), start=dt(1), end=dt(20))
    config = rc.empty_shared_config("ACT-1")
    # 字段不在授权范围
    result = rc.authorize(
        [grant], [], config,
        activity_id="ACT-1", party_id="party-college",
        field="grade", business_time=dt(10),
    )
    assert result.decision == rc.Decision.DENIED
    # 业务时间落在有效区间之外
    result = rc.authorize(
        [grant], [], config,
        activity_id="ACT-1", party_id="party-college",
        field="hours", business_time=dt(21),
    )
    assert result.decision == rc.Decision.DENIED
    # 参与方不在责任链上
    result = rc.authorize(
        [grant], [], config,
        activity_id="ACT-1", party_id="party-stranger",
        field="hours", business_time=dt(10),
    )
    assert result.decision == rc.Decision.DENIED


def test_authorize_allows_delegate_then_denies_after_expiry():
    grant = _grant(party_id="party-college")
    delegation = _delegation(
        "D-1", "party-college", "party-intern",
        start=dt(10), end=dt(12), grants=[grant],
    )
    config = rc.empty_shared_config("ACT-1")
    result = rc.authorize(
        [grant], [delegation], config,
        activity_id="ACT-1", party_id="party-intern",
        field="hours", business_time=dt(11),
    )
    assert result.decision == rc.Decision.ALLOWED
    assert result.authority is not None
    assert result.authority.via_delegation_id == "D-1"
    # 委托过期后受托方立即失去授权
    result = rc.authorize(
        [grant], [delegation], config,
        activity_id="ACT-1", party_id="party-intern",
        field="hours", business_time=dt(12),
    )
    assert result.decision == rc.Decision.DENIED


def test_circular_delegation_rejected():
    grants = [
        _grant("G-A", "party-a", rc.Role.COLLEGE),
        _grant("G-B", "party-b", rc.Role.ENTERPRISE),
        _grant("G-C", "party-c", rc.Role.THIRD_PARTY),
    ]
    d1 = _delegation("D-1", "party-a", "party-b", grants=grants)
    d2 = _delegation("D-2", "party-b", "party-c", grants=grants, existing=[d1])
    # party-c -> party-a 会闭合成环
    with pytest.raises(rc.CircularDelegationError):
        _delegation("D-3", "party-c", "party-a", grants=grants, existing=[d1, d2])
    # 自我委托同样是环
    with pytest.raises(rc.CircularDelegationError):
        _delegation("D-4", "party-a", "party-a", grants=grants)
    # 区间错开后不再同时生效，允许反向委托
    later = _delegation(
        "D-5",
        "party-c",
        "party-a",
        start=dt(20),
        grants=grants,
        existing=[
            replace(d1, effective_to=dt(15)),
            replace(d2, effective_to=dt(15)),
        ],
    )
    assert later.status == rc.DelegationStatus.ACTIVE


def test_delegation_requires_delegator_authority():
    with pytest.raises(rc.AuthorizationError):
        _delegation("D-1", "party-nobody", "party-b", grants=[])


def test_transfer_is_not_retroactive_and_splits_chain_at_midnight():
    grant = _grant("G-1", "party-old", fields=("hours",), start=dt(1))
    closed, opened = rc.plan_transfer(
        grant,
        to_party_id="party-new",
        new_grant_id="G-2",
        effective_at=dt(16),  # 3 月 16 日 00:00 (+08:00) 跨日生效
        actor_id="ops",
        reason="轮值转移",
        now=dt(15, 12),
    )
    assert closed.status == rc.GrantStatus.CLOSED
    assert closed.effective_to == dt(16)
    assert closed.version == grant.version + 1
    assert opened.effective_from == dt(16)
    assert opened.fields == grant.fields
    chain = [closed, opened]
    config = rc.empty_shared_config("ACT-1")
    # 转移前的事件仍归旧责任方（不追溯）
    before = rc.authorize(
        chain, [], config,
        activity_id="ACT-1", party_id="party-old",
        field="hours", business_time=dt(15, 23, 30),
    )
    assert before.decision == rc.Decision.ALLOWED
    denied = rc.authorize(
        chain, [], config,
        activity_id="ACT-1", party_id="party-new",
        field="hours", business_time=dt(15, 23, 30),
    )
    assert denied.decision == rc.Decision.DENIED
    # 跨日边界起新责任方接管
    after = rc.authorize(
        chain, [], config,
        activity_id="ACT-1", party_id="party-new",
        field="hours", business_time=dt(16),
    )
    assert after.decision == rc.Decision.ALLOWED
    old_denied = rc.authorize(
        chain, [], config,
        activity_id="ACT-1", party_id="party-old",
        field="hours", business_time=dt(16),
    )
    assert old_denied.decision == rc.Decision.DENIED


def test_transfer_rejects_backdating_and_same_party():
    grant = _grant("G-1", "party-old", start=dt(10))
    with pytest.raises(rc.DomainError):
        rc.plan_transfer(
            grant,
            to_party_id="party-new",
            new_grant_id="G-2",
            effective_at=dt(9),  # 早于当前授权起点
            actor_id="ops",
            reason="追溯改写",
            now=dt(10),
        )
    with pytest.raises(rc.DomainError):
        rc.plan_transfer(
            grant,
            to_party_id="party-old",
            new_grant_id="G-3",
            effective_at=dt(11),
            actor_id="ops",
            reason="原地转移",
            now=dt(10),
        )
    closed, _ = rc.plan_transfer(
        grant,
        to_party_id="party-new",
        new_grant_id="G-2",
        effective_at=dt(11),
        actor_id="ops",
        reason="轮值转移",
        now=dt(10),
    )
    with pytest.raises(rc.ConflictError):
        rc.plan_transfer(
            closed,  # 已关闭的授权不能再转移
            to_party_id="party-x",
            new_grant_id="G-4",
            effective_at=dt(12),
            actor_id="ops",
            reason="重复转移",
            now=dt(11),
        )


def _shared_setup():
    grants = [
        _grant("G-C", "party-college", rc.Role.COLLEGE, ("hours",)),
        _grant("G-E", "party-enterprise", rc.Role.ENTERPRISE, ("hours",)),
    ]
    config = rc.configure_shared_fields(
        rc.empty_shared_config("ACT-1"),
        changes={"hours": ["college", "enterprise"]},
        actor_id="ops",
        reason="共同字段配置",
        now=dt(1),
    )
    return grants, config


def test_shared_field_correction_requires_countersign():
    grants, config = _shared_setup()
    correction = rc.open_correction(
        correction_id="C-1",
        activity_id="ACT-1",
        event_id="E-1",
        field="hours",
        old_value="4",
        new_value="6",
        business_time=dt(10),
        party_id="party-college",
        reason="补录漏记学时",
        now=dt(11),
        grants=grants,
        delegations=[],
        shared_config=config,
    )
    assert correction.status == rc.CorrectionStatus.PENDING_COUNTERSIGN
    assert [r.party_id for r in correction.required_countersigners] == [
        "party-enterprise"
    ]
    # 无关参与方不能会签
    with pytest.raises(rc.AuthorizationError):
        rc.countersign(
            correction, party_id="party-stranger",
            approve=True, reason="同意", now=dt(11),
        )
    # 开单方不在会签要求中
    with pytest.raises(rc.AuthorizationError):
        rc.countersign(
            correction, party_id="party-college",
            approve=True, reason="自签", now=dt(11),
        )
    signed = rc.countersign(
        correction, party_id="party-enterprise",
        approve=True, reason="确认无误", now=dt(11, 9),
    )
    assert signed.status == rc.CorrectionStatus.APPROVED
    # 重复会签被拒绝
    with pytest.raises(rc.ConflictError):
        rc.countersign(
            signed, party_id="party-enterprise",
            approve=True, reason="再次会签", now=dt(11, 10),
        )


def test_shared_field_countersign_rejection():
    grants, config = _shared_setup()
    correction = rc.open_correction(
        correction_id="C-2",
        activity_id="ACT-1",
        event_id="E-2",
        field="hours",
        old_value="4",
        new_value="6",
        business_time=dt(10),
        party_id="party-college",
        reason="补录漏记学时",
        now=dt(11),
        grants=grants,
        delegations=[],
        shared_config=config,
    )
    rejected = rc.countersign(
        correction, party_id="party-enterprise",
        approve=False, reason="缺少证明材料", now=dt(11, 9),
    )
    assert rejected.status == rc.CorrectionStatus.REJECTED


def test_emergency_correction_requires_timely_review():
    grants, config = _shared_setup()
    correction = rc.open_correction(
        correction_id="C-EM",
        activity_id="ACT-1",
        event_id="E-3",
        field="hours",
        old_value="0",
        new_value="2",
        business_time=dt(10),
        party_id="party-college",
        reason="系统故障紧急补录",
        now=dt(10, 8),
        grants=grants,
        delegations=[],
        shared_config=config,
        emergency=True,
        review_window=timedelta(hours=24),
    )
    # 紧急单跳过会签先生效，但必须在期限内补审
    assert correction.status == rc.CorrectionStatus.EMERGENCY_EFFECTIVE
    assert correction.review_deadline == dt(10, 8) + timedelta(hours=24)
    assert not correction.review_overdue(dt(10, 20))
    assert correction.review_overdue(dt(12))
    # 本人不得补审
    with pytest.raises(rc.AuthorizationError):
        rc.review(
            correction, party_id="party-college",
            outcome="confirm", reason="自查", now=dt(10, 9), grants=grants,
        )
    # 责任链之外的人不得补审
    with pytest.raises(rc.AuthorizationError):
        rc.review(
            correction, party_id="party-stranger",
            outcome="confirm", reason="越权", now=dt(10, 9), grants=grants,
        )
    confirmed = rc.review(
        correction, party_id="party-enterprise",
        outcome="confirm", reason="事后核实", now=dt(10, 20), grants=grants,
    )
    assert confirmed.status == rc.CorrectionStatus.CONFIRMED
    assert confirmed.reviewed_by == "party-enterprise"
    # 超期后不允许再补审
    with pytest.raises(rc.DomainError):
        rc.review(
            correction, party_id="party-enterprise",
            outcome="revert", reason="超时补审", now=dt(12), grants=grants,
        )


def test_verify_audit_detects_tampering():
    grant = _grant("G-1")
    closed, _ = rc.plan_transfer(
        grant,
        to_party_id="party-new",
        new_grant_id="G-2",
        effective_at=dt(16),
        actor_id="ops",
        reason="轮值转移",
        now=dt(15),
    )
    assert rc.verify_audit(closed)
    tampered = replace(closed, audit=closed.audit[1:])  # 抽掉首条审计记录
    assert not rc.verify_audit(tampered)
    duplicated = replace(closed, audit=closed.audit + closed.audit[:1])
    assert not rc.verify_audit(duplicated)
