"""责任链纯领域逻辑测试：窗口、循环授权、委托传导、补审期限。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.compliance import responsibility as r


T0 = datetime(2026, 9, 1, 0, 0, tzinfo=UTC)
T1 = T0 + timedelta(days=1)
T2 = T0 + timedelta(days=2)


def grant(role, actor, valid_from=T0, valid_until=None):
    return r.RoleGrant(role=role, actor_id=actor, valid_from=valid_from, valid_until=valid_until)


def edge(a, b, valid_from=T0, valid_until=None):
    return r.DelegationEdge(
        delegator_actor_id=a,
        delegatee_actor_id=b,
        valid_from=valid_from,
        valid_until=valid_until,
    )


def test_window_is_half_open():
    assert r.in_window(T0, T1, T0)          # 含起点
    assert r.in_window(T0, T1, T1 - timedelta(seconds=1))
    assert not r.in_window(T0, T1, T1)      # 不含终点
    assert not r.in_window(T0, None, T0 - timedelta(seconds=1))
    assert r.in_window(T0, None, T2)        # 开放区间


def test_naive_datetime_rejected():
    with pytest.raises(r.DomainError):
        r.normalize(datetime(2026, 9, 1))


def test_self_delegation_is_a_cycle():
    assert r.creates_cycle([], "A", "A", T0)


def test_direct_and_indirect_cycles_detected():
    existing = [edge("A", "B"), edge("B", "C")]
    assert not r.creates_cycle(existing, "A", "C", T0)   # A->C 不构成环
    assert r.creates_cycle(existing, "C", "A", T0)       # C->A 闭环
    assert r.creates_cycle(existing, "B", "A", T0)       # B->A 经新边闭环


def test_expired_edges_do_not_form_cycle():
    # B->C 在 T1 已失效；T1 之后加入 C->A 不构成循环
    existing = [edge("A", "B"), edge("B", "C", T0, T1)]
    assert not r.creates_cycle(existing, "C", "A", T1)
    # 但在委托生效期内仍然成环
    assert r.creates_cycle(existing, "C", "A", T1 - timedelta(seconds=1))


def test_delegation_transitive_roles():
    grants = [grant(r.Role.COLLEGE, "A")]
    edges = [edge("A", "B"), edge("B", "C")]
    assert r.roles_for_actor(grants, edges, "A", T0) == frozenset({r.Role.COLLEGE})
    assert r.roles_for_actor(grants, edges, "B", T0) == frozenset({r.Role.COLLEGE})
    assert r.roles_for_actor(grants, edges, "C", T0) == frozenset({r.Role.COLLEGE})
    assert r.roles_for_actor(grants, edges, "X", T0) == frozenset()


def test_delegation_outside_window_does_not_transfer():
    grants = [grant(r.Role.COLLEGE, "A")]
    edges = [edge("A", "B", T1, T2)]
    assert r.roles_for_actor(grants, edges, "B", T0) == frozenset()
    assert r.roles_for_actor(grants, edges, "B", T1) == frozenset({r.Role.COLLEGE})
    assert r.roles_for_actor(grants, edges, "B", T2) == frozenset()


def test_decide_matches_chain_at_event_time():
    grants = [
        grant(r.Role.COLLEGE, "A", T0, T1),
        grant(r.Role.COLLEGE, "C", T1, None),
    ]
    scopes = [r.FieldScope("score", (r.Role.COLLEGE,), T0)]
    # 旧区间：A 有权，新责任人 C 对旧事件无权
    d_old = r.decide(
        field_name="score", actor_id="A", at=T1 - timedelta(seconds=1),
        field_scopes=scopes, grants=grants, delegations=[],
    )
    assert d_old.allowed and not d_old.countersign_required
    d_new_actor = r.decide(
        field_name="score", actor_id="C", at=T1 - timedelta(seconds=1),
        field_scopes=scopes, grants=grants, delegations=[],
    )
    assert not d_new_actor.allowed and d_new_actor.reason == "unauthorized"
    # 新区间：C 有权，A 不再有权（责任转移不追溯旧授权，也不延续）
    d_after = r.decide(
        field_name="score", actor_id="C", at=T1 + timedelta(hours=1),
        field_scopes=scopes, grants=grants, delegations=[],
    )
    assert d_after.allowed


def test_decide_joint_field_requires_countersign():
    grants = [
        grant(r.Role.COLLEGE, "A"),
        grant(r.Role.ENTERPRISE, "B"),
    ]
    scopes = [r.FieldScope("joint", (r.Role.COLLEGE, r.Role.ENTERPRISE), T0)]
    d = r.decide(
        field_name="joint", actor_id="A", at=T0,
        field_scopes=scopes, grants=grants, delegations=[],
    )
    assert d.allowed
    assert d.countersign_required
    assert d.missing_roles == (r.Role.ENTERPRISE,)


def test_decide_chain_gap_and_unconfigured_field():
    grants = [grant(r.Role.COLLEGE, "A", T0, T1)]
    scopes = [r.FieldScope("score", (r.Role.COLLEGE, r.Role.ENTERPRISE), T0)]
    gap = r.decide(
        field_name="score", actor_id="A", at=T2,
        field_scopes=scopes, grants=grants, delegations=[],
    )
    assert not gap.allowed and gap.reason == "chain_gap"
    missing = r.decide(
        field_name="unknown", actor_id="A", at=T0,
        field_scopes=scopes, grants=grants, delegations=[],
    )
    assert not missing.allowed and missing.reason == "field_not_governed"


def test_review_window():
    deadline = r.review_deadline(T0, 3600)
    assert r.within_review_window(T0 + timedelta(seconds=3600), deadline)
    assert not r.within_review_window(T0 + timedelta(seconds=3601), deadline)
    with pytest.raises(r.DomainError):
        r.review_deadline(T0, 0)


def test_fingerprint_chaining_changes_with_previous():
    f1 = r.audit_fingerprint(
        sequence=1, activity_id="act", entity_type="t", entity_id="1",
        action="a", actor_id="A", occurred_at=T0, detail={}, previous_fingerprint="",
    )
    f2 = r.audit_fingerprint(
        sequence=2, activity_id="act", entity_type="t", entity_id="2",
        action="b", actor_id="B", occurred_at=T0, detail={}, previous_fingerprint=f1,
    )
    f2_alt = r.audit_fingerprint(
        sequence=2, activity_id="act", entity_type="t", entity_id="2",
        action="b", actor_id="B", occurred_at=T0, detail={}, previous_fingerprint="",
    )
    assert f2 != f2_alt and len(f1) == 64
