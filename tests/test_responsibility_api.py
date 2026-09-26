"""责任链 API 与应用服务集成测试。

覆盖：责任配置与循环授权拒绝、授权判定、跨日生效、责任转移不追溯、
共有字段会签、紧急操作期限内补审与超期失效、越权拒绝、并发转移、
并发会签与审计链校验。
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import responsibility_service as svc
from tests.conftest import TestSessionLocal


D1 = datetime(2026, 9, 1, 0, 0, tzinfo=UTC)
D2 = D1 + timedelta(days=1)
D3 = D1 + timedelta(days=2)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dt(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC)
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


@pytest.fixture
def configured(client: TestClient) -> str:
    activity = "ACT-1"
    # 学院：A 负责 D1~D2，C 自 D2 起接手
    client.put(
        f"/api/activities/{activity}/roles/college",
        json={"actor_id": "A", "valid_from": _iso(D1)},
    )
    client.put(
        f"/api/activities/{activity}/roles/college",
        json={"actor_id": "C", "valid_from": _iso(D2)},
    )
    # 企业 B 全区间在责
    client.put(
        f"/api/activities/{activity}/roles/enterprise",
        json={"actor_id": "B", "valid_from": _iso(D1)},
    )
    # 成绩：学院独有
    client.put(
        f"/api/activities/{activity}/fields/score/scope",
        json={"roles": ["college"], "valid_from": _iso(D1)},
    )
    # 考勤：D1~D3 学院+企业共有；D3 起调整为学院独有
    client.put(
        f"/api/activities/{activity}/fields/attendance/scope",
        json={"roles": ["college", "enterprise"], "valid_from": _iso(D1)},
    )
    client.put(
        f"/api/activities/{activity}/fields/attendance/scope",
        json={"roles": ["college"], "valid_from": _iso(D3)},
    )
    return activity


# ---- 责任配置 --------------------------------------------------------------


def test_assignment_history_preserved_on_transfer(client: TestClient, configured: str):
    resp = client.get(f"/api/activities/{configured}/chain")
    assert resp.status_code == 200
    college = [
        a for a in resp.json()["assignments"] if a["role"] == "college"
    ]
    assert len(college) == 2
    assert _dt(college[0]["valid_until"]) == D2
    assert college[1]["actor_id"] == "C"


def test_backdated_and_same_instant_transfer_rejected(
    client: TestClient, configured: str
):
    backdated = client.put(
        f"/api/activities/{configured}/roles/college",
        json={"actor_id": "Z", "valid_from": _iso(D1 + timedelta(hours=1))},
    )
    assert backdated.status_code == 400

    same_instant = client.put(
        f"/api/activities/{configured}/roles/college",
        json={"actor_id": "Z", "valid_from": _iso(D2)},
    )
    assert same_instant.status_code == 400


def test_invalid_role_and_window_rejected(client: TestClient, configured: str):
    bad_role = client.put(
        f"/api/activities/{configured}/roles/student_union",
        json={"actor_id": "Z", "valid_from": _iso(D1)},
    )
    assert bad_role.status_code == 400

    bad_scope = client.put(
        f"/api/activities/{configured}/fields/x/scope",
        json={"roles": [], "valid_from": _iso(D1)},
    )
    assert bad_scope.status_code == 422

    bad_window = client.post(
        f"/api/activities/{configured}/delegations",
        json={
            "delegator_actor_id": "B",
            "delegatee_actor_id": "E",
            "valid_from": _iso(D2),
            "valid_until": _iso(D1),
        },
    )
    assert bad_window.status_code == 422


def test_circular_delegation_rejected(client: TestClient, configured: str):
    ok = client.post(
        f"/api/activities/{configured}/delegations",
        json={
            "delegator_actor_id": "A",
            "delegatee_actor_id": "D",
            "valid_from": _iso(D1),
        },
    )
    assert ok.status_code == 201
    cycle = client.post(
        f"/api/activities/{configured}/delegations",
        json={
            "delegator_actor_id": "D",
            "delegatee_actor_id": "A",
            "valid_from": _iso(D1),
        },
    )
    assert cycle.status_code == 400
    assert "循环授权" in cycle.json()["detail"]

    self_loop = client.post(
        f"/api/activities/{configured}/delegations",
        json={
            "delegator_actor_id": "B",
            "delegatee_actor_id": "B",
            "valid_from": _iso(D1),
        },
    )
    assert self_loop.status_code == 400


def test_delegation_grants_authority_within_window(client: TestClient, configured: str):
    resp = client.post(
        f"/api/activities/{configured}/delegations",
        json={
            "delegator_actor_id": "B",
            "delegatee_actor_id": "E",
            "valid_from": _iso(D1),
            "valid_until": _iso(D2),
        },
    )
    assert resp.status_code == 201
    inside = client.get(
        f"/api/activities/{configured}/authorize",
        params={"field_name": "attendance", "actor_id": "E", "at": _iso(D1 + timedelta(hours=12))},
    )
    assert inside.json()["allowed"] is True
    outside = client.get(
        f"/api/activities/{configured}/authorize",
        params={"field_name": "attendance", "actor_id": "E", "at": _iso(D2)},
    )
    # D2 委托已失效，且 attendance 在 D3 前仍是共有字段，E 无任何角色
    assert outside.json()["allowed"] is False


# ---- 授权判定与跨日生效 -----------------------------------------------------


def test_authorize_cross_day_transfer(client: TestClient, configured: str):
    before = client.get(
        f"/api/activities/{configured}/authorize",
        params={"field_name": "score", "actor_id": "A", "at": _iso(D2 - timedelta(seconds=1))},
    ).json()
    after = client.get(
        f"/api/activities/{configured}/authorize",
        params={"field_name": "score", "actor_id": "A", "at": _iso(D2)},
    ).json()
    assert before["allowed"] is True
    assert after["allowed"] is False and after["reason"] == "unauthorized"

    new_owner = client.get(
        f"/api/activities/{configured}/authorize",
        params={"field_name": "score", "actor_id": "C", "at": _iso(D2)},
    ).json()
    assert new_owner["allowed"] is True


def test_authorize_field_scope_cross_day(client: TestClient, configured: str):
    joint = client.get(
        f"/api/activities/{configured}/authorize",
        params={"field_name": "attendance", "actor_id": "B", "at": _iso(D2 + timedelta(hours=6))},
    ).json()
    assert joint["allowed"] is True
    assert joint["countersign_required"] is True

    single = client.get(
        f"/api/activities/{configured}/authorize",
        params={"field_name": "attendance", "actor_id": "C", "at": _iso(D3)},
    ).json()
    assert single["allowed"] is True
    assert single["countersign_required"] is False


def test_authorize_unconfigured_field_denied(client: TestClient, configured: str):
    resp = client.get(
        f"/api/activities/{configured}/authorize",
        params={"field_name": "secret", "actor_id": "A", "at": _iso(D1 + timedelta(hours=6))},
    )
    body = resp.json()
    assert body["allowed"] is False
    assert body["reason"] == "field_not_governed"


def test_authorize_chain_gap_denied(client: TestClient, configured: str):
    # 企业 B 的区间仅到 D2；D2 之后企业角色无人在责，共有字段出现责任链空窗
    db = TestSessionLocal()
    try:
        from app.models import ResponsibilityAssignment
        from sqlalchemy import update as sql_update

        db.execute(
            sql_update(ResponsibilityAssignment)
            .where(
                ResponsibilityAssignment.activity_id == configured,
                ResponsibilityAssignment.role == "enterprise",
                ResponsibilityAssignment.valid_until.is_(None),
            )
            .values(valid_until=D2)
        )
        db.commit()
    finally:
        db.close()

    resp = client.get(
        f"/api/activities/{configured}/authorize",
        params={"field_name": "attendance", "actor_id": "C", "at": _iso(D2 + timedelta(hours=2))},
    )
    body = resp.json()
    assert body["allowed"] is False
    assert body["reason"] == "chain_gap"


def test_list_corrections_filtered_by_status(client: TestClient, configured: str):
    payload = _correction_payload(
        "C",
        D2 + timedelta(hours=6),
        correction_id="CORR-LIST-1",
        field_name="attendance",
        new_value="present",
    )
    client.post(f"/api/activities/{configured}/corrections", json=payload)

    pending = client.get(
        f"/api/activities/{configured}/corrections",
        params={"status": "pending_countersign"},
    ).json()
    assert [c["correction_id"] for c in pending] == ["CORR-LIST-1"]

    effective = client.get(
        f"/api/activities/{configured}/corrections",
        params={"status": "effective"},
    ).json()
    assert effective == []


# ---- 更正：事件时刻责任链 ---------------------------------------------------


def _correction_payload(actor: str, at: datetime, **overrides):
    payload = {
        "correction_id": f"CORR-{actor}-{at.isoformat()}",
        "actor_id": actor,
        "field_name": "score",
        "event_ref": f"EVT-{at.isoformat()}",
        "event_occurred_at": _iso(at),
        "old_value": "60",
        "new_value": "80",
        "reason": "企业回传成绩与签到记录不符",
    }
    payload.update(overrides)
    return payload


def test_transfer_does_not_retroactively_change_old_authorization(
    client: TestClient, configured: str
):
    # 事件发生在 D1 中午（A 在责），提交在转移之后
    old_event = D1 + timedelta(hours=12)
    ok = client.post(
        f"/api/activities/{configured}/corrections",
        json=_correction_payload("A", old_event),
    )
    assert ok.status_code == 201
    assert ok.json()["status"] == "effective"

    # 新责任人 C 对 D1 的旧事件无更正权（责任转移不追溯）
    denied = client.post(
        f"/api/activities/{configured}/corrections",
        json=_correction_payload("C", old_event, correction_id="CORR-C-OLD"),
    )
    assert denied.status_code == 403
    assert "事件时刻" in denied.json()["detail"]


def test_unauthorized_actor_rejected(client: TestClient, configured: str):
    resp = client.post(
        f"/api/activities/{configured}/corrections",
        json=_correction_payload("X", D1 + timedelta(hours=6)),
    )
    assert resp.status_code == 403


def test_joint_field_countersign_flow(client: TestClient, configured: str):
    event_at = D2 + timedelta(hours=6)
    payload = _correction_payload(
        "C",
        event_at,
        correction_id="CORR-JOINT-1",
        field_name="attendance",
        new_value="present",
    )
    resp = client.post(f"/api/activities/{configured}/corrections", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "pending_countersign"
    assert body["missing_roles"] == ["enterprise"]
    assert body["signed_roles"] == ["college"]

    # 越权：学院人不能替企业会签
    forge = client.post(
        f"/api/activities/{configured}/corrections/CORR-JOINT-1/countersign",
        json={"actor_id": "A"},
    )
    assert forge.status_code == 403

    signed = client.post(
        f"/api/activities/{configured}/corrections/CORR-JOINT-1/countersign",
        json={"actor_id": "B", "note": "企业确认考勤原始记录一致"},
    )
    assert signed.status_code == 200
    final = signed.json()
    assert final["status"] == "effective"
    assert final["missing_roles"] == []

    # 已生效单据重复会签 → 状态冲突
    again = client.post(
        f"/api/activities/{configured}/corrections/CORR-JOINT-1/countersign",
        json={"actor_id": "B"},
    )
    assert again.status_code == 409


def test_emergency_correction_must_be_reviewed_within_deadline(
    client: TestClient, configured: str
):
    event_at = D2 + timedelta(hours=6)
    submit_at = D2 + timedelta(hours=7)

    db = TestSessionLocal()
    try:
        created = svc.submit_correction(
            db,
            activity_id=configured,
            correction_id="CORR-EMG-1",
            field_name="attendance",
            event_ref="EVT-EMG-1",
            event_occurred_at=event_at,
            old_value="absent",
            new_value="present",
            reason="考勤机故障，现场紧急更正",
            actor_id="C",
            is_emergency=True,
            review_seconds=3600,
            now=submit_at,
        )
    finally:
        db.close()
    assert created["status"] == "emergency_pending"
    assert created["is_emergency"] is True
    deadline = _dt(created["review_deadline"])
    assert deadline == submit_at + timedelta(seconds=3600)

    # 期限内补审 → 生效
    within = client.post(
        f"/api/activities/{configured}/corrections/CORR-EMG-1/countersign",
        json={"actor_id": "B", "at": _iso(deadline - timedelta(seconds=1))},
    )
    assert within.status_code == 200
    assert within.json()["status"] == "effective"

    # 第二张紧急单：超过补审期限未补签 → 补审被拒并自动失效
    db = TestSessionLocal()
    try:
        svc.submit_correction(
            db,
            activity_id=configured,
            correction_id="CORR-EMG-2",
            field_name="attendance",
            event_ref="EVT-EMG-2",
            event_occurred_at=event_at,
            old_value="present",
            new_value="absent",
            reason="第二次紧急更正",
            actor_id="C",
            is_emergency=True,
            review_seconds=3600,
            now=submit_at,
        )
    finally:
        db.close()
    late = client.post(
        f"/api/activities/{configured}/corrections/CORR-EMG-2/countersign",
        json={"actor_id": "B", "at": _iso(deadline + timedelta(seconds=1))},
    )
    assert late.status_code == 409

    expired = client.get(
        f"/api/activities/{configured}/corrections/CORR-EMG-2"
    ).json()
    assert expired["status"] == "expired"


def test_expire_overdue_batch_and_recheck(client: TestClient, configured: str):
    event_at = D2 + timedelta(hours=6)
    submit_at = D2 + timedelta(hours=7)
    db = TestSessionLocal()
    try:
        svc.submit_correction(
            db,
            activity_id=configured,
            correction_id="CORR-EMG-3",
            field_name="attendance",
            event_ref="EVT-EMG-3",
            event_occurred_at=event_at,
            old_value="x",
            new_value="late",
            reason="批量过期校验",
            actor_id="C",
            is_emergency=True,
            review_seconds=60,
            now=submit_at,
        )
        # 尚未到期限：不清扫
        none = svc.expire_overdue_corrections(
            db, activity_id=configured, now=submit_at + timedelta(seconds=60)
        )
        assert none == []
        # 超过期限：懒失效
        expired = svc.expire_overdue_corrections(
            db, activity_id=configured, now=submit_at + timedelta(seconds=61)
        )
        assert expired == ["CORR-EMG-3"]
        # 幂等：再次清扫不再返回
        again = svc.expire_overdue_corrections(
            db, activity_id=configured, now=submit_at + timedelta(seconds=120)
        )
        assert again == []
    finally:
        db.close()


# ---- 并发 ------------------------------------------------------------------


def _call_transfer_in_thread(activity: str, actor: str, moment: datetime, box: dict):
    db = TestSessionLocal()
    try:
        svc.configure_assignment(
            db,
            activity_id=activity,
            role="enterprise",
            actor_id=actor,
            valid_from=moment,
        )
        box["ok"] = True
    except Exception as exc:  # noqa: BLE001
        box["ok"] = False
        box["error"] = type(exc).__name__
    finally:
        db.close()


def test_concurrent_transfer_only_one_wins(client: TestClient, configured: str):
    barrier = threading.Barrier(2)
    results: list[dict] = []

    def worker(actor: str):
        box: dict = {}
        barrier.wait()
        _call_transfer_in_thread(configured, actor, D2 + timedelta(hours=2), box)
        results.append(box)

    threads = [threading.Thread(target=worker, args=(a,)) for a in ("F", "G")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(r["ok"] for r in results) == [False, True]
    chain = client.get(f"/api/activities/{configured}/chain").json()
    enterprise = [a for a in chain["assignments"] if a["role"] == "enterprise"]
    # B 段 + 一个胜出的新段（失败者不留下半截区间）
    assert [a["actor_id"] for a in enterprise][-1] in {"F", "G"}
    assert len(enterprise) == 2


def test_concurrent_countersigns_both_apply(client: TestClient, configured: str):
    # 第三方角色在 D2 才加入，构造三方共有字段
    client.put(
        f"/api/activities/{configured}/roles/third_party",
        json={"actor_id": "T", "valid_from": _iso(D2)},
    )
    client.put(
        f"/api/activities/{configured}/fields/summary/scope",
        json={"roles": ["college", "enterprise", "third_party"], "valid_from": _iso(D2)},
    )
    event_at = D2 + timedelta(hours=3)
    payload = _correction_payload(
        "C",
        event_at,
        correction_id="CORR-JOINT-3",
        field_name="summary",
        new_value="ok",
    )
    created = client.post(
        f"/api/activities/{configured}/corrections", json=payload
    ).json()
    assert created["status"] == "pending_countersign"

    barrier = threading.Barrier(2)
    boxes: list[dict] = []

    def worker(actor: str):
        barrier.wait()
        db = TestSessionLocal()
        try:
            svc.countersign(db, correction_id="CORR-JOINT-3", actor_id=actor)
            boxes.append({"actor": actor, "ok": True})
        except Exception as exc:  # noqa: BLE001
            boxes.append({"actor": actor, "ok": False, "error": str(exc)})
        finally:
            db.close()

    threads = [threading.Thread(target=worker, args=(a,)) for a in ("B", "T")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(b["ok"] for b in boxes), boxes
    final = client.get(
        f"/api/activities/{configured}/corrections/CORR-JOINT-3"
    ).json()
    assert final["status"] == "effective"
    assert len(final["signatures"]) == 3


# ---- 审计 ------------------------------------------------------------------


def test_audit_chain_query_and_tamper_detection(
    client: TestClient, configured: str, db
):
    resp = client.get(f"/api/activities/{configured}/audit")
    assert resp.status_code == 200
    body = resp.json()
    assert body["chain_valid"] is True
    actions = [e["action"] for e in body["entries"]]
    assert "responsibility_assign" in actions
    assert "responsibility_transfer" in actions
    assert "field_scope_configure" in actions

    # 按实体过滤
    only_corr = client.get(
        f"/api/activities/{configured}/audit",
        params={"entity_type": "correction"},
    )
    assert all(e["entity_type"] == "correction" for e in only_corr.json()["entries"])

    # 篡改一条审计：链式指纹必须失效
    first_seq = body["entries"][0]["sequence"]
    db.execute(
        text("UPDATE responsibility_audit SET actor_id = 'HACKER' WHERE sequence = :s"),
        {"s": first_seq},
    )
    db.commit()
    tampered = client.get(f"/api/activities/{configured}/audit").json()
    assert tampered["chain_valid"] is False
    assert tampered["broken_at"] is not None


def test_correction_audit_trail_complete(client: TestClient, configured: str):
    payload = _correction_payload(
        "C",
        D2 + timedelta(hours=6),
        correction_id="CORR-AUDIT-1",
        field_name="attendance",
        new_value="present",
    )
    client.post(f"/api/activities/{configured}/corrections", json=payload)
    client.post(
        f"/api/activities/{configured}/corrections/CORR-AUDIT-1/countersign",
        json={"actor_id": "B"},
    )
    entries = client.get(
        f"/api/activities/{configured}/audit",
        params={"entity_type": "correction", "entity_id": "CORR-AUDIT-1"},
    ).json()["entries"]
    assert [e["action"] for e in entries] == [
        "correction_submit",
        "correction_countersign",
        "correction_effective",
    ]
