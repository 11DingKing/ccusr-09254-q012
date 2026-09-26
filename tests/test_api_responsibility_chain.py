"""责任链 API 测试：责任配置、授权判定、会签、审计查询，以及

- 循环授权：同一时刻生效的委托成环必须拒绝；
- 并发转移：同一授权的并发转移只有一方成功；
- 跨日生效：责任转移在跨日边界切换，旧授权不追溯改写；
- 越权拒绝：无授权、字段越界、区间外更正一律拒绝。
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from app import responsibility_services as services
from app.compliance import responsibility_chain as rc
from tests.conftest import TestSessionLocal

CST = timezone(timedelta(hours=8))


def iso(day: int, hour: int = 0, minute: int = 0) -> str:
    return datetime(2024, 3, day, hour, minute, tzinfo=CST).isoformat()


def _grant_body(
    grant_id: str,
    role: str,
    party_id: str,
    fields: list[str],
    effective_from: str,
    effective_to: str | None = None,
) -> dict:
    return {
        "grant_id": grant_id,
        "role": role,
        "party_id": party_id,
        "fields": fields,
        "effective_from": effective_from,
        "effective_to": effective_to,
        "actor_id": "ops",
        "reason": "责任配置",
    }


def _create_grant(client, activity: str, **kwargs) -> dict:
    resp = client.post(f"/api/activities/{activity}/grants", json=kwargs)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _authorize(client, activity: str, party_id: str, field: str, business_time: str) -> dict:
    resp = client.post(
        f"/api/activities/{activity}/authorize",
        json={
            "party_id": party_id,
            "field": field,
            "business_time": business_time,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# 责任配置与当时责任链查询
# ---------------------------------------------------------------------------


def test_grant_config_and_chain_query(client):
    _create_grant(
        client,
        "ACT-CFG",
        **_grant_body("G-C", "college", "party-college", ["hours", "attendance"], iso(1)),
    )
    _create_grant(
        client,
        "ACT-CFG",
        **_grant_body("G-E", "enterprise", "party-enterprise", ["hours"], iso(1), iso(20)),
    )
    chain = client.get(
        "/api/activities/ACT-CFG/chain", params={"at": iso(10, 12)}
    ).json()
    assert [r["role"] for r in chain["roles"]] == ["college", "enterprise"]
    assert chain["roles"][0]["party_id"] == "party-college"
    assert chain["shared_fields"] == {}

    # 企业授权在 3 月 20 日到期，之后责任链上只剩学院
    chain = client.get(
        "/api/activities/ACT-CFG/chain", params={"at": iso(21)}
    ).json()
    assert [r["role"] for r in chain["roles"]] == ["college"]

    grants = client.get("/api/activities/ACT-CFG/grants").json()
    assert len(grants) == 2
    at_filter = client.get(
        "/api/activities/ACT-CFG/grants", params={"at": iso(21)}
    ).json()
    assert [g["grant_id"] for g in at_filter] == ["G-C"]


def test_duplicate_active_grant_conflict(client):
    _create_grant(
        client,
        "ACT-DUP",
        **_grant_body("G-1", "college", "party-a", ["hours"], iso(1)),
    )
    # 同一角色已存在生效中的授权
    resp = client.post(
        "/api/activities/ACT-DUP/grants",
        json=_grant_body("G-2", "college", "party-b", ["hours"], iso(2)),
    )
    assert resp.status_code == 409
    # 授权标识重复
    resp = client.post(
        "/api/activities/ACT-DUP/grants",
        json=_grant_body("G-1", "enterprise", "party-c", ["hours"], iso(2)),
    )
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# 循环授权
# ---------------------------------------------------------------------------


def test_circular_delegation_rejected(client):
    activity = "ACT-CYCLE"
    _create_grant(client, activity, **_grant_body("G-A", "college", "party-a", ["hours"], iso(1)))
    _create_grant(client, activity, **_grant_body("G-B", "enterprise", "party-b", ["hours"], iso(1)))
    _create_grant(client, activity, **_grant_body("G-C", "third_party", "party-c", ["hours"], iso(1)))

    def delegate(delegation_id, from_party, to_party, start, end=None):
        return client.post(
            f"/api/activities/{activity}/delegations",
            json={
                "delegation_id": delegation_id,
                "from_party_id": from_party,
                "to_party_id": to_party,
                "fields": ["hours"],
                "effective_from": start,
                "effective_to": end,
                "actor_id": "ops",
                "reason": "值班委托",
            },
        )

    assert delegate("D-1", "party-a", "party-b", iso(10), iso(15)).status_code == 201
    assert delegate("D-2", "party-b", "party-c", iso(10), iso(15)).status_code == 201
    # party-c -> party-a 与既有委托闭合成环
    resp = delegate("D-3", "party-c", "party-a", iso(10), iso(15))
    assert resp.status_code == 409
    assert "循环" in resp.json()["detail"]
    # 自我委托同样是环
    assert delegate("D-4", "party-a", "party-a", iso(10)).status_code == 409
    # 区间错开后不再同时生效，允许反向委托
    assert delegate("D-5", "party-c", "party-a", iso(16)).status_code == 201


def test_delegation_requires_delegator_authority(client):
    activity = "ACT-DELAUTH"
    _create_grant(client, activity, **_grant_body("G-B", "enterprise", "party-b", ["hours"], iso(1)))
    resp = client.post(
        f"/api/activities/{activity}/delegations",
        json={
            "delegation_id": "D-X",
            "from_party_id": "party-nobody",
            "to_party_id": "party-b",
            "fields": ["hours"],
            "effective_from": iso(10),
            "effective_to": None,
            "actor_id": "ops",
            "reason": "无授权委托",
        },
    )
    assert resp.status_code == 403


def test_delegate_inherits_authority_via_api(client):
    activity = "ACT-DELEGATE"
    _create_grant(client, activity, **_grant_body("G-A", "college", "party-a", ["hours"], iso(1)))
    resp = client.post(
        f"/api/activities/{activity}/delegations",
        json={
            "delegation_id": "D-1",
            "from_party_id": "party-a",
            "to_party_id": "party-intern",
            "fields": ["hours"],
            "effective_from": iso(10),
            "effective_to": iso(12),
            "actor_id": "ops",
            "reason": "值班委托",
        },
    )
    assert resp.status_code == 201
    result = _authorize(client, activity, "party-intern", "hours", iso(11))
    assert result["decision"] == "allowed"
    assert result["via_delegation_id"] == "D-1"
    # 委托到期后受托方越权
    result = _authorize(client, activity, "party-intern", "hours", iso(13))
    assert result["decision"] == "denied"


# ---------------------------------------------------------------------------
# 并发转移
# ---------------------------------------------------------------------------


def _setup_transferable_grant(client, activity: str) -> None:
    _create_grant(
        client,
        activity,
        **_grant_body("G-T-1", "college", "party-old", ["hours"], iso(1)),
    )


def _transfer_body(grant_id: str, new_grant_id: str, to_party: str, expected_version: int) -> dict:
    return {
        "grant_id": grant_id,
        "to_party_id": to_party,
        "to_role": None,
        "new_grant_id": new_grant_id,
        "effective_at": iso(16),
        "expected_version": expected_version,
        "actor_id": "ops",
        "reason": "轮值转移",
    }


def test_transfer_with_stale_version_rejected(client):
    activity = "ACT-STALE"
    _setup_transferable_grant(client, activity)
    resp = client.post(
        f"/api/activities/{activity}/transfers",
        json=_transfer_body("G-T-1", "G-T-2", "party-new", expected_version=99),
    )
    assert resp.status_code == 409

    resp = client.post(
        f"/api/activities/{activity}/transfers",
        json=_transfer_body("G-T-1", "G-T-2", "party-new", expected_version=1),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["closed"]["status"] == "closed"
    assert body["closed"]["effective_to"] is not None
    assert body["opened"]["party_id"] == "party-new"
    assert body["opened"]["version"] == 1

    # 基于旧授权与旧版本号重试 -> 该授权已关闭，视为冲突
    resp = client.post(
        f"/api/activities/{activity}/transfers",
        json=_transfer_body("G-T-1", "G-T-3", "party-other", expected_version=1),
    )
    assert resp.status_code == 409
    # 不存在的授权 -> 404
    resp = client.post(
        f"/api/activities/{activity}/transfers",
        json=_transfer_body("G-NOPE", "G-T-4", "party-other", expected_version=1),
    )
    assert resp.status_code == 404


def test_concurrent_transfer_only_one_wins(db):
    activity = "ACT-CONC"
    services.create_grant(
        db,
        activity_id=activity,
        grant_id="G-C-1",
        role="college",
        party_id="party-old",
        fields=["hours"],
        effective_from=datetime(2024, 3, 1, tzinfo=CST),
        effective_to=None,
        actor_id="ops",
        reason="责任配置",
    )
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def worker(to_party: str, new_grant_id: str) -> None:
        session = TestSessionLocal()
        try:
            barrier.wait(timeout=10)
            services.transfer_responsibility(
                session,
                activity_id=activity,
                grant_id="G-C-1",
                to_party_id=to_party,
                to_role=None,
                new_grant_id=new_grant_id,
                effective_at=datetime(2024, 3, 16, tzinfo=CST),
                expected_version=1,
                actor_id="ops",
                reason="轮值转移",
            )
            outcomes.append("ok")
        except rc.ConflictError:
            # 并发失败表现为版本冲突或授权已被关闭
            outcomes.append("conflict")
        finally:
            session.close()

    threads = [
        threading.Thread(target=worker, args=("party-b", "G-C-2")),
        threading.Thread(target=worker, args=("party-c", "G-C-3")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert sorted(outcomes) == ["conflict", "ok"]
    grants = services.list_grants(db, activity)
    active = [g for g in grants if g["status"] == "active"]
    assert len(active) == 1
    assert active[0]["party_id"] in {"party-b", "party-c"}
    closed = [g for g in grants if g["status"] == "closed"]
    assert closed and closed[0]["grant_id"] == "G-C-1"


# ---------------------------------------------------------------------------
# 跨日生效与不追溯
# ---------------------------------------------------------------------------


def test_transfer_takes_effect_across_midnight(client):
    activity = "ACT-XDAY"
    _create_grant(
        client,
        activity,
        **_grant_body("G-X-1", "college", "party-day1", ["hours"], iso(1)),
    )
    resp = client.post(
        f"/api/activities/{activity}/transfers",
        json={
            "grant_id": "G-X-1",
            "to_party_id": "party-day2",
            "to_role": None,
            "new_grant_id": "G-X-2",
            "effective_at": iso(16),  # 3 月 16 日 00:00 (+08:00)
            "expected_version": 1,
            "actor_id": "ops",
            "reason": "跨日轮值",
        },
    )
    assert resp.status_code == 201, resp.text

    # 跨日前一刻：旧责任方有权，新责任方越权
    assert _authorize(client, activity, "party-day1", "hours", iso(15, 23, 30))["decision"] == "allowed"
    assert _authorize(client, activity, "party-day2", "hours", iso(15, 23, 30))["decision"] == "denied"
    # 跨日边界（含）：新责任方接管，旧责任方越权
    assert _authorize(client, activity, "party-day2", "hours", iso(16))["decision"] == "allowed"
    assert _authorize(client, activity, "party-day1", "hours", iso(16))["decision"] == "denied"

    # 不追溯：转移完成后，旧责任方仍可更正其任期内的历史事件
    resp = client.post(
        f"/api/activities/{activity}/corrections",
        json={
            "correction_id": "C-X-1",
            "event_id": "E-OLD",
            "field": "hours",
            "old_value": "2",
            "new_value": "3",
            "business_time": iso(15, 10),
            "party_id": "party-day1",
            "reason": "更正任期内事件",
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["status"] == "approved"
    # 新责任方更正转移前的事件 -> 越权
    resp = client.post(
        f"/api/activities/{activity}/corrections",
        json={
            "correction_id": "C-X-2",
            "event_id": "E-OLD",
            "field": "hours",
            "old_value": "2",
            "new_value": "5",
            "business_time": iso(15, 10),
            "party_id": "party-day2",
            "reason": "追溯改写",
        },
    )
    assert resp.status_code == 403

    # 旧授权仅被截断，历史区间保持不变（时间以 UTC 归一化存储）
    grants = {g["grant_id"]: g for g in client.get(f"/api/activities/{activity}/grants").json()}
    assert grants["G-X-1"]["status"] == "closed"
    assert datetime.fromisoformat(grants["G-X-1"]["effective_from"]) == datetime(2024, 3, 1, tzinfo=CST)
    assert datetime.fromisoformat(grants["G-X-1"]["effective_to"]) == datetime(2024, 3, 16, tzinfo=CST)


# ---------------------------------------------------------------------------
# 越权拒绝
# ---------------------------------------------------------------------------


def test_unauthorized_correction_rejected(client):
    activity = "ACT-DENY"
    _create_grant(
        client,
        activity,
        **_grant_body("G-D-1", "college", "party-college", ["hours"], iso(1), iso(20)),
    )
    base = {
        "event_id": "E-1",
        "field": "hours",
        "old_value": "1",
        "new_value": "2",
        "business_time": iso(10),
        "reason": "越权尝试",
    }
    # 参与方不在责任链上
    resp = client.post(
        f"/api/activities/{activity}/corrections",
        json={**base, "correction_id": "C-D-1", "party_id": "party-stranger"},
    )
    assert resp.status_code == 403
    # 字段不在授权范围
    resp = client.post(
        f"/api/activities/{activity}/corrections",
        json={
            **base,
            "correction_id": "C-D-2",
            "party_id": "party-college",
            "field": "grade",
        },
    )
    assert resp.status_code == 403
    # 业务时间落在有效区间之外
    resp = client.post(
        f"/api/activities/{activity}/corrections",
        json={
            **base,
            "correction_id": "C-D-3",
            "party_id": "party-college",
            "business_time": iso(21),
        },
    )
    assert resp.status_code == 403
    # 授权判定接口同步给出 denied
    assert _authorize(client, activity, "party-stranger", "hours", iso(10))["decision"] == "denied"


# ---------------------------------------------------------------------------
# 共同字段会签
# ---------------------------------------------------------------------------


def _setup_shared_activity(client, activity: str) -> None:
    _create_grant(client, activity, **_grant_body("G-S-C", "college", "party-college", ["hours"], iso(1)))
    _create_grant(client, activity, **_grant_body("G-S-E", "enterprise", "party-enterprise", ["hours"], iso(1)))
    resp = client.put(
        f"/api/activities/{activity}/shared-fields",
        json={
            "shared_fields": {"hours": ["college", "enterprise"]},
            "actor_id": "ops",
            "reason": "共同字段配置",
        },
    )
    assert resp.status_code == 200, resp.text


def _open_correction(client, activity: str, correction_id: str, party_id: str, **extra) -> dict:
    payload = {
        "correction_id": correction_id,
        "event_id": "E-1",
        "field": "hours",
        "old_value": "4",
        "new_value": "6",
        "business_time": iso(10),
        "party_id": party_id,
        "reason": "补录漏记学时",
    }
    payload.update(extra)
    resp = client.post(f"/api/activities/{activity}/corrections", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_shared_field_countersign_flow(client):
    activity = "ACT-SIGN"
    _setup_shared_activity(client, activity)

    opened = _open_correction(client, activity, "C-S-1", "party-college")
    assert opened["status"] == "pending_countersign"
    assert opened["required_countersigners"] == [
        {"party_id": "party-enterprise", "role": "enterprise"}
    ]

    # 无关参与方会签 -> 越权
    resp = client.post(
        f"/api/activities/{activity}/corrections/C-S-1/countersign",
        json={"party_id": "party-stranger", "approve": True, "reason": "越权会签"},
    )
    assert resp.status_code == 403
    # 开单方不能给自己会签
    resp = client.post(
        f"/api/activities/{activity}/corrections/C-S-1/countersign",
        json={"party_id": "party-college", "approve": True, "reason": "自签"},
    )
    assert resp.status_code == 403
    # 共同责任方会签通过
    resp = client.post(
        f"/api/activities/{activity}/corrections/C-S-1/countersign",
        json={"party_id": "party-enterprise", "approve": True, "reason": "确认无误"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "approved"
    assert resp.json()["countersignatures"][0]["party_id"] == "party-enterprise"

    # 任何一方拒绝即驳回
    opened = _open_correction(client, activity, "C-S-2", "party-college")
    assert opened["status"] == "pending_countersign"
    resp = client.post(
        f"/api/activities/{activity}/corrections/C-S-2/countersign",
        json={"party_id": "party-enterprise", "approve": False, "reason": "缺少证明材料"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"


def test_countersign_uses_chain_at_business_time(client):
    """会签要求在开单时按当时责任链固化，事后的责任转移不影响本单。"""
    activity = "ACT-SNAP"
    _setup_shared_activity(client, activity)
    opened = _open_correction(client, activity, "C-SN-1", "party-college")
    assert opened["status"] == "pending_countersign"

    # 企业角色随后转移给新参与方
    resp = client.post(
        f"/api/activities/{activity}/transfers",
        json={
            "grant_id": "G-S-E",
            "to_party_id": "party-enterprise-2",
            "to_role": None,
            "new_grant_id": "G-S-E2",
            "effective_at": iso(12),
            "expected_version": 1,
            "actor_id": "ops",
            "reason": "企业侧换帅",
        },
    )
    assert resp.status_code == 201

    # 新参与方不在会签要求中，原责任方（事件发生时）仍可会签
    resp = client.post(
        f"/api/activities/{activity}/corrections/C-SN-1/countersign",
        json={"party_id": "party-enterprise-2", "approve": True, "reason": "新官会签"},
    )
    assert resp.status_code == 403
    resp = client.post(
        f"/api/activities/{activity}/corrections/C-SN-1/countersign",
        json={"party_id": "party-enterprise", "approve": True, "reason": "任内确认"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "approved"


# ---------------------------------------------------------------------------
# 紧急操作限期补审
# ---------------------------------------------------------------------------


def test_emergency_correction_reviewed_within_deadline(client):
    activity = "ACT-EM"
    _setup_shared_activity(client, activity)
    opened = _open_correction(
        client,
        activity,
        "C-EM-1",
        "party-college",
        emergency=True,
        review_window_hours=24,
        requested_at=iso(10, 8),
    )
    # 紧急单跳过会签先生效，补审期限 = 提交时间 + 窗口
    assert opened["status"] == "emergency_effective"
    assert opened["review_deadline"] is not None
    assert opened["review_overdue"] is False

    # 本人不得补审（在期限内提交，确保触发的是身份校验）
    resp = client.post(
        f"/api/activities/{activity}/corrections/C-EM-1/review",
        json={
            "party_id": "party-college",
            "outcome": "confirm",
            "reason": "自查",
            "reviewed_at": iso(10, 20),
        },
    )
    assert resp.status_code == 403
    # 共同责任方在期限内补审通过
    resp = client.post(
        f"/api/activities/{activity}/corrections/C-EM-1/review",
        json={
            "party_id": "party-enterprise",
            "outcome": "confirm",
            "reason": "事后核实",
            "reviewed_at": iso(10, 20),
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "confirmed"
    assert resp.json()["review_outcome"] == "confirm"


def test_emergency_correction_overdue_and_late_review_rejected(client):
    activity = "ACT-EM2"
    _setup_shared_activity(client, activity)
    opened = _open_correction(
        client,
        activity,
        "C-EM-2",
        "party-college",
        emergency=True,
        review_window_hours=24,
        requested_at=iso(10, 8),
    )
    assert opened["status"] == "emergency_effective"

    # 以未来时刻查询：该单已逾期未补审
    overdue = client.get(
        f"/api/activities/{activity}/corrections",
        params={"overdue_only": True, "as_of": iso(12, 8)},
    ).json()
    assert [item["correction_id"] for item in overdue] == ["C-EM-2"]
    assert overdue[0]["review_overdue"] is True

    # 超过补审期限后不允许再补审
    resp = client.post(
        f"/api/activities/{activity}/corrections/C-EM-2/review",
        json={
            "party_id": "party-enterprise",
            "outcome": "confirm",
            "reason": "超时补审",
            "reviewed_at": iso(12, 9),
        },
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 审计查询
# ---------------------------------------------------------------------------


def test_audit_trail_query(client):
    activity = "ACT-AUDIT"
    _setup_shared_activity(client, activity)
    _open_correction(client, activity, "C-A-1", "party-college")
    client.post(
        f"/api/activities/{activity}/corrections/C-A-1/countersign",
        json={"party_id": "party-enterprise", "approve": True, "reason": "确认无误"},
    )

    trail = client.get(f"/api/activities/{activity}/audit").json()
    assert trail["activity_id"] == activity
    assert trail["total"] == len(trail["entries"])
    actions = [entry["action"] for entry in trail["entries"]]
    occurred = [entry["occurred_at"] for entry in trail["entries"]]
    assert occurred == sorted(occurred)
    assert {"grant.create", "shared_fields.configure", "correction.open", "correction.countersign"} <= set(actions)
    for entry in trail["entries"]:
        assert len(entry["fingerprint"]) == 64
        assert entry["aggregate_type"] in {"grant", "delegation", "shared_fields", "correction"}

    by_action = client.get(
        f"/api/activities/{activity}/audit", params={"action": "correction.countersign"}
    ).json()
    assert by_action["total"] == 1
    assert by_action["entries"][0]["actor_id"] == "party-enterprise"

    by_actor = client.get(
        f"/api/activities/{activity}/audit", params={"actor_id": "ops"}
    ).json()
    assert by_actor["total"] == 3  # 两条授权 + 共同字段配置

    by_type = client.get(
        f"/api/activities/{activity}/audit", params={"aggregate_type": "correction"}
    ).json()
    assert by_type["total"] == 2
    assert {entry["aggregate_id"] for entry in by_type["entries"]} == {"C-A-1"}


def test_correction_not_found(client):
    resp = client.get("/api/activities/ACT-VOID/corrections/NOPE")
    assert resp.status_code == 404
    resp = client.post(
        "/api/activities/ACT-VOID/corrections/NOPE/countersign",
        json={"party_id": "party-a", "approve": True, "reason": "不存在"},
    )
    assert resp.status_code == 404
