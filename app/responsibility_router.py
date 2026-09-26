"""联合实训活动主办方责任链 API。

提供责任配置、授权判定、会签和审计查询能力；更正事件时始终匹配
事件业务时间对应的当时责任链。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from . import responsibility_services as services
from .compliance import responsibility_chain as rc
from .db import get_db
from .schemas import (
    AuditTrailOut,
    AuthorizeIn,
    AuthorizeOut,
    ChainOut,
    CorrectionIn,
    CorrectionOut,
    CountersignIn,
    DelegationIn,
    DelegationOut,
    GrantIn,
    GrantOut,
    ReviewIn,
    SharedFieldsIn,
    SharedFieldsOut,
    TransferIn,
    TransferOut,
)

router = APIRouter(prefix="/api/activities/{activity_id}", tags=["responsibility"])


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, (services.GrantNotFoundError, services.CorrectionNotFoundError)):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, rc.AuthorizationError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, (rc.ConflictError, services.RecordConflictError)):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, rc.DomainError):
        return HTTPException(status_code=422, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


@router.post("/grants", response_model=GrantOut, status_code=status.HTTP_201_CREATED)
def create_grant(
    activity_id: str, body: GrantIn, db: Session = Depends(get_db)
) -> Any:
    """责任配置：为参与方建立责任角色、授权范围和有效区间。"""
    try:
        return services.create_grant(
            db,
            activity_id=activity_id,
            grant_id=body.grant_id,
            role=body.role,
            party_id=body.party_id,
            fields=body.fields,
            effective_from=body.effective_from,
            effective_to=body.effective_to,
            actor_id=body.actor_id,
            reason=body.reason,
        )
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.get("/grants", response_model=list[GrantOut])
def list_grants(
    activity_id: str,
    at: datetime | None = Query(None, description="按时刻过滤当时责任链上的授权"),
    db: Session = Depends(get_db),
) -> Any:
    try:
        return services.list_grants(db, activity_id, at=at)
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.get("/chain", response_model=ChainOut)
def get_chain(
    activity_id: str,
    at: datetime | None = Query(None, description="缺省为服务器当前时间"),
    db: Session = Depends(get_db),
) -> Any:
    """查询某时刻的责任链：各角色责任方、授权范围、生效委托与共同字段。"""
    try:
        return services.get_chain(db, activity_id, at=at)
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.put("/shared-fields", response_model=SharedFieldsOut)
def put_shared_fields(
    activity_id: str, body: SharedFieldsIn, db: Session = Depends(get_db)
) -> Any:
    """配置多方共同字段及其会签角色。"""
    try:
        return services.configure_shared_fields(
            db,
            activity_id=activity_id,
            changes=body.shared_fields,
            actor_id=body.actor_id,
            reason=body.reason,
        )
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.get("/shared-fields", response_model=SharedFieldsOut)
def get_shared_fields(activity_id: str, db: Session = Depends(get_db)) -> Any:
    return services.get_shared_fields(db, activity_id)


@router.post(
    "/transfers", response_model=TransferOut, status_code=status.HTTP_201_CREATED
)
def transfer(
    activity_id: str, body: TransferIn, db: Session = Depends(get_db)
) -> Any:
    """责任转移：在生效时刻截断当前授权并开启新授权，不追溯改写旧授权。"""
    try:
        return services.transfer_responsibility(
            db,
            activity_id=activity_id,
            grant_id=body.grant_id,
            to_party_id=body.to_party_id,
            to_role=body.to_role,
            new_grant_id=body.new_grant_id,
            effective_at=body.effective_at,
            expected_version=body.expected_version,
            actor_id=body.actor_id,
            reason=body.reason,
        )
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.post(
    "/delegations",
    response_model=DelegationOut,
    status_code=status.HTTP_201_CREATED,
)
def create_delegation(
    activity_id: str, body: DelegationIn, db: Session = Depends(get_db)
) -> Any:
    """委托授权：同一时刻生效的委托关系不得形成循环授权。"""
    try:
        return services.create_delegation(
            db,
            activity_id=activity_id,
            delegation_id=body.delegation_id,
            from_party_id=body.from_party_id,
            to_party_id=body.to_party_id,
            fields=body.fields,
            effective_from=body.effective_from,
            effective_to=body.effective_to,
            actor_id=body.actor_id,
            reason=body.reason,
        )
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.get("/delegations", response_model=list[DelegationOut])
def list_delegations(activity_id: str, db: Session = Depends(get_db)) -> Any:
    return services.list_delegations(db, activity_id)


@router.post("/authorize", response_model=AuthorizeOut)
def authorize(
    activity_id: str, body: AuthorizeIn, db: Session = Depends(get_db)
) -> Any:
    """授权判定：按事件业务时间匹配当时责任链，判定参与方能否更正字段。"""
    try:
        return services.authorize(
            db,
            activity_id=activity_id,
            party_id=body.party_id,
            field=body.field,
            business_time=body.business_time,
        )
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.post(
    "/corrections",
    response_model=CorrectionOut,
    status_code=status.HTTP_201_CREATED,
)
def open_correction(
    activity_id: str, body: CorrectionIn, db: Session = Depends(get_db)
) -> Any:
    """提交事件更正；共同字段进入会签，紧急操作先生效并在期限内补审。"""
    try:
        return services.open_correction(
            db,
            activity_id=activity_id,
            correction_id=body.correction_id,
            event_id=body.event_id,
            field=body.field,
            old_value=body.old_value,
            new_value=body.new_value,
            business_time=body.business_time,
            party_id=body.party_id,
            reason=body.reason,
            emergency=body.emergency,
            review_window_hours=body.review_window_hours,
            requested_at=body.requested_at,
        )
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.get("/corrections", response_model=list[CorrectionOut])
def list_corrections(
    activity_id: str,
    as_of: datetime | None = Query(None, description="评估补审逾期的参照时刻"),
    status: str | None = Query(None),
    overdue_only: bool = Query(False),
    db: Session = Depends(get_db),
) -> Any:
    try:
        return services.list_corrections(
            db, activity_id, as_of=as_of, status=status, overdue_only=overdue_only
        )
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.get("/corrections/{correction_id}", response_model=CorrectionOut)
def get_correction(
    activity_id: str,
    correction_id: str,
    as_of: datetime | None = Query(None),
    db: Session = Depends(get_db),
) -> Any:
    try:
        return services.get_correction(db, activity_id, correction_id, as_of=as_of)
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.post("/corrections/{correction_id}/countersign", response_model=CorrectionOut)
def countersign(
    activity_id: str,
    correction_id: str,
    body: CountersignIn,
    db: Session = Depends(get_db),
) -> Any:
    """会签：共同字段更正需其他责任方全部同意，任何一方拒绝即驳回。"""
    try:
        return services.countersign_correction(
            db,
            activity_id=activity_id,
            correction_id=correction_id,
            party_id=body.party_id,
            approve=body.approve,
            reason=body.reason,
        )
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.post("/corrections/{correction_id}/review", response_model=CorrectionOut)
def review(
    activity_id: str,
    correction_id: str,
    body: ReviewIn,
    db: Session = Depends(get_db),
) -> Any:
    """紧急更正的限期补审。"""
    try:
        return services.review_correction(
            db,
            activity_id=activity_id,
            correction_id=correction_id,
            party_id=body.party_id,
            outcome=body.outcome,
            reason=body.reason,
            reviewed_at=body.reviewed_at,
        )
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.get("/audit", response_model=AuditTrailOut)
def audit_trail(
    activity_id: str,
    action: str | None = Query(None),
    actor_id: str | None = Query(None),
    aggregate_type: str | None = Query(None),
    db: Session = Depends(get_db),
) -> Any:
    """审计查询：汇总活动下授权、委托、共同字段配置与更正的完整审计轨迹。"""
    return services.audit_trail(
        db,
        activity_id,
        action=action,
        actor_id=actor_id,
        aggregate_type=aggregate_type,
    )
