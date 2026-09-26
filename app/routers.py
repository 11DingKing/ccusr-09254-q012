"""服务端业务模块。"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from . import responsibility_service as resp_services
from . import services
from . import responsibility_store as resp_store
from .db import get_db
from .schemas import (
    AssignmentIn,
    CorrectionIn,
    CountersignIn,
    DelegationIn,
    DiffOut,
    EventBatchIn,
    FieldScopeIn,
    FreezeIn,
    ImportResult,
    PlanIn,
    PlanOut,
    SnapshotOut,
    StudentProgressOut,
)

router = APIRouter(prefix="/api")


def _raise_responsibility_error(exc: Exception) -> None:
    if isinstance(exc, resp_services.ConfigError):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if isinstance(exc, resp_services.AuthorizationError):
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if isinstance(exc, resp_store.NotFoundError):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if isinstance(
        exc, (resp_store.ConflictError, resp_services.CorrectionStateError)
    ):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    raise exc


@router.post("/plans", response_model=PlanOut, status_code=status.HTTP_201_CREATED)
def create_plan(body: PlanIn, db: Session = Depends(get_db)) -> Any:
    return services.ensure_plan(
        db,
        plan_version=body.plan_version,
        iana_timezone=body.iana_timezone,
        required_seconds=body.required_seconds,
    )


@router.get("/plans/{plan_version}", response_model=PlanOut)
def read_plan(plan_version: str, db: Session = Depends(get_db)) -> Any:
    plan = services.get_plan_plain(db, plan_version)
    if plan is None:
        raise HTTPException(status_code=404, detail="plan not found")
    return plan


@router.post(
    "/plans/{plan_version}/events",
    response_model=ImportResult,
    status_code=status.HTTP_201_CREATED,
)
def post_events(
    plan_version: str, body: EventBatchIn, db: Session = Depends(get_db)
) -> Any:
    try:
        return services.import_events(
            db,
            plan_version=plan_version,
            events=[e.model_dump() for e in body.events],
        )
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/snapshot",
    response_model=SnapshotOut,
)
def get_snapshot(plan_version: str, db: Session = Depends(get_db)) -> Any:
    try:
        snap = services.current_snapshot(db, plan_version)
        return snap.to_dict()
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/students/{student_id}/progress",
    response_model=StudentProgressOut,
)
def get_progress(
    plan_version: str, student_id: str, db: Session = Depends(get_db)
) -> Any:
    try:
        result = services.student_progress(db, plan_version, student_id)
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="student not found")
    return result


@router.post(
    "/plans/{plan_version}/freezes/{freeze_id}",
    response_model=SnapshotOut,
    status_code=status.HTTP_201_CREATED,
)
def post_freeze(
    plan_version: str,
    freeze_id: str,
    body: FreezeIn,
    db: Session = Depends(get_db),
) -> Any:
    try:
        snap, _ = services.freeze_semester(
            db, plan_version=plan_version, freeze_id=freeze_id
        )
        return snap.to_dict()
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/freezes/{freeze_id}",
    response_model=SnapshotOut,
)
def get_freeze(
    plan_version: str, freeze_id: str, db: Session = Depends(get_db)
) -> Any:
    try:
        snap = services.get_frozen_snapshot(db, plan_version, freeze_id)
        return snap.to_dict()
    except services.PlanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except services.FreezeNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/plans/{plan_version}/freezes/{freeze_id}/explain/{student_id}",
    response_model=StudentProgressOut,
)
def explain_freeze_student(
    plan_version: str,
    freeze_id: str,
    student_id: str,
    db: Session = Depends(get_db),
) -> Any:
    try:
        result = services.explain_frozen_student(
            db, plan_version, freeze_id, student_id
        )
    except (services.PlanNotFoundError, services.FreezeNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="student not found")
    return result


@router.get(
    "/plans/{plan_version}/freezes/{freeze_id}/diff/{other_freeze_id}",
    response_model=DiffOut,
)
def get_diff(
    plan_version: str,
    freeze_id: str,
    other_freeze_id: str,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return services.diff_freezes(
            db, plan_version, freeze_id, other_freeze_id
        )
    except (services.PlanNotFoundError, services.FreezeNotFoundError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# 多方责任链：责任配置 / 授权判定 / 会签 / 审计查询
# ---------------------------------------------------------------------------

_RESP_TAGS = ["responsibility"]


@router.put(
    "/activities/{activity_id}/roles/{role}",
    status_code=status.HTTP_200_OK,
    tags=_RESP_TAGS,
)
def configure_assignment(
    activity_id: str, role: str, body: AssignmentIn, db: Session = Depends(get_db)
) -> Any:
    try:
        return resp_services.configure_assignment(
            db,
            activity_id=activity_id,
            role=role,
            actor_id=body.actor_id,
            valid_from=body.valid_from,
            note=body.note,
        )
    except Exception as exc:  # noqa: BLE001 - 统一映射领域异常
        _raise_responsibility_error(exc)


@router.put(
    "/activities/{activity_id}/fields/{field_name}/scope",
    status_code=status.HTTP_200_OK,
    tags=_RESP_TAGS,
)
def configure_field_scope(
    activity_id: str, field_name: str, body: FieldScopeIn, db: Session = Depends(get_db)
) -> Any:
    try:
        return resp_services.configure_field_scope(
            db,
            activity_id=activity_id,
            field_name=field_name,
            roles=body.roles,
            valid_from=body.valid_from,
        )
    except Exception as exc:  # noqa: BLE001
        _raise_responsibility_error(exc)


@router.post(
    "/activities/{activity_id}/delegations",
    status_code=status.HTTP_201_CREATED,
    tags=_RESP_TAGS,
)
def create_delegation(
    activity_id: str, body: DelegationIn, db: Session = Depends(get_db)
) -> Any:
    try:
        return resp_services.configure_delegation(
            db,
            activity_id=activity_id,
            delegator_actor_id=body.delegator_actor_id,
            delegatee_actor_id=body.delegatee_actor_id,
            valid_from=body.valid_from,
            valid_until=body.valid_until,
            reason=body.reason,
        )
    except Exception as exc:  # noqa: BLE001
        _raise_responsibility_error(exc)


@router.get("/activities/{activity_id}/chain", tags=_RESP_TAGS)
def get_chain(activity_id: str, db: Session = Depends(get_db)) -> Any:
    return resp_services.describe_chain(db, activity_id)


@router.get("/activities/{activity_id}/authorize", tags=_RESP_TAGS)
def authorize(
    activity_id: str,
    field_name: str,
    actor_id: str,
    at: datetime | None = None,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return resp_services.authorize(
            db,
            activity_id=activity_id,
            field_name=field_name,
            actor_id=actor_id,
            at=at,
        )
    except Exception as exc:  # noqa: BLE001
        _raise_responsibility_error(exc)


@router.post(
    "/activities/{activity_id}/corrections",
    status_code=status.HTTP_201_CREATED,
    tags=_RESP_TAGS,
)
def submit_correction(
    activity_id: str, body: CorrectionIn, db: Session = Depends(get_db)
) -> Any:
    try:
        return resp_services.submit_correction(
            db,
            activity_id=activity_id,
            correction_id=body.correction_id,
            field_name=body.field_name,
            event_ref=body.event_ref,
            event_occurred_at=body.event_occurred_at,
            old_value=body.old_value,
            new_value=body.new_value,
            reason=body.reason,
            actor_id=body.actor_id,
            is_emergency=body.is_emergency,
            review_seconds=body.review_seconds,
        )
    except Exception as exc:  # noqa: BLE001
        _raise_responsibility_error(exc)


@router.get(
    "/activities/{activity_id}/corrections", tags=_RESP_TAGS
)
def list_corrections(
    activity_id: str,
    status_filter: str | None = Query(None, alias="status"),
    db: Session = Depends(get_db),
) -> Any:
    return resp_services.list_corrections(db, activity_id, status_filter)


@router.get(
    "/activities/{activity_id}/corrections/{correction_id}",
    tags=_RESP_TAGS,
)
def get_correction(
    activity_id: str, correction_id: str, db: Session = Depends(get_db)
) -> Any:
    try:
        return resp_services.get_correction(db, correction_id)
    except resp_store.NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/activities/{activity_id}/corrections/{correction_id}/countersign",
    tags=_RESP_TAGS,
)
def countersign(
    activity_id: str,
    correction_id: str,
    body: CountersignIn,
    db: Session = Depends(get_db),
) -> Any:
    try:
        return resp_services.countersign(
            db,
            correction_id=correction_id,
            actor_id=body.actor_id,
            note=body.note,
            at=body.at,
        )
    except Exception as exc:  # noqa: BLE001
        _raise_responsibility_error(exc)


@router.post("/activities/{activity_id}/expire-overdue", tags=_RESP_TAGS)
def expire_overdue(activity_id: str, db: Session = Depends(get_db)) -> Any:
    expired = resp_services.expire_overdue_corrections(db, activity_id=activity_id)
    return {"expired": expired}


@router.get("/activities/{activity_id}/audit", tags=_RESP_TAGS)
def get_audit(
    activity_id: str,
    entity_type: str | None = None,
    entity_id: str | None = None,
    db: Session = Depends(get_db),
) -> Any:
    return resp_services.query_audit(
        db, activity_id, entity_type=entity_type, entity_id=entity_id
    )
