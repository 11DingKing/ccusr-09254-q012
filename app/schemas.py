"""服务端业务模块。"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class PlanIn(BaseModel):
    plan_version: str = Field(..., min_length=1, max_length=128)
    iana_timezone: str = Field(..., min_length=1, max_length=64)
    required_seconds: int = Field(0, ge=0)


class PlanOut(BaseModel):
    plan_version: str
    iana_timezone: str
    required_seconds: int


class CheckinPayload(BaseModel):
    activity_id: str = ""
    activity_type: str = "regular"
    check_in_at: datetime
    check_out_at: datetime

    @model_validator(mode="after")
    def _check_order(self) -> "CheckinPayload":
        if self.check_out_at <= self.check_in_at:
            raise ValueError("check_out_at must be after check_in_at")
        return self

    @field_validator("check_in_at", "check_out_at")
    @classmethod
    def _ensure_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware (RFC 3339)")
        return v


class MentorConfirmPayload(BaseModel):
    checkin_event_id: str


class LeaveCorrectionPayload(BaseModel):
    adjustment_seconds: int
    reason: str = ""


class EventIn(BaseModel):
    event_id: str = Field(..., min_length=1, max_length=128)
    event_type: Literal["checkin", "mentor_confirm", "leave_correction"]
    student_id: str = Field(..., min_length=1, max_length=128)
    payload: dict[str, Any]


class EventBatchIn(BaseModel):
    events: list[EventIn]


class EventOut(BaseModel):
    event_id: str
    plan_version: str
    event_type: str
    student_id: str
    payload: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class ImportResult(BaseModel):
    accepted: int
    duplicates: list[str]
    rejected: list[dict[str, Any]]


class DailyTotal(BaseModel):
    academic_day: str
    seconds: int


class CheckinExplanation(BaseModel):
    event_id: str
    activity_id: str
    activity_type: str
    status: str
    counts: bool
    check_in_at_utc: str
    check_out_at_utc: str
    raw_seconds: int
    academic_days: list[dict[str, Any]]


class AdjustmentOut(BaseModel):
    event_id: str
    seconds: int
    reason: str


class StudentProgressOut(BaseModel):
    student_id: str
    confirmed_seconds: int
    pending_seconds: int
    adjustment_seconds: int
    total_seconds: int
    lesson_units: int
    pending_lesson_units: int
    meets_requirement: bool
    daily: list[DailyTotal]
    checkins: list[CheckinExplanation]
    adjustments: list[AdjustmentOut]


class SnapshotOut(BaseModel):
    plan_version: str
    freeze_id: str | None
    timezone: str
    required_seconds: int
    generated_at: str
    event_cutoff_id: str | None
    students: list[dict[str, Any]]


class FreezeIn(BaseModel):
    pass


class DiffOut(BaseModel):
    plan_version: str
    old_freeze_id: str | None
    new_freeze_id: str | None
    old_generated_at: str
    new_generated_at: str
    old_event_cutoff_id: str | None
    new_event_cutoff_id: str | None
    student_changes: list[dict[str, Any]]
    students_affected: int


RoleName = Literal["college", "enterprise", "third_party"]


def _ensure_aware(v: datetime | None) -> datetime | None:
    if v is not None and v.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware (RFC 3339)")
    return v


class GrantIn(BaseModel):
    grant_id: str = Field(..., min_length=1, max_length=128)
    role: RoleName
    party_id: str = Field(..., min_length=1, max_length=128)
    fields: list[str] = Field(..., min_length=1)
    effective_from: datetime
    effective_to: datetime | None = None
    actor_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(..., min_length=1, max_length=512)

    @field_validator("effective_from", "effective_to")
    @classmethod
    def _aware(cls, v: datetime | None) -> datetime | None:
        return _ensure_aware(v)


class GrantOut(BaseModel):
    grant_id: str
    activity_id: str
    role: str
    party_id: str
    fields: list[str]
    effective_from: str
    effective_to: str | None
    status: str
    version: int


class TransferIn(BaseModel):
    grant_id: str = Field(..., min_length=1, max_length=128)
    to_party_id: str = Field(..., min_length=1, max_length=128)
    to_role: RoleName | None = None
    new_grant_id: str = Field(..., min_length=1, max_length=128)
    effective_at: datetime
    expected_version: int = Field(..., ge=1)
    actor_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(..., min_length=1, max_length=512)

    @field_validator("effective_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        return _ensure_aware(v)  # type: ignore[return-value]


class TransferOut(BaseModel):
    closed: GrantOut
    opened: GrantOut


class DelegationIn(BaseModel):
    delegation_id: str = Field(..., min_length=1, max_length=128)
    from_party_id: str = Field(..., min_length=1, max_length=128)
    to_party_id: str = Field(..., min_length=1, max_length=128)
    fields: list[str] = Field(..., min_length=1)
    effective_from: datetime
    effective_to: datetime | None = None
    actor_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(..., min_length=1, max_length=512)

    @field_validator("effective_from", "effective_to")
    @classmethod
    def _aware(cls, v: datetime | None) -> datetime | None:
        return _ensure_aware(v)


class DelegationOut(BaseModel):
    delegation_id: str
    activity_id: str
    from_party_id: str
    to_party_id: str
    fields: list[str]
    effective_from: str
    effective_to: str | None
    status: str
    version: int


class SharedFieldsIn(BaseModel):
    shared_fields: dict[str, list[str] | None]
    actor_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(..., min_length=1, max_length=512)


class SharedFieldsOut(BaseModel):
    activity_id: str
    shared_fields: dict[str, list[str]]
    version: int


class AuthorizeIn(BaseModel):
    party_id: str = Field(..., min_length=1, max_length=128)
    field: str = Field(..., min_length=1, max_length=128)
    business_time: datetime

    @field_validator("business_time")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        return _ensure_aware(v)  # type: ignore[return-value]


class CountersignerOut(BaseModel):
    party_id: str
    role: str


class AuthorizeOut(BaseModel):
    decision: str
    reason: str
    via_delegation_id: str | None
    required_countersigners: list[CountersignerOut]


class CorrectionIn(BaseModel):
    correction_id: str = Field(..., min_length=1, max_length=128)
    event_id: str = Field(..., min_length=1, max_length=128)
    field: str = Field(..., min_length=1, max_length=128)
    old_value: str = Field("", max_length=512)
    new_value: str = Field("", max_length=512)
    business_time: datetime
    party_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(..., min_length=1, max_length=512)
    emergency: bool = False
    review_window_hours: int = Field(48, gt=0, le=720)
    requested_at: datetime | None = Field(
        None, description="缺省取服务器当前时间；用于补录历史操作"
    )

    @field_validator("business_time", "requested_at")
    @classmethod
    def _aware(cls, v: datetime | None) -> datetime | None:
        return _ensure_aware(v)


class CountersignatureOut(BaseModel):
    party_id: str
    role: str
    approve: bool
    signed_at: str
    reason: str


class CorrectionOut(BaseModel):
    correction_id: str
    activity_id: str
    event_id: str
    field: str
    old_value: str
    new_value: str
    business_time: str
    requested_by: str
    requested_at: str
    emergency: bool
    status: str
    required_countersigners: list[CountersignerOut]
    countersignatures: list[CountersignatureOut]
    review_deadline: str | None
    reviewed_by: str | None
    reviewed_at: str | None
    review_outcome: str | None
    review_overdue: bool
    version: int


class CountersignIn(BaseModel):
    party_id: str = Field(..., min_length=1, max_length=128)
    approve: bool
    reason: str = Field(..., min_length=1, max_length=512)


class ReviewIn(BaseModel):
    party_id: str = Field(..., min_length=1, max_length=128)
    outcome: Literal["confirm", "revert"]
    reason: str = Field(..., min_length=1, max_length=512)
    reviewed_at: datetime | None = Field(
        None, description="缺省取服务器当前时间；用于补录历史操作"
    )

    @field_validator("reviewed_at")
    @classmethod
    def _aware(cls, v: datetime | None) -> datetime | None:
        return _ensure_aware(v)


class ChainRoleOut(BaseModel):
    role: str
    party_id: str
    grant_id: str
    fields: list[str]
    effective_from: str
    effective_to: str | None
    status: str


class ChainOut(BaseModel):
    activity_id: str
    at: str
    roles: list[ChainRoleOut]
    delegations: list[DelegationOut]
    shared_fields: dict[str, list[str]]


class AuditEntryOut(BaseModel):
    aggregate_type: str
    aggregate_id: str
    sequence: int
    action: str
    actor_id: str
    occurred_at: str
    before: str
    after: str
    reason: str
    fingerprint: str


class AuditTrailOut(BaseModel):
    activity_id: str
    total: int
    entries: list[AuditEntryOut]
