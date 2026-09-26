"""服务端业务模块。"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Plan(Base):
    __tablename__ = "plans"

    plan_version: Mapped[str] = mapped_column(String(128), primary_key=True)
    iana_timezone: Mapped[str] = mapped_column(String(64), nullable=False)
    required_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    __table_args__ = (
        CheckConstraint("required_seconds >= 0", name="ck_plans_required_nonneg"),
    )


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    plan_version: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    student_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("event_id", "plan_version", name="uq_events_event_id_plan"),
        Index("ix_events_plan_student", "plan_version", "student_id"),
    )


class Freeze(Base):
    __tablename__ = "freezes"

    plan_version: Mapped[str] = mapped_column(String(128), primary_key=True)
    freeze_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    snapshot: Mapped[dict] = mapped_column(JSON, nullable=False)
    event_cutoff_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class ResponsibilityGrant(Base):
    """责任授权：有效区间以 ISO-8601 字符串保存，区间判定在领域层完成。"""

    __tablename__ = "responsibility_grants"

    grant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    activity_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    party_id: Mapped[str] = mapped_column(String(128), nullable=False)
    fields: Mapped[list] = mapped_column(JSON, nullable=False)
    effective_from: Mapped[str] = mapped_column(String(64), nullable=False)
    effective_to: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    audit: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_resp_grants_activity_role", "activity_id", "role"),
    )


class ResponsibilityDelegation(Base):
    __tablename__ = "responsibility_delegations"

    delegation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    activity_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    from_party_id: Mapped[str] = mapped_column(String(128), nullable=False)
    to_party_id: Mapped[str] = mapped_column(String(128), nullable=False)
    fields: Mapped[list] = mapped_column(JSON, nullable=False)
    effective_from: Mapped[str] = mapped_column(String(64), nullable=False)
    effective_to: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    audit: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )


class SharedFieldConfig(Base):
    __tablename__ = "shared_field_configs"

    activity_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    shared_fields: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    audit: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )


class Correction(Base):
    __tablename__ = "corrections"

    correction_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    activity_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    field: Mapped[str] = mapped_column(String(128), nullable=False)
    old_value: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    new_value: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    business_time: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    requested_at: Mapped[str] = mapped_column(String(64), nullable=False)
    emergency: Mapped[bool] = mapped_column(nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    required_countersigners: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    countersignatures: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    review_deadline: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reviewed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    review_outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    audit: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
