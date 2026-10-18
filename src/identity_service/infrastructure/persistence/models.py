import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    Uuid,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class IdentityModel(Base):
    __tablename__ = "identities"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending_verification', 'active', 'deactivated')",
            name="ck_identities_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    # Stored already normalized (trimmed + lowercased) by the application;
    # the unique constraint is the race-safe backstop for concurrent
    # registrations.
    email: Mapped[str] = mapped_column(String(254), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Stable, optional reference to the customer owned by the separate
    # Customer Service. Unique so one customer can link to one identity.
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, nullable=True, unique=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class EmailVerificationTokenModel(Base):
    __tablename__ = "email_verification_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    identity_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("identities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # SHA-256 hex digest of the raw token; the raw value is never stored.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class PasswordResetTokenModel(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    identity_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("identities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AuthSessionModel(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    identity_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("identities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # SHA-256 hex digest of the raw session token; the raw value is only
    # ever returned to the client at login.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
