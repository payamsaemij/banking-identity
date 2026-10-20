from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from identity_service.application.validators.email import (
    normalize_and_validate_email,
    normalize_email,
)
from identity_service.application.validators.password import validate_password
from identity_service.domain.entities.identity import Identity
from identity_service.domain.enums.identity_status import IdentityStatus
from identity_service.domain.exceptions import InvalidEmailError, InvalidPasswordError


def _clean_email(value: str) -> str:
    try:
        return normalize_and_validate_email(value)
    except InvalidEmailError as error:  # pydantic turns this into a field error
        raise ValueError(str(error)) from error


def _registered_email(value: str) -> str:
    """Normalize for lookups; format errors simply never match."""
    return normalize_email(value)


def _policy_password(value: str) -> str:
    try:
        return validate_password(value)
    except InvalidPasswordError as error:
        raise ValueError(str(error)) from error


class RegisterRequest(BaseModel):
    email: str
    password: str
    customer_id: UUID | None = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return _clean_email(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return _policy_password(value)


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=1, max_length=256)


class ResendVerificationRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def normalize(cls, value: str) -> str:
        return _registered_email(value)


class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize(cls, value: str) -> str:
        return _registered_email(value)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        return _policy_password(value)


class PasswordResetRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def normalize(cls, value: str) -> str:
        return _registered_email(value)


class PasswordResetCompletionRequest(BaseModel):
    token: str = Field(min_length=1, max_length=256)
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        return _policy_password(value)


class DeactivateRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)


class ReactivateRequest(BaseModel):
    identity_id: UUID


class IntrospectRequest(BaseModel):
    """Token introspection request from a trusted calling service."""

    token: str = Field(min_length=1, max_length=256)


class IntrospectionResponse(BaseModel):
    """Minimal introspection result; never includes email or status.

    ``active`` is false for unknown, expired, revoked, and deactivated
    sessions alike — deliberately indistinguishable. The optional fields
    are present only when ``active`` is true.
    """

    active: bool
    identity_id: UUID | None = None
    expires_at: datetime | None = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


class IdentityResponse(BaseModel):
    id: UUID
    email: str
    status: IdentityStatus
    email_verified_at: datetime | None
    customer_id: UUID | None

    @classmethod
    def from_identity(cls, identity: Identity) -> "IdentityResponse":
        return cls(
            id=identity.id,
            email=identity.email,
            status=identity.status,
            email_verified_at=identity.email_verified_at,
            customer_id=identity.customer_id,
        )


class MessageResponse(BaseModel):
    message: str


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: str | None = None
    details: object | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody
