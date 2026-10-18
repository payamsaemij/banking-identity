from fastapi import APIRouter, Depends, status

from identity_service.presentation.dependencies import (
    AuthContextDep,
    LoginRateLimited,
    PasswordResetRequestRateLimited,
    RegisterRateLimited,
    ResendRateLimited,
    UseCasesDep,
    require_admin,
)
from identity_service.presentation.schemas import (
    ChangePasswordRequest,
    DeactivateRequest,
    IdentityResponse,
    LoginRequest,
    LoginResponse,
    MessageResponse,
    PasswordResetCompletionRequest,
    PasswordResetRequest,
    ReactivateRequest,
    RegisterRequest,
    ResendVerificationRequest,
    VerifyEmailRequest,
)

router = APIRouter(prefix="/api/v1/identity", tags=["identity"])

_GENERIC_ACCEPTED = (
    "If the request applies to an existing account, an email has been sent."
)


@router.post(
    "/register",
    response_model=IdentityResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new identity",
)
def register(
    payload: RegisterRequest,
    use_cases: UseCasesDep,
    _: RegisterRateLimited,
) -> IdentityResponse:
    identity = use_cases.register_identity.execute(
        payload.email, payload.password, customer_id=payload.customer_id
    )
    return IdentityResponse.from_identity(identity)


@router.post(
    "/verify-email",
    response_model=IdentityResponse,
    summary="Verify an email address with a single-use token",
)
def verify_email(
    payload: VerifyEmailRequest,
    use_cases: UseCasesDep,
) -> IdentityResponse:
    identity = use_cases.verify_email.execute(payload.token)
    return IdentityResponse.from_identity(identity)


@router.post(
    "/resend-verification",
    response_model=MessageResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Resend the verification email",
    description=(
        "Always returns 202 with a generic message; the response never "
        "reveals whether the email belongs to an account."
    ),
)
def resend_verification(
    payload: ResendVerificationRequest,
    use_cases: UseCasesDep,
    _: ResendRateLimited,
) -> MessageResponse:
    use_cases.resend_email_verification.execute(payload.email)
    return MessageResponse(message=_GENERIC_ACCEPTED)


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Authenticate and open a session",
)
def login(
    payload: LoginRequest,
    use_cases: UseCasesDep,
    _: LoginRateLimited,
) -> LoginResponse:
    result = use_cases.login.execute(payload.email, payload.password)
    return LoginResponse(
        access_token=result.access_token,
        expires_at=result.expires_at,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke the current session",
)
def logout(auth: AuthContextDep, use_cases: UseCasesDep) -> None:
    use_cases.logout.execute(auth.session_id)


@router.post(
    "/password/change",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change the password of the authenticated identity",
    description=(
        "Requires the current password. On success every session of the "
        "identity (including this one) is revoked."
    ),
)
def change_password(
    payload: ChangePasswordRequest,
    auth: AuthContextDep,
    use_cases: UseCasesDep,
) -> None:
    use_cases.change_password.execute(
        auth.identity_id, payload.current_password, payload.new_password
    )


@router.post(
    "/password/reset-request",
    response_model=MessageResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a password-reset email",
    description=(
        "Always returns 202 with a generic message; the response never "
        "reveals whether the email belongs to an account."
    ),
)
def request_password_reset(
    payload: PasswordResetRequest,
    use_cases: UseCasesDep,
    _: PasswordResetRequestRateLimited,
) -> MessageResponse:
    use_cases.request_password_reset.execute(payload.email)
    return MessageResponse(message=_GENERIC_ACCEPTED)


@router.post(
    "/password/reset",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Complete a password reset with a single-use token",
)
def reset_password(
    payload: PasswordResetCompletionRequest,
    use_cases: UseCasesDep,
) -> None:
    use_cases.reset_password.execute(payload.token, payload.new_password)


@router.post(
    "/deactivate",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deactivate the authenticated identity",
    description=(
        "Self-service deactivation; requires the current password. All "
        "sessions and outstanding tokens are invalidated."
    ),
)
def deactivate(
    payload: DeactivateRequest,
    auth: AuthContextDep,
    use_cases: UseCasesDep,
) -> None:
    use_cases.deactivate_identity.execute(auth.identity_id, payload.current_password)


@router.post(
    "/reactivate",
    response_model=IdentityResponse,
    summary="Reactivate a deactivated identity (administrative)",
    description=(
        "Guarded by the X-Admin-Key service header. Disabled (403 for "
        "every caller) when no admin key is configured."
    ),
    dependencies=[Depends(require_admin)],
)
def reactivate(
    payload: ReactivateRequest,
    use_cases: UseCasesDep,
) -> IdentityResponse:
    identity = use_cases.reactivate_identity.execute(payload.identity_id)
    return IdentityResponse.from_identity(identity)
