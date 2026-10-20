import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from identity_service.application.exceptions import RateLimitExceededError
from identity_service.application.ports.clock import Clock, SystemClock
from identity_service.application.ports.rate_limiter import RateLimiter
from identity_service.application.use_cases.authenticate_session import (
    AuthContext,
    AuthenticateSession,
)
from identity_service.application.use_cases.change_password import ChangePassword
from identity_service.application.use_cases.deactivate_identity import (
    DeactivateIdentity,
)
from identity_service.application.use_cases.login import Login
from identity_service.application.use_cases.logout import Logout
from identity_service.application.use_cases.reactivate_identity import (
    ReactivateIdentity,
)
from identity_service.application.use_cases.register_identity import RegisterIdentity
from identity_service.application.use_cases.request_password_reset import (
    RequestPasswordReset,
)
from identity_service.application.use_cases.resend_email_verification import (
    ResendEmailVerification,
)
from identity_service.application.use_cases.reset_password import ResetPassword
from identity_service.application.use_cases.verify_email import VerifyEmail
from identity_service.domain.exceptions import AuthenticationError
from identity_service.infrastructure.config import Settings, get_settings
from identity_service.infrastructure.email.senders import (
    ConsoleEmailSender,
    SmtpEmailSender,
    build_email_senders,
)
from identity_service.infrastructure.persistence.repositories import (
    SqlAlchemyIdentityRepository,
    SqlAlchemyPasswordResetTokenRepository,
    SqlAlchemySessionRepository,
    SqlAlchemyVerificationTokenRepository,
)
from identity_service.infrastructure.security.argon2_hasher import Argon2PasswordHasher
from identity_service.infrastructure.security.secrets_token_generator import (
    SecretsTokenGenerator,
)

_bearer_scheme = HTTPBearer(auto_error=False, description="Session token from login")


@dataclass
class _Infra:
    """Process-wide infrastructure singletons shared by all requests."""

    settings: Settings
    password_hasher: Argon2PasswordHasher
    token_generator: SecretsTokenGenerator
    clock: Clock
    email_sender: ConsoleEmailSender | SmtpEmailSender


def build_infra(settings: Settings) -> _Infra:
    return _Infra(
        settings=settings,
        password_hasher=Argon2PasswordHasher(),
        token_generator=SecretsTokenGenerator(),
        clock=SystemClock(),
        email_sender=build_email_senders(settings),
    )


@dataclass
class UseCases:
    """All application use cases wired to one request's repositories."""

    register_identity: RegisterIdentity
    verify_email: VerifyEmail
    resend_email_verification: ResendEmailVerification
    login: Login
    authenticate_session: AuthenticateSession
    logout: Logout
    change_password: ChangePassword
    request_password_reset: RequestPasswordReset
    reset_password: ResetPassword
    deactivate_identity: DeactivateIdentity
    reactivate_identity: ReactivateIdentity


def get_db_session(request: Request) -> Iterator[Session]:
    """One transaction per request: commit on success, roll back on error."""
    session: Session = request.app.state.session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


DbSession = Annotated[Session, Depends(get_db_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def get_use_cases(request: Request, session: DbSession) -> UseCases:
    infra: _Infra = request.app.state.infra
    settings = infra.settings

    identity_repository = SqlAlchemyIdentityRepository(session)
    verification_token_repository = SqlAlchemyVerificationTokenRepository(session)
    password_reset_token_repository = SqlAlchemyPasswordResetTokenRepository(session)
    session_repository = SqlAlchemySessionRepository(session)

    return UseCases(
        register_identity=RegisterIdentity(
            identity_repository=identity_repository,
            verification_token_repository=verification_token_repository,
            password_hasher=infra.password_hasher,
            token_generator=infra.token_generator,
            verification_email_sender=infra.email_sender,
            clock=infra.clock,
            verification_token_ttl_seconds=(
                settings.email_verification_token_ttl_seconds
            ),
        ),
        verify_email=VerifyEmail(
            identity_repository=identity_repository,
            verification_token_repository=verification_token_repository,
            clock=infra.clock,
        ),
        resend_email_verification=ResendEmailVerification(
            identity_repository=identity_repository,
            verification_token_repository=verification_token_repository,
            token_generator=infra.token_generator,
            verification_email_sender=infra.email_sender,
            clock=infra.clock,
            verification_token_ttl_seconds=(
                settings.email_verification_token_ttl_seconds
            ),
        ),
        login=Login(
            identity_repository=identity_repository,
            session_repository=session_repository,
            password_hasher=infra.password_hasher,
            token_generator=infra.token_generator,
            clock=infra.clock,
            session_ttl_seconds=settings.session_ttl_seconds,
        ),
        authenticate_session=AuthenticateSession(
            session_repository=session_repository,
            identity_repository=identity_repository,
            clock=infra.clock,
        ),
        logout=Logout(session_repository=session_repository, clock=infra.clock),
        change_password=ChangePassword(
            identity_repository=identity_repository,
            session_repository=session_repository,
            password_reset_token_repository=password_reset_token_repository,
            password_hasher=infra.password_hasher,
            clock=infra.clock,
        ),
        request_password_reset=RequestPasswordReset(
            identity_repository=identity_repository,
            password_reset_token_repository=password_reset_token_repository,
            token_generator=infra.token_generator,
            password_reset_email_sender=infra.email_sender,
            clock=infra.clock,
            password_reset_token_ttl_seconds=(
                settings.password_reset_token_ttl_seconds
            ),
        ),
        reset_password=ResetPassword(
            identity_repository=identity_repository,
            password_reset_token_repository=password_reset_token_repository,
            session_repository=session_repository,
            password_hasher=infra.password_hasher,
            clock=infra.clock,
        ),
        deactivate_identity=DeactivateIdentity(
            identity_repository=identity_repository,
            session_repository=session_repository,
            verification_token_repository=verification_token_repository,
            password_reset_token_repository=password_reset_token_repository,
            password_hasher=infra.password_hasher,
            clock=infra.clock,
        ),
        reactivate_identity=ReactivateIdentity(identity_repository=identity_repository),
    )


UseCasesDep = Annotated[UseCases, Depends(get_use_cases)]


async def get_auth_context(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ],
    use_cases: UseCasesDep,
) -> AuthContext:
    """Resolve the bearer session token into an authenticated principal."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AuthenticationError("Authentication credentials were not provided.")

    context = use_cases.authenticate_session.execute(credentials.credentials)
    if context is None:
        raise AuthenticationError("Invalid or expired session.")

    return context


AuthContextDep = Annotated[AuthContext, Depends(get_auth_context)]


async def require_admin(
    settings: Annotated[Settings, Depends(get_settings)],
    x_admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> None:
    """Explicit authorization policy for administrative operations.

    The key is a server-to-service secret configured per environment.
    When no key is configured, administrative access is disabled
    outright rather than falling back to open access.
    """
    configured = settings.admin_api_key
    if (
        not configured
        or x_admin_key is None
        or not secrets.compare_digest(
            x_admin_key.encode("utf-8"), configured.encode("utf-8")
        )
    ):
        raise HTTPException(status_code=403, detail="Administrative access required.")


async def require_service(
    settings: Annotated[Settings, Depends(get_settings)],
    x_service_key: Annotated[str | None, Header(alias="X-Service-Key")] = None,
) -> None:
    """Authorize a trusted calling service for token introspection.

    Same policy as ``require_admin``: a shared per-environment secret,
    compared in constant time, and when no key is configured the
    endpoint is disabled outright rather than accepting keyless calls.
    """
    configured = settings.service_api_key
    if (
        not configured
        or x_service_key is None
        or not secrets.compare_digest(
            x_service_key.encode("utf-8"), configured.encode("utf-8")
        )
    ):
        raise HTTPException(status_code=403, detail="Service access required.")


async def register_rate_limit(request: Request, settings: SettingsDep) -> None:
    await _enforce_rate_limit(
        request,
        "register",
        settings.register_rate_limit_max,
        settings.register_rate_limit_window_seconds,
    )


async def login_rate_limit(request: Request, settings: SettingsDep) -> None:
    await _enforce_rate_limit(
        request,
        "login",
        settings.login_rate_limit_max,
        settings.login_rate_limit_window_seconds,
    )


async def resend_rate_limit(request: Request, settings: SettingsDep) -> None:
    await _enforce_rate_limit(
        request,
        "resend_verification",
        settings.resend_rate_limit_max,
        settings.resend_rate_limit_window_seconds,
    )


async def password_reset_request_rate_limit(
    request: Request, settings: SettingsDep
) -> None:
    await _enforce_rate_limit(
        request,
        "password_reset_request",
        settings.password_reset_request_rate_limit_max,
        settings.password_reset_request_rate_limit_window_seconds,
    )


async def _enforce_rate_limit(
    request: Request, scope: str, limit: int, window_seconds: int
) -> None:
    limiter: RateLimiter = request.app.state.rate_limiter
    client_ip = request.client.host if request.client else "unknown"
    decision = limiter.check(scope, f"{scope}:{client_ip}", limit, window_seconds)
    if not decision.allowed:
        raise RateLimitExceededError(scope, decision.retry_after_seconds)


# --- rate-limit dependencies for sensitive operations --------------------
# Limits apply per client IP and per instance; see README for the
# distributed-deployment caveat.

RegisterRateLimited = Annotated[None, Depends(register_rate_limit)]
LoginRateLimited = Annotated[None, Depends(login_rate_limit)]
ResendRateLimited = Annotated[None, Depends(resend_rate_limit)]
PasswordResetRequestRateLimited = Annotated[
    None, Depends(password_reset_request_rate_limit)
]
