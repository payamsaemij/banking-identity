import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from identity_service.application.exceptions import (
    ApplicationError,
    RateLimitExceededError,
)
from identity_service.domain.exceptions import (
    AuthenticationError,
    CustomerAlreadyLinkedError,
    DomainError,
    EmailAlreadyVerifiedError,
    IdentityAlreadyExistsError,
    IdentityNotActiveError,
    IdentityNotFoundError,
    InvalidCurrentPasswordError,
    InvalidEmailError,
    InvalidIdentityStateError,
    InvalidPasswordError,
    InvalidTokenError,
)
from identity_service.infrastructure.observability.logging import get_request_id

logger = logging.getLogger(__name__)

# Domain error -> (HTTP status, machine-readable code). Messages come
# from the exceptions themselves; they never contain secrets.
_ERROR_MAP: dict[type[DomainError], tuple[int, str]] = {
    InvalidEmailError: (422, "invalid_email"),
    InvalidPasswordError: (422, "invalid_password"),
    IdentityAlreadyExistsError: (409, "email_already_registered"),
    CustomerAlreadyLinkedError: (409, "customer_already_linked"),
    IdentityNotFoundError: (404, "identity_not_found"),
    IdentityNotActiveError: (409, "identity_not_active"),
    InvalidIdentityStateError: (409, "invalid_identity_state"),
    EmailAlreadyVerifiedError: (409, "email_already_verified"),
    InvalidTokenError: (400, "invalid_token"),
    AuthenticationError: (401, "invalid_credentials"),
    InvalidCurrentPasswordError: (403, "invalid_current_password"),
}


def error_body(
    code: str, message: str, details: object | None = None
) -> dict[str, object]:
    error: dict[str, object] = {
        "code": code,
        "message": message,
        "request_id": get_request_id(),
    }
    if details is not None:
        error["details"] = details
    return {"error": error}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def handle_domain_error(request: Request, exc: DomainError) -> JSONResponse:
        status, code = _ERROR_MAP.get(type(exc), (500, "domain_error"))
        if status >= 500:
            logger.error(
                "Unhandled domain error.",
                extra={"event": "error.unhandled_domain", "error": type(exc).__name__},
            )
        headers = (
            {"WWW-Authenticate": "Bearer"}
            if isinstance(exc, AuthenticationError)
            else None
        )
        return JSONResponse(
            status_code=status, content=error_body(code, str(exc)), headers=headers
        )

    @app.exception_handler(RateLimitExceededError)
    async def handle_rate_limit(
        request: Request, exc: RateLimitExceededError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content=error_body("rate_limit_exceeded", str(exc)),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )

    @app.exception_handler(ApplicationError)
    async def handle_application_error(
        request: Request, exc: ApplicationError
    ) -> JSONResponse:
        logger.error(
            "Unhandled application error.",
            extra={"event": "error.unhandled_application", "error": type(exc).__name__},
        )
        return JSONResponse(
            status_code=500,
            content=error_body("internal_error", "An unexpected error occurred."),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Only locations, messages, and types are echoed back — pydantic's
        # error context can embed raw input values (e.g. the password).
        details = [
            {"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]}
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=error_body(
                "validation_error", "Request validation failed.", details
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        headers = dict(exc.headers or {})
        if exc.status_code == 401:
            headers.setdefault("WWW-Authenticate", "Bearer")
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(f"http_{exc.status_code}", str(exc.detail)),
            headers=headers or None,
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # Single boundary log: class name only, never the message or
        # traceback of an arbitrary exception (both can embed sensitive
        # values such as SQL parameters).
        logger.error(
            "Unhandled server error.",
            extra={"event": "error.unhandled", "error": type(exc).__name__},
        )
        return JSONResponse(
            status_code=500,
            content=error_body("internal_error", "An unexpected error occurred."),
        )
