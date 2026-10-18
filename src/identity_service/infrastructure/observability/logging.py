import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from identity_service.infrastructure.config import Settings

# Builtin attributes of a LogRecord; anything else found on the record is
# treated as a structured extra field and merged into the JSON payload.
_RESERVED_RECORD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__) | {
    "message",
    "asctime",
    "taskName",
}

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


def set_request_id(request_id: str | None) -> None:
    request_id_var.set(request_id)


def get_request_id() -> str | None:
    return request_id_var.get()


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log line, ready for log shippers.

    Stable fields: timestamp, level, service, environment, logger,
    message, request_id (when inside a request), plus any ``extra``
    fields passed by application code. Only the exception class name is
    recorded — never the raw traceback text or arbitrary exception
    payloads, which could embed sensitive values.
    """

    def __init__(self, service_name: str, environment: str) -> None:
        super().__init__()
        self._service_name = service_name
        self._environment = environment

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "service": self._service_name,
            "environment": self._environment,
            "logger": record.name,
            "message": record.getMessage(),
        }

        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id

        for key, value in record.__dict__.items():
            if key not in _RESERVED_RECORD_FIELDS and not key.startswith("_"):
                payload[key] = value

        if record.exc_info and record.exc_info[0] is not None:
            payload["error"] = record.exc_info[0].__name__

        return json.dumps(payload, default=str, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """Human-readable format for local development."""

    def format(self, record: logging.LogRecord) -> str:
        request_id = request_id_var.get() or "-"
        message = super().format(record)
        return f"[{request_id}] {message}"


def configure_logging(settings: Settings) -> None:
    """Configure root logging once at startup.

    Uvicorn's own access log is disabled: request lines come from the
    application's request-context middleware, which carries the
    correlation id and route template instead.
    """
    root = logging.getLogger()
    root.setLevel(settings.log_level.upper())

    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    if settings.log_format == "json":
        formatter: logging.Formatter = JsonFormatter(
            service_name=settings.service_name, environment=settings.environment
        )
    else:
        formatter = ConsoleFormatter(
            "%(levelname)s %(name)s %(message)s",
        )
    handler.setFormatter(formatter)
    root.addHandler(handler)

    # Requests are logged once, by the middleware, with correlation ids.
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("uvicorn").propagate = True
    logging.getLogger("uvicorn.error").propagate = True
