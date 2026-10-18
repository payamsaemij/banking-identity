import logging
import time
import uuid

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from identity_service.infrastructure.observability.logging import set_request_id

logger = logging.getLogger("identity_service.http")

_MAX_REQUEST_ID_LENGTH = 128


class RequestContextMiddleware:
    """Correlation ids and one structured access-log line per request.

    Assigns (or accepts) an ``X-Request-ID``, exposes it to logs through
    a context variable, echoes it on the response, and logs method,
    route template (never the query string), status, duration, and
    client IP once the response is complete.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = Headers(scope=scope).get("x-request-id")
        request_id = (incoming or uuid.uuid4().hex)[:_MAX_REQUEST_ID_LENGTH]
        set_request_id(request_id)

        status_holder: dict[str, int | None] = {"status": None}

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                MutableHeaders(scope=message).append("x-request-id", request_id)
            await send(message)

        started_at = time.perf_counter()
        try:
            await self.app(scope, receive, send_with_headers)
        finally:
            duration_ms = round((time.perf_counter() - started_at) * 1000, 1)
            status = status_holder["status"]
            route = scope.get("route")
            log = logger.error if (status or 500) >= 500 else logger.info
            log(
                "Request completed.",
                extra={
                    "event": "http.request",
                    "method": scope.get("method"),
                    "route": getattr(route, "path", scope.get("path")),
                    "status": status,
                    "duration_ms": duration_ms,
                    "client_ip": self._client_ip(scope),
                },
            )
            set_request_id(None)

    @staticmethod
    def _client_ip(scope: Scope) -> str | None:
        client = scope.get("client")
        if isinstance(client, tuple) and client:
            return str(client[0])
        return None
