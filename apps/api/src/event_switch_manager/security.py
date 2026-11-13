from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class LocalWebGuard:
    def __init__(self, app: ASGIApp, *, authorities: frozenset[str], development: bool) -> None:
        self.app = app
        self.authorities = authorities
        self.development = development

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def secure_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                if scope["path"].startswith("/api/"):
                    headers["Cache-Control"] = "no-store"
                if not self.development:
                    headers["Content-Security-Policy"] = (
                        "default-src 'self'; object-src 'none'; base-uri 'none'; "
                        "frame-ancestors 'none'; form-action 'self'"
                    )
            await send(message)

        headers = Headers(scope=scope)
        hosts = headers.getlist("host")
        if len(hosts) != 1 or hosts[0] not in self.authorities:
            response = JSONResponse({"detail": "Invalid local host"}, status_code=400)
            await response(scope, receive, secure_send)
            return
        if scope["method"] not in SAFE_METHODS:
            origins = headers.getlist("origin")
            if origins != [f"http://{hosts[0]}"]:
                response = JSONResponse({"detail": "Same-origin request required"}, status_code=403)
                await response(scope, receive, secure_send)
                return
        await self.app(scope, receive, secure_send)
