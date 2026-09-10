"""Shared API response helpers.

Lives outside app.py so route modules (admin_api, auth, future routers) can
use the same error envelope without importing the app (circular import).
"""

from __future__ import annotations

from fastapi.responses import JSONResponse


def api_response(payload, code: int = 200):
    """JSON response with a consistent error envelope.

    Only ERROR payloads are shaped as ``{"error": {"code", "message"}}``.
    Successful payloads keep their natural shape (``{"ok": true}``, ticket
    objects, lists, …) - do NOT "fix" this by wrapping successes; clients
    (and util.js ``errText``) expect the two forms.
    """
    if isinstance(payload, dict) and isinstance(payload.get("error"), str):
        payload = {"error": {"code": str(code), "message": payload["error"]}}
    return JSONResponse(payload, status_code=code)
