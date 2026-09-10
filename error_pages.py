"""Friendly error pages, with an exact carve-out for API and JSON clients.

Browsers get a small cat-themed page rendered from `templates/error.html`,
which extends the shared public layout, so the nav menu and the footer come
along and the user can navigate away from the error. Any request whose path
starts with `/api/` or whose `Accept` header asks for `application/json`
instead gets exactly the response it got before this module existed: the
admin UI sends that Accept header on every fetch (`static/js/util.js`) and
the overlay posts JSON to `/api/report`, so both keep the shapes their
clients parse.

The copy lives here and nowhere else. Rendering is injected (`render`), so
this module stays a leaf module: it never imports `app` and never builds a
Jinja environment of its own.
"""

from __future__ import annotations

from collections.abc import Callable
from http import HTTPStatus

from fastapi import Request
from fastapi.responses import (HTMLResponse, JSONResponse, PlainTextResponse,
                               Response)

# The page that extends the shared public layout (nav + footer).
TEMPLATE = "error.html"

# Status code -> (quote, one-line explanation). Wording is verbatim from the
# agreed copy; the 500 explanation must not promise that data was saved.
QUOTES: dict[int, tuple[str, str]] = {
    400: ("That request made no sense to the cats.",
          "The server could not read the request."),
    403: ("Nope. This cat is not sitting in that lap.",
          "The server refused this request. If you were sending a form, "
          "reload the page and try again."),
    404: ("No cat here. It wandered off.",
          "That address does not exist. The link may be old or mistyped."),
    405: ("You cannot pet a cat that way.",
          "That action is not allowed on this address."),
    413: ("That log paste is bigger than the cat. Trim it and try again.",
          "The pasted data was larger than the 400 KB limit."),
    429: ("Too many reports at once. The cats are napping. Try again in a "
          "minute.",
          "You have hit the rate limit for this action."),
    500: ("A cat walked across the keyboard. Nothing you sent was lost.",
          "The server hit an unexpected error. Try again in a moment."),
}

# Every code without a row above.
GENERIC_CODE_COPY = ("The cats are confused. Please try again.",
                     "Something went wrong.")


def error_copy(code: int) -> tuple[str, str]:
    """The (quote, explanation) pair shown on the page for *code*."""
    return QUOTES.get(code, GENERIC_CODE_COPY)


def wants_json(request: Request) -> bool:
    """True when the caller expects a machine-readable body, never a page.

    `/api/` is the JSON-only surface, and `Accept: application/json` is what
    the admin UI sends on every fetch, so both keep the error shape
    `errText()` in `static/js/util.js` already parses.
    """
    if request.url.path.startswith("/api/"):
        return True
    accept = request.headers.get("accept") or ""
    return "application/json" in accept.lower()


def _reason(code: int) -> str:
    """The standard reason phrase for *code*, or a label for a custom one."""
    try:
        return HTTPStatus(code).phrase
    except ValueError:
        # Not a registered HTTP status, so there is no phrase to reuse.
        return f"HTTP {code}"


def api_response(code: int, headers: dict | None = None) -> Response:
    """The response a JSON/API client got for *code* before this module.

    Reproduces FastAPI's default HTTP error body (`{"detail": <phrase>}`),
    plus the two raw bodies this app produced itself: the payload cap in the
    middleware (a bare Response, so it carried no content-type) and
    Starlette's plain-text 500.
    """
    if code == 413:
        return Response("payload too large", status_code=code, headers=headers)
    if code == 500:
        return PlainTextResponse("Internal Server Error", status_code=code,
                                 headers=headers)
    return JSONResponse({"detail": _reason(code)}, status_code=code,
                        headers=headers)


def render_error(request: Request, code: int, fallback: Response | None = None,
                 *, render: Callable[..., str],
                 headers: dict | None = None) -> Response:
    """Error response for *request*: a page for browsers, bytes for clients.

    *render* is the app's string renderer, called as
    ``render(TEMPLATE, code=..., quote=..., explanation=...)``.
    *fallback* is the response a JSON/API client must keep when the app
    builds a route-specific body (the two 403s and the report 429); when it
    is omitted the framework default for *code* is reproduced.
    *headers* is forwarded to both shapes, so a 405 keeps its `Allow`.
    """
    if wants_json(request):
        if fallback is not None:
            return fallback
        return api_response(code, headers=headers)
    quote, explanation = error_copy(code)
    body = render(TEMPLATE, code=code, quote=quote, explanation=explanation)
    return HTMLResponse(body, status_code=code, headers=headers)
