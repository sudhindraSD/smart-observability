"""FastAPI 422 handler that never echoes rejected input back to the caller.

FastAPI's default ``RequestValidationError`` response includes each error's
``input`` value. Even with Pydantic ``hide_input_in_errors=True`` set, the raw
rejected string (a secret pasted into the wrong field, for example) is echoed
to the client in the 422 body, so the default handler is not safe for a
service that validates secret-bearing payloads. This module registers a
replacement that strips everything except ``type``, ``loc`` and ``msg``.
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.requests import Request


def install_safe_validation_handler(app: FastAPI) -> None:
    """Register a ``RequestValidationError`` handler returning a minimal 422.

    Response body is exactly::

        [{"type": <str>, "loc": [<str|int>, ...], "msg": <str>}, ...]

    with no ``input``, ``url`` or ``ctx`` keys, so rejected secret strings can
    never leak through validation errors.
    """

    @app.exception_handler(RequestValidationError)
    async def _safe_validation_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        safe_errors: List[Dict[str, Any]] = [
            {"type": err["type"], "loc": list(err["loc"]), "msg": err["msg"]}
            for err in exc.errors()
        ]
        return JSONResponse(status_code=422, content=safe_errors)
