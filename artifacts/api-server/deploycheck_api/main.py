from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.concurrency import run_in_threadpool

from .scanner import (
    MAX_ARCHIVE_BYTES,
    ArchiveLimitError,
    InvalidArchiveError,
    ScanTimeoutError,
    scan_project_archive,
)
from .schemas import ErrorResponse, ScanResponse

MAX_REQUEST_BODY_BYTES = MAX_ARCHIVE_BYTES + 512 * 1024
SCAN_ROUTE = "/api/v1/scans"
logger = logging.getLogger("deploycheck")


class BoundedUploadBody:
    """Buffer only bounded scan requests so chunked uploads cannot grow without limit."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope.get("path") != SCAN_ROUTE:
            await self.app(scope, receive, send)
            return

        content_length: int | None = None
        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                try:
                    content_length = int(value)
                except ValueError:
                    await self._send_error(
                        scope, receive, send, 400, "Invalid request size."
                    )
                    return
                break

        if content_length is not None and content_length > MAX_REQUEST_BODY_BYTES:
            await self._send_error(
                scope, receive, send, 413, "Uploaded archive exceeds the 12 MB limit."
            )
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_REQUEST_BODY_BYTES:
                await self._send_error(
                    scope, receive, send, 413, "Uploaded archive exceeds the 12 MB limit."
                )
                return
            if not message.get("more_body", False):
                break

        buffered_body = bytes(body)
        replayed = False

        async def replay_body() -> dict[str, Any]:
            nonlocal replayed
            if replayed:
                await asyncio.sleep(0)
                return {"type": "http.disconnect"}
            replayed = True
            return {
                "type": "http.request",
                "body": buffered_body,
                "more_body": False,
            }

        await self.app(scope, replay_body, send)

    @staticmethod
    async def _send_error(
        scope: dict[str, Any],
        receive: Any,
        send: Any,
        status_code: int,
        message: str,
    ) -> None:
        response = JSONResponse({"error": message}, status_code=status_code)
        await response(scope, receive, send)


app = FastAPI(
    title="DeployCheck API",
    description="Static, privacy-conscious checks for pre-deployment project archives.",
    version="1.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url=None,
)
app.add_middleware(BoundedUploadBody)


@app.get("/api/healthz")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    SCAN_ROUTE,
    response_model=ScanResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid archive"},
        408: {"model": ErrorResponse, "description": "Scan time limit exceeded"},
        413: {"model": ErrorResponse, "description": "Archive exceeds size limits"},
        422: {"model": ErrorResponse, "description": "Invalid scan request"},
    },
)
async def scan_project(archive: UploadFile = File(...)) -> JSONResponse:
    try:
        archive_bytes = await archive.read(MAX_ARCHIVE_BYTES + 1)
        if len(archive_bytes) > MAX_ARCHIVE_BYTES:
            raise ArchiveLimitError
        result = await run_in_threadpool(
            scan_project_archive, archive_bytes, archive.filename
        )
        return JSONResponse(result.model_dump(mode="json"))
    except ArchiveLimitError:
        return JSONResponse(
            {"error": "Archive exceeds a supported scan limit."}, status_code=413
        )
    except InvalidArchiveError:
        return JSONResponse(
            {"error": "The upload is not a valid, safe ZIP archive."},
            status_code=400,
        )
    except ScanTimeoutError:
        return JSONResponse(
            {"error": "The static scan exceeded its time limit. Try a smaller archive."},
            status_code=408,
        )
    except Exception as exc:
        # Never log exception text or uploaded content; only the exception class.
        logger.error("Scan request failed (%s)", type(exc).__name__)
        return JSONResponse(
            {"error": "The scan could not be completed. Uploaded content was not saved."},
            status_code=500,
        )
    finally:
        await archive.close()


@app.exception_handler(RequestValidationError)
async def request_validation_error(
    _request: Request, _exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse({"error": "Invalid scan request."}, status_code=422)


@app.exception_handler(StarletteHTTPException)
async def http_error(
    _request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    if exc.status_code == 404:
        return JSONResponse({"error": "Not found."}, status_code=404)
    return JSONResponse({"error": "Request could not be processed."}, status_code=exc.status_code)
