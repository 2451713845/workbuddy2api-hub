from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from pathlib import Path
from threading import Lock
from typing import Any, Union


class RawTraceWriter:
    """Append full request/response material without altering field values."""

    def __init__(self, path: Union[Path, str]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    @staticmethod
    def _body(value: Union[bytes, str, None]) -> dict[str, Any]:
        if value is None:
            return {"encoding": "text", "value": ""}
        if isinstance(value, str):
            return {"encoding": "text", "value": value}
        try:
            return {"encoding": "text", "value": value.decode("utf-8")}
        except UnicodeDecodeError:
            return {
                "encoding": "base64",
                "value": base64.b64encode(value).decode("ascii"),
            }

    def write(
        self,
        *,
        sequence: int,
        method: str,
        url: str,
        request_headers: dict[str, str],
        request_body: Union[bytes, str, None],
        response: Any,
        cookies: dict[str, str],
    ) -> None:
        record = {
            "sequence": sequence,
            "time": datetime.now(timezone.utc).isoformat(),
            "request": {
                "method": method,
                "url": url,
                "headers": dict(request_headers),
                "body": self._body(request_body),
            },
            "response": {
                "status": int(response.status_code),
                "url": str(response.url),
                "headers": dict(response.headers),
                "body": self._body(bytes(response.content)),
            },
            "cookies": dict(cookies),
        }
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def write_error(
        self,
        *,
        sequence: int,
        method: str,
        url: str,
        request_headers: dict[str, str],
        request_body: Union[bytes, str, None],
        error: BaseException,
        cookies: dict[str, str],
    ) -> None:
        record = {
            "sequence": sequence,
            "time": datetime.now(timezone.utc).isoformat(),
            "request": {
                "method": method,
                "url": url,
                "headers": dict(request_headers),
                "body": self._body(request_body),
            },
            "error": {
                "type": type(error).__name__,
                "message": str(error),
            },
            "cookies": dict(cookies),
        }
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
