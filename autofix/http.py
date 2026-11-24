"""Small JSON-over-HTTP helper built on the standard library.

Keeping the runtime free of third-party packages makes the Docker image and
local setup simpler: Python 3.10+ is all that is needed.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Callable

log = logging.getLogger(__name__)

RETRY_STATUS = {429, 500, 502, 503, 504}


class HttpError(RuntimeError):
    def __init__(self, status: int, url: str, body: str):
        super().__init__(f"HTTP {status} for {url}: {body[:500]}")
        self.status = status
        self.body = body


def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: Any = None,
    header_factory: Callable[[str, str], dict[str, str]] | None = None,
    retries: int = 3,
    timeout: int = 120,
) -> Any:
    """Send a request and return the decoded JSON response (or None if empty).

    header_factory(method, url) is called on every attempt, which lets
    signature-based auth (Veracode HMAC) produce a fresh signature per retry.
    """
    data = json.dumps(body).encode() if body is not None else None
    for attempt in range(1, retries + 1):
        all_headers = {"Accept": "application/json"}
        if data is not None:
            all_headers["Content-Type"] = "application/json"
        all_headers.update(headers or {})
        if header_factory:
            all_headers.update(header_factory(method, url))

        req = urllib.request.Request(url, data=data, method=method, headers=all_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as err:
            err_body = err.read().decode(errors="replace")
            if err.code in RETRY_STATUS and attempt < retries:
                wait = 2**attempt
                log.warning("HTTP %s from %s, retrying in %ss", err.code, url, wait)
                time.sleep(wait)
                continue
            raise HttpError(err.code, url, err_body) from None
        except urllib.error.URLError as err:
            if attempt < retries:
                time.sleep(2**attempt)
                continue
            raise RuntimeError(f"Cannot reach {url}: {err.reason}") from None
    raise RuntimeError("unreachable")
