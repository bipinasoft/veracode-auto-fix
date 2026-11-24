"""Veracode REST API client (Applications, Sandboxes, Findings).

Authentication uses Veracode's HMAC scheme (VERACODE-HMAC-SHA-256), the same
algorithm implemented by the official `veracode-api-signing` package.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from binascii import unhexlify
from urllib.parse import quote, urlencode, urlparse

from .http import request_json

log = logging.getLogger(__name__)

SIGNING_VERSION = b"vcode_request_version_1"


def _hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def build_hmac_header(
    api_id: str, api_secret: str, url: str, method: str, *, timestamp_ms: int | None = None,
    nonce_hex: str | None = None,
) -> str:
    """Return the Authorization header value for one Veracode API request."""
    parsed = urlparse(url)
    path_and_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    timestamp = str(timestamp_ms if timestamp_ms is not None else int(time.time() * 1000))
    nonce = nonce_hex or secrets.token_hex(16)

    signing_data = f"id={api_id}&host={parsed.hostname}&url={path_and_query}&method={method}"

    key_nonce = _hmac_sha256(unhexlify(api_secret), unhexlify(nonce))
    key_date = _hmac_sha256(key_nonce, timestamp.encode())
    signature_key = _hmac_sha256(key_date, SIGNING_VERSION)
    signature = hmac.new(signature_key, signing_data.encode(), hashlib.sha256).hexdigest()

    return (
        f"VERACODE-HMAC-SHA-256 id={api_id},ts={timestamp},nonce={nonce},sig={signature}"
    )


class VeracodeClient:
    def __init__(self, api_id: str, api_secret: str, base_url: str = "https://api.veracode.com"):
        self.api_id = api_id
        self.api_secret = api_secret
        self.base_url = base_url.rstrip("/")

    # -- low level ------------------------------------------------------------
    def _auth(self, method: str, url: str) -> dict[str, str]:
        return {"Authorization": build_hmac_header(self.api_id, self.api_secret, url, method)}

    def get(self, path: str, params: dict | None = None) -> dict:
        query = f"?{urlencode(params, quote_via=quote)}" if params else ""
        return request_json("GET", f"{self.base_url}{path}{query}", header_factory=self._auth) or {}

    def _get_all_pages(self, path: str, params: dict, embedded_key: str) -> list[dict]:
        """Follow Veracode's HAL pagination and return every embedded item."""
        items: list[dict] = []
        page = 0
        while True:
            data = self.get(path, {**params, "page": page, "size": 500})
            items.extend(data.get("_embedded", {}).get(embedded_key, []))
            total_pages = data.get("page", {}).get("total_pages", 1)
            page += 1
            if page >= total_pages:
                return items

    # -- applications / sandboxes ---------------------------------------------------
    def find_application(self, name: str) -> dict:
        """Return the application profile whose name matches exactly."""
        apps = self._get_all_pages("/appsec/v1/applications", {"name": name}, "applications")
        exact = [a for a in apps if a.get("profile", {}).get("name") == name]
        if not exact:
            raise SystemExit(f"Veracode application profile '{name}' not found.")
        return exact[0]

    def find_sandbox(self, app_guid: str, name: str) -> dict | None:
        sandboxes = self._get_all_pages(
            f"/appsec/v1/applications/{app_guid}/sandboxes", {}, "sandboxes"
        )
        return next((s for s in sandboxes if s.get("name") == name), None)

    # -- findings ------------------------------------------------------------------
    def get_findings(self, app_guid: str, scan_type: str, sandbox_guid: str | None) -> list[dict]:
        """Latest findings for the policy scan, or for a sandbox when given.

        STATIC and SCA must be requested separately: the Findings API does not
        return SCA findings combined with other scan types.
        """
        params = {"scan_type": scan_type}
        if sandbox_guid:
            params["context"] = sandbox_guid
        return self._get_all_pages(
            f"/appsec/v2/applications/{app_guid}/findings", params, "findings"
        )
