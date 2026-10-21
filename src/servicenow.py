"""Small, fail-closed ServiceNow Table API client.

Delivery retries and reconciliation belong to the durable outbox. In particular,
an uncertain POST/PATCH result must never be treated as permission to resend it.
"""

from dataclasses import dataclass, field
import os
import re
from typing import Any, Mapping
from urllib.parse import urlsplit
from uuid import UUID

import httpx


class SnowError(Exception):
    """A sanitized failure that is safe to persist in delivery status."""

    def __init__(self, message: str, *, status_code: int | None = None,
                 retryable: bool = False) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable


class SnowAmbiguousWrite(SnowError):
    """The remote write may have committed; reconcile before taking action."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message, status_code=status_code, retryable=False)


def _correlation(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("aiops:"):
        raise SnowError("Invalid ServiceNow correlation ID")
    try:
        parsed = UUID(value[6:])
    except (ValueError, AttributeError):
        raise SnowError("Invalid ServiceNow correlation ID") from None
    if value != f"aiops:{parsed}":
        raise SnowError("Invalid ServiceNow correlation ID")
    return value


def _sys_id(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise SnowError("Invalid ServiceNow sys_id")
    return value


@dataclass(frozen=True)
class Settings:
    instance_url: str = ""
    user: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    correlation_field: str = "correlation_id"
    category: str = "inquiry"
    subcategory: str = ""
    assignment_group: str = ""
    dry_run: bool = True
    note_format: str = "html"

    def __post_init__(self) -> None:
        if self.note_format not in {"html", "text"}:
            raise SnowError("Invalid SERVICENOW_NOTE_FORMAT; expected html or text")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", self.correlation_field) or (
            self.correlation_field in {"sys_id", "number", "active", "state"}
        ):
            raise SnowError("Invalid SERVICENOW_CORRELATION_FIELD")
        url = self.instance_url.strip().rstrip("/")
        if url:
            try:
                parsed = urlsplit(url)
                valid = (parsed.scheme == "https" and bool(parsed.hostname)
                         and parsed.username is None and parsed.password is None
                         and not parsed.query and not parsed.fragment and not parsed.path
                         and "?" not in url and "#" not in url
                         and not any(character.isspace() for character in url)
                         and "\\" not in url and parsed.port != 0)
            except ValueError:
                valid = False
            if not valid:
                raise SnowError("SERVICENOW_INSTANCE_URL must be an HTTPS origin without credentials, path, query, or fragment")
        object.__setattr__(self, "instance_url", url)

    @property
    def enabled(self) -> bool:
        return bool(self.instance_url)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ
        dry_run = env.get("SERVICENOW_DRY_RUN", "true").strip().lower()
        if dry_run not in {"1", "true", "yes", "on", "0", "false", "no", "off"}:
            raise SnowError("Invalid SERVICENOW_DRY_RUN")
        return cls(
            note_format=env.get("SERVICENOW_NOTE_FORMAT", "html").strip().lower(),
            instance_url=env.get("SERVICENOW_INSTANCE_URL", ""),
            user=env.get("SERVICENOW_USER", ""),
            password=env.get("SERVICENOW_PASSWORD", ""),
            correlation_field=env.get("SERVICENOW_CORRELATION_FIELD", "correlation_id"),
            category=env.get("SERVICENOW_CATEGORY", "inquiry"),
            subcategory=env.get("SERVICENOW_SUBCATEGORY", ""),
            assignment_group=env.get("SERVICENOW_ASSIGNMENT_GROUP", ""),
            dry_run=dry_run in {"1", "true", "yes", "on"},
        )


ServiceNowSettings = Settings


class ServiceNowClient:
    def __init__(self, settings: Settings | None = None, *,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings or Settings.from_env()
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "ServiceNowClient":
        if self._client is not None:
            raise SnowError("ServiceNow client is already open")
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=5.0, pool=5.0),
            transport=self._transport,
            follow_redirects=False,
            auth=(self.settings.user, self.settings.password),
            headers={"Accept": "application/json"},
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def _fields(self) -> str:
        return f"sys_id,number,active,state,{self.settings.correlation_field}"

    async def _request(self, method: str, path: str = "", *,
                       params: dict[str, str] | None = None,
                       payload: dict[str, Any] | None = None) -> Any:
        write = method != "GET"
        if write and self.settings.dry_run:
            raise SnowError("ServiceNow writes are disabled in dry-run mode")
        if not self.settings.enabled or not self.settings.user or not self.settings.password:
            raise SnowError("ServiceNow credentials or instance URL are not configured")
        if self._client is None:
            raise SnowError("ServiceNow client must be used as an async context manager")
        query = {"sysparm_fields": self._fields, "sysparm_display_value": "false",
                 "sysparm_exclude_reference_link": "true", **(params or {})}
        try:
            response = await self._client.request(
                method, f"{self.settings.instance_url}/api/now/table/incident{path}",
                params=query, json=payload,
            )
        except httpx.RequestError:
            if write:
                raise SnowAmbiguousWrite("ServiceNow write outcome is unknown after a transport failure") from None
            raise SnowError("ServiceNow read failed during transport", retryable=True) from None

        status = response.status_code
        if not 200 <= status < 300:
            if write and status >= 500:
                raise SnowAmbiguousWrite("ServiceNow write outcome is unknown after a server error",
                                         status_code=status)
            raise SnowError(f"ServiceNow request returned HTTP {status}", status_code=status,
                            retryable=status == 429 or (not write and (status == 408 or status >= 500)))
        try:
            body = response.json()
            if not isinstance(body, dict) or "result" not in body:
                raise ValueError
            return body["result"]
        except (ValueError, TypeError):
            if write:
                raise SnowAmbiguousWrite("ServiceNow write returned an invalid success response") from None
            raise SnowError("ServiceNow read returned an invalid success response") from None

    def _record(self, result: Any, *, sys_id: str | None = None,
                correlation_id: str | None = None) -> dict[str, Any]:
        if not isinstance(result, dict):
            raise SnowError("ServiceNow returned an invalid incident record")
        actual_id = _sys_id(result.get("sys_id"))
        actual_correlation = _correlation(result.get(self.settings.correlation_field))
        if sys_id is not None and actual_id != sys_id:
            raise SnowError("ServiceNow returned an unexpected incident sys_id")
        if correlation_id is not None and actual_correlation != correlation_id:
            raise SnowError("ServiceNow returned an unexpected incident correlation ID")
        if not isinstance(result.get("number"), str) or not result["number"]:
            raise SnowError("ServiceNow returned an incident without a number")
        if result.get("active") not in (True, False, "true", "false") or "active" not in result:
            raise SnowError("ServiceNow returned an invalid incident active flag")
        if not isinstance(result.get("state"), (str, int)) or result["state"] == "":
            raise SnowError("ServiceNow returned an incident without a state")
        return result

    async def find_incident(self, correlation_id: str) -> dict[str, Any] | None:
        key = _correlation(correlation_id)
        results = await self._request("GET", params={
            "sysparm_query": f"{self.settings.correlation_field}={key}",
            "sysparm_limit": "2",
        })
        if not isinstance(results, list) or len(results) > 1:
            raise SnowError("ServiceNow correlation lookup returned an invalid or ambiguous result")
        if not results:
            return None
        return self._record(results[0], correlation_id=key)

    async def get_incident(self, sys_id: str) -> dict[str, Any]:
        identity = _sys_id(sys_id)
        result = await self._request("GET", f"/{identity}")
        return self._record(result, sys_id=identity)

    async def create_incident(self, payload: dict[str, Any]) -> dict[str, Any]:
        key = _correlation(payload.get(self.settings.correlation_field))
        if "sys_id" in payload:
            raise SnowError("ServiceNow create payload must not supply sys_id")
        result = await self._request("POST", payload=payload)
        try:
            return self._record(result, correlation_id=key)
        except SnowError:
            raise SnowAmbiguousWrite("ServiceNow create returned an invalid incident confirmation") from None

    async def update_incident(self, sys_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        identity = _sys_id(sys_id)
        if "sys_id" in payload:
            raise SnowError("ServiceNow update payload must not supply sys_id")
        key = (_correlation(payload[self.settings.correlation_field])
               if self.settings.correlation_field in payload else None)
        result = await self._request("PATCH", f"/{identity}", payload=payload)
        try:
            return self._record(result, sys_id=identity, correlation_id=key)
        except SnowError:
            raise SnowAmbiguousWrite("ServiceNow update returned an invalid incident confirmation") from None
