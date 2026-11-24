"""Shared helpers: normalization, hashing, ids, time."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-_]{1,63}(?<!-)(\.(?!-)[a-z0-9-_]{1,63}(?<!-))*$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt: datetime | None) -> str | None:
    return dt.replace(microsecond=0).isoformat() + "Z" if dt else None


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def stable_hash(obj) -> str:
    return sha256(json.dumps(obj, sort_keys=True, default=str))[:24]


def normalize_host(host: str | None) -> str:
    if not host:
        return ""
    h = host.strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    if "://" in h:
        h = urlsplit(h).hostname or ""
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    # strip a port if present (but not for bare IPv6)
    if h.count(":") == 1:
        h = h.split(":")[0]
    return h


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def valid_hostname(host: str) -> bool:
    return bool(host) and not is_ip(host) and bool(_HOST_RE.match(host))


def normalize_url(url: str, keep_query: bool = True) -> str:
    """Canonical URL form used as an asset identity key."""
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "http").lower()
    host = normalize_host(parts.hostname or "")
    port = parts.port
    netloc = host if not port or DEFAULT_PORTS.get(scheme) == port else f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    query = ""
    if keep_query and parts.query:
        # keep parameter names, drop values: identity is the endpoint, not the data.
        names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
        query = urlencode([(n, "") for n in names])
    return urlunsplit((scheme, netloc, path, query, ""))


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = normalize_host(parts.hostname or "")
    port = parts.port or DEFAULT_PORTS.get(scheme)
    if DEFAULT_PORTS.get(scheme) == port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def host_of(url: str) -> str:
    return normalize_host(urlsplit(url).hostname or "")


def truncate(text: str, n: int = 300) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"
