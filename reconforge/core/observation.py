"""In-memory observation types emitted by modules and consumed by the correlation engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Rel:
    """A relationship from the observed asset to another asset.

    confirmed=True means the relationship was directly observed (e.g. a DNS answer,
    a TLS handshake). confirmed=False means it was inferred (e.g. a certificate SAN
    lists a name, a JS file references a domain).
    """

    type: str
    target_type: str
    target_key: str
    confirmed: bool = True
    attrs: dict[str, Any] = field(default_factory=dict)
    target_attrs: dict[str, Any] = field(default_factory=dict)
    reverse: bool = False  # relation direction is target -> observed asset


@dataclass
class Obs:
    type: str
    key: str
    attrs: dict[str, Any] = field(default_factory=dict)
    source: str | None = None          # tool that produced it (defaults to module name)
    display: str | None = None
    evidence_id: str | None = None
    confidence: float | None = None    # multiplier in [0,1] applied to source reliability
    relations: list[Rel] = field(default_factory=list)
    scope: str | None = None           # override scope classification
    tags: list[str] = field(default_factory=list)
