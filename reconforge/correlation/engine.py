"""Intelligence correlation engine.

Turns observations from independent tools into one record per real-world asset:

* Identity: (target, type, normalized key). Different tools reporting the same
  hostname / URL / IP / certificate collapse into one asset (cross-tool matching).
* Assets are NEVER merged because they share infrastructure (IP, CDN, certificate
  issuer, hosting provider). Shared infrastructure is modelled as relations instead.
* Every observation is stored separately with its module, source tool, timestamp and
  evidence reference, so any merged attribute can be traced back.
* Confidence = 1 - Π(1 - reliability_i × multiplier_i) over distinct sources
  (noisy-OR), so corroboration by independent tools raises confidence.
* False-positive flags are sticky: they survive re-observation in later scans.
"""
from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.observation import Obs, Rel
from ..db.models import Asset, Observation, Relation
from ..util import is_ip, new_id, normalize_host, normalize_url, origin_of, utcnow

if TYPE_CHECKING:  # pragma: no cover
    from ..config import Config
    from ..scope import Scope

log = logging.getLogger("reconforge.correlation")

HOST_TYPES = {"domain", "subdomain"}


def normalize_key(type_: str, key: str) -> str:
    key = (key or "").strip()
    if type_ in HOST_TYPES or type_ == "third_party":
        return normalize_host(key)
    if type_ == "ip":
        return str(ipaddress.ip_address(key.strip("[]")))
    if type_ == "web_app":
        return origin_of(key)
    if type_ in ("endpoint", "js_file"):
        return normalize_url(key)
    if type_ == "asn":
        k = key.upper()
        return k if k.startswith("AS") else f"AS{k}"
    if type_ in ("technology", "provider", "cloud_resource", "certificate", "repository"):
        return key.lower()
    return key


def combine_confidence(values: list[float]) -> float:
    p = 1.0
    for v in values:
        p *= 1.0 - max(0.0, min(1.0, v))
    return round(1.0 - p, 3)


class CorrelationEngine:
    def __init__(self, session: Session, config: "Config", scope: "Scope", target_id: str, scan_id: str):
        self.s = session
        self.config = config
        self.scope = scope
        self.target_id = target_id
        self.scan_id = scan_id
        self._cache: dict[tuple[str, str], Asset] = {}
        self.touched: dict[str, set[str]] = defaultdict(set)     # asset_id -> modules that directly observed it this scan
        self.referenced: dict[str, set[str]] = defaultdict(set)  # asset_id -> modules that only referenced it (relation target)
        self.observation_count = 0

    # ------------------------------------------------------------------ assets
    def _classify_scope(self, type_: str, key: str, attrs: dict) -> str:
        if type_ in HOST_TYPES:
            return self.scope.classify_host(key)
        if type_ in ("web_app", "endpoint", "js_file"):
            from ..util import host_of

            return self.scope.classify_host(host_of(key))
        if type_ == "third_party":
            return "third_party"
        if type_ == "ip":
            return "in_scope" if self.scope.ip_allowed(key) else "unverified"
        if type_ == "service":
            ip = key.split(":")[0] if not key.startswith("[") else key[1:].split("]")[0]
            return "in_scope" if self.scope.ip_allowed(ip) else "unverified"
        return "n/a"

    def _fix_type(self, type_: str, key: str) -> str:
        if type_ in HOST_TYPES and is_ip(key):
            return "ip"  # IP targets are hosts too; never store an address as a (sub)domain
        if type_ in HOST_TYPES:
            return "domain" if key in self.scope.root_domains else "subdomain"
        return type_

    def get(self, type_: str, key: str) -> Asset | None:
        nkey = normalize_key(type_, key)
        type_ = self._fix_type(type_, nkey)
        if (type_, nkey) in self._cache:
            return self._cache[(type_, nkey)]
        asset = self.s.execute(
            select(Asset).where(Asset.target_id == self.target_id, Asset.type == type_, Asset.key == nkey)
        ).scalar_one_or_none()
        if asset:
            self._cache[(type_, nkey)] = asset
        return asset

    def upsert(self, type_: str, key: str, attrs: dict | None, source: str, module: str,
               multiplier: float | None = None, display: str | None = None, scope: str | None = None,
               tags: list[str] | None = None, direct: bool = True) -> Asset:
        nkey = normalize_key(type_, key)
        if not nkey:
            raise ValueError(f"empty key for {type_}")
        type_ = self._fix_type(type_, nkey)
        now = utcnow()
        asset = self.get(type_, nkey)
        if asset is None:
            asset = Asset(
                id=new_id("ast"), target_id=self.target_id, type=type_, key=nkey,
                display=display or nkey, scope=scope or self._classify_scope(type_, nkey, attrs or {}),
                attributes={}, sources=[], confidence=0.0, first_seen=now, last_seen=now,
                first_scan_id=self.scan_id, last_scan_id=self.scan_id, status="active", tags=[],
            )
            self.s.add(asset)
            self._cache[(type_, nkey)] = asset
        else:
            asset.last_seen = now
            asset.last_scan_id = self.scan_id
            asset.status = "active"
            if scope:
                asset.scope = scope
        if attrs:
            asset.attributes = merge_attrs(asset.attributes or {}, attrs)
        derived = self._derived(type_, nkey, asset.attributes or {})
        if derived:
            asset.attributes = {**(asset.attributes or {}), **derived}
        if tags:
            asset.tags = sorted(set(asset.tags or []) | set(tags))
        # provenance + confidence
        rel = self.config.reliability(source) * (multiplier if multiplier is not None else 1.0)
        sources = [dict(x) for x in (asset.sources or [])]
        for entry in sources:
            if entry["source"] == source:
                entry["last_seen"] = now.isoformat()
                entry["count"] = entry.get("count", 1) + 1
                entry["reliability"] = max(entry.get("reliability", 0), rel)
                break
        else:
            sources.append({"source": source, "module": module, "first_seen": now.isoformat(),
                            "last_seen": now.isoformat(), "count": 1, "reliability": round(rel, 3)})
        asset.sources = sources
        asset.confidence = combine_confidence([e["reliability"] for e in sources])
        (self.touched if direct else self.referenced)[asset.id].add(module)
        return asset

    @staticmethod
    def _derived(type_: str, key: str, attrs: dict) -> dict:
        """Central derived classifications (categories never imply a weakness)."""
        from .classify import classify_third_party, query_params, url_categories

        out = {}
        if type_ == "endpoint" and "url_categories" not in attrs:
            out["url_categories"] = url_categories(key)
            params = query_params(key)
            if params:
                out["params"] = sorted(set(params) | set(attrs.get("params", [])))
        if type_ == "third_party" and attrs.get("category") in (None, "external", "cname-target", "redirect-target"):
            cat, svc = classify_third_party(key)
            if cat != "external" or "category" not in attrs:
                out["category"] = cat
                if svc and not attrs.get("service"):
                    out["service"] = svc
        return out

    # ---------------------------------------------------------------- relations
    def relate(self, src: Asset, dst: Asset, rel_type: str, confirmed: bool, source: str,
               attrs: dict | None = None, evidence_id: str | None = None, confidence: float | None = None) -> Relation:
        if src.id == dst.id:
            raise ValueError("self relation")
        rel = self.s.execute(
            select(Relation).where(Relation.src_id == src.id, Relation.dst_id == dst.id, Relation.type == rel_type)
        ).scalar_one_or_none()
        now = utcnow()
        conf = confidence if confidence is not None else self.config.reliability(source) * (1.0 if confirmed else 0.7)
        if rel is None:
            rel = Relation(id=new_id("rel"), target_id=self.target_id, src_id=src.id, dst_id=dst.id, type=rel_type,
                           confirmed=confirmed, confidence=round(conf, 3), attributes=attrs or {}, sources=[source],
                           evidence_ids=[evidence_id] if evidence_id else [], first_seen=now, last_seen=now,
                           last_scan_id=self.scan_id)
            self.s.add(rel)
        else:
            rel.last_seen = now
            rel.last_scan_id = self.scan_id
            rel.confirmed = rel.confirmed or confirmed
            if source not in (rel.sources or []):
                rel.sources = [*(rel.sources or []), source]
            if evidence_id and evidence_id not in (rel.evidence_ids or []):
                rel.evidence_ids = [*(rel.evidence_ids or []), evidence_id][-20:]
            if attrs:
                rel.attributes = {**(rel.attributes or {}), **attrs}
            rel.confidence = round(combine_confidence([rel.confidence, conf * 0.5]), 3)
        return rel

    # ------------------------------------------------------------------ ingest
    def ingest(self, obs: Obs, module: str) -> Asset:
        source = obs.source or module
        asset = self.upsert(obs.type, obs.key, obs.attrs, source, module, obs.confidence, obs.display, obs.scope, obs.tags)
        self.s.add(Observation(
            id=new_id("obs"), scan_id=self.scan_id, asset_id=asset.id, module=module, source=source,
            observed_at=utcnow(), data=_jsonable(obs.attrs), evidence_id=obs.evidence_id,
            confidence=round(self.config.reliability(source) * (obs.confidence if obs.confidence is not None else 1.0), 3),
        ))
        self.observation_count += 1
        if obs.evidence_id:
            asset.attributes = {**(asset.attributes or {}), "_last_evidence": obs.evidence_id}
        for r in obs.relations:
            self._ingest_relation(asset, r, source, module, obs.evidence_id)
        if self.observation_count % 200 == 0:
            self.s.flush()
        return asset

    def _ingest_relation(self, asset: Asset, r: Rel, source: str, module: str, evidence_id: str | None) -> None:
        try:
            other = self.upsert(r.target_type, r.target_key, r.target_attrs, source, module,
                                multiplier=None if r.confirmed else 0.7, direct=False,
                                display=(r.target_attrs or {}).get("name") if r.target_type == "technology" else None)
        except ValueError as exc:
            log.debug("skipping relation %s: %s", r, exc)
            return
        if other.id == asset.id:
            return
        src, dst = (other, asset) if r.reverse else (asset, other)
        self.relate(src, dst, r.type, r.confirmed, source, r.attrs, evidence_id)


def merge_attrs(existing: dict, new: dict) -> dict:
    """Merge observation attributes into an asset record.

    Keys prefixed with '+' are union-merged lists (e.g. '+discovered_via'); other keys
    overwrite (latest observation wins, older values remain in the observation table).
    """
    out = dict(existing)
    for k, v in new.items():
        if k.startswith("+"):
            name = k[1:]
            cur = out.get(name) or []
            vals = v if isinstance(v, list) else [v]
            out[name] = sorted({*map(_freeze, cur), *map(_freeze, vals)}, key=str)
            out[name] = [_thaw(x) for x in out[name]]
        else:
            out[k] = _jsonable(v)
    return out


def _freeze(x):
    import json

    return json.dumps(x, sort_keys=True) if isinstance(x, (dict, list)) else x


def _thaw(x):
    import json

    if isinstance(x, str) and x[:1] in "[{":
        try:
            return json.loads(x)
        except ValueError:
            return x
    return x


def _jsonable(v):
    import json

    return json.loads(json.dumps(v, default=str))
