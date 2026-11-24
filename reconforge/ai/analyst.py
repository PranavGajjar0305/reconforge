"""Optional AI-assisted analysis over collected evidence.

Design guarantees:
  * The model only sees an "evidence pack" built from the database (assets, findings,
    changes, module runs), each item carrying a stable ID.
  * Every returned statement must cite at least one ID from the pack and is labelled
    `fact` (directly supported) or `hypothesis` (interpretation to verify).
  * An evidence guard rejects any statement that cites unknown IDs or mentions a
    hostname, IP address, port, URL or CVE that does not appear in the pack. Rejected
    statements are stored separately for audit and never shown as results.

Providers: `anthropic` (Claude via the official SDK) and `heuristic` (deterministic,
rule-based, no network). If the Anthropic call cannot be made, the heuristic analysis
is stored instead and the error is recorded.
"""
from __future__ import annotations

import json
import re
from typing import Protocol

from ..db import Database
from ..db.models import AIAnalysis
from ..reports.data import build_report_data
from ..util import new_id, utcnow

SECTIONS = ["top_priorities", "executive_summary", "asset_relationships", "technology_stack", "interesting_assets", "unusual_changes",
            "security_observations", "cve_intelligence", "manual_investigation", "coverage_gaps"]

ITEM_SCHEMA = {"type": "object", "additionalProperties": False, "required": ["statement", "kind", "refs"],
               "properties": {"statement": {"type": "string"}, "kind": {"type": "string", "enum": ["fact", "hypothesis"]},
                              "refs": {"type": "array", "items": {"type": "string"}}}}
PRIORITY_ITEM_SCHEMA = {"type": "object", "additionalProperties": False, "required": ["statement", "kind", "refs", "priority", "rationale"],
                        "properties": {**ITEM_SCHEMA["properties"],
                                       "priority": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                                       "rationale": {"type": "string"}}}
OUTPUT_SCHEMA = {"type": "object", "additionalProperties": False, "required": SECTIONS,
                 "properties": {s: {"type": "array", "items": PRIORITY_ITEM_SCHEMA if s == "top_priorities" else ITEM_SCHEMA}
                                for s in SECTIONS}}

SYSTEM_PROMPT = """You are a reconnaissance analyst reviewing results from an authorized attack-surface assessment.
You receive an evidence pack: JSON records, each with an "id". Write an analysis using ONLY that evidence.

Rules:
- Every statement must cite one or more ids from the pack in "refs".
- kind="fact": restates something the cited records directly show. kind="hypothesis": your interpretation, a
  possible risk, or a suggestion that needs manual verification. Phrase hypotheses tentatively.
- Never mention a hostname, IP address, port, URL, technology version, endpoint or CVE that is not in the pack.
- Do not claim anything is vulnerable or exploitable. Version-based CVE matches are correlations, not confirmations.
  Exposure is not vulnerability.
- "coverage_gaps": what the collected data does not cover (skipped/failed modules, unresolved hosts, ports not probed).
- "manual_investigation": concrete, non-destructive follow-up checks an authorized tester could perform.
- "top_priorities": the 5-15 items an authorized tester should look at FIRST, ordered most crucial first. Each has
  "priority" (critical/high/medium/low = urgency of manual review, not a confirmed severity) and a one-sentence
  "rationale" explaining why it ranks there (exposure, sensitivity, advisories, recent change, confidence).
- Keep each statement to one or two sentences. Empty arrays are fine when there is nothing to say."""

HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_RE = re.compile(r"(?:\bport\s+|:)(\d{2,5})\b", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)?[a-z0-9]*\b", re.I)
SAFE_WORDS = {"e.g", "i.e", "node.js", "next.js", "vue.js", "nuxt.js", "asp.net"}


def build_evidence_pack(data: dict, max_assets: int = 400) -> dict:
    def rec(a, fields):
        return {"id": a["id"], "type": a["type"], "key": a["key"], "evidence": a.get("evidence"),
                **{f: a["attributes"].get(f) for f in fields if a["attributes"].get(f) not in (None, [], {}, "")}}

    pack = {
        "target": {"name": data["target"]["name"], "root_domains": data["target"]["root_domains"]},
        "scan": {k: data["scan"][k] for k in ("id", "profile", "status", "started_at", "finished_at", "prev_scan_id")},
        "hosts": [rec(h, ["resolved", "ips", "dns", "discovered_via"]) for h in data["hosts"]][:max_assets],
        "ips": [rec(i, ["asn", "asn_name", "provider", "cdn", "ptr"]) for i in data["ips"]],
        "services": [rec(s, ["ip", "port", "service", "product", "version", "hosts"]) for s in data["services"]],
        "web_apps": [rec(a, ["status", "title", "server", "technologies", "missing_security_headers", "cdn", "waf", "is_api", "tls"])
                     for a in data["web_apps"]][:max_assets],
        "endpoints": [rec(e, ["kind", "methods_documented", "api_version", "discovered_via"]) for e in data["endpoints"]][:max_assets],
        "certificates": [rec(c, ["subject_cn", "issuer_cn", "sans", "not_after", "days_remaining", "trusted"]) for c in data["certificates"]],
        "cloud": [rec(c, ["provider", "service", "name", "ownership"]) for c in data["cloud"]],
        "third_parties": [rec(t, ["category", "service"]) for t in data["third_parties"]],
        "findings": [rec(f, ["title", "severity", "category", "subject", "description", "cves", "product", "version"])
                     for f in data["findings"] + data["cve_findings"]],
        "changes": [{"id": c["id"], "category": c["category"], "summary": c["summary"], "previous": c["previous"],
                     "current": c["current"], "asset_id": c["asset_id"], "evidence": c["evidence"]} for c in data["changes"]],
        "module_runs": [{"id": f"module:{r['module']}", "status": r["status"], "reason": r["reason"],
                         "observations": r["observations"]} for r in data["module_runs"]],
        "priorities": [{"id": p["asset"]["id"], "tier": p["tier"], "score": p["score"]} for p in data["priorities"][:30]],
    }
    return pack


class EvidenceGuard:
    def __init__(self, pack: dict):
        self.ids: set[str] = set()
        self._collect_ids(pack)
        self.corpus = json.dumps(pack, default=str).lower()

    def _collect_ids(self, node) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("id", "evidence", "asset_id") and isinstance(v, str):
                    self.ids.add(v)
                self._collect_ids(v)
        elif isinstance(node, list):
            for v in node:
                self._collect_ids(v)

    def check(self, item: dict) -> str | None:
        """Return a rejection reason, or None if the statement is supported."""
        stmt = str(item.get("statement", "")).strip()
        refs = item.get("refs") or []
        if not stmt:
            return "empty statement"
        if item.get("kind") not in ("fact", "hypothesis"):
            return "kind must be fact or hypothesis"
        if not refs:
            return "no evidence references"
        unknown = [r for r in refs if r not in self.ids]
        if unknown:
            return f"unknown evidence reference(s): {unknown[:5]}"
        low = stmt.lower()
        for m in CVE_RE.findall(stmt):
            if m.lower() not in self.corpus:
                return f"CVE not present in collected evidence: {m}"
        for m in IP_RE.findall(stmt):
            if m not in self.corpus:
                return f"IP address not present in collected evidence: {m}"
        for m in HOST_RE.findall(low):
            if m in SAFE_WORDS or VERSION_RE.fullmatch(m):
                continue
            if m not in self.corpus:
                return f"hostname not present in collected evidence: {m}"
        for m in PORT_RE.findall(stmt):
            if f'"port": {m}' not in self.corpus and f":{m}" not in self.corpus:
                return f"port not present in collected evidence: {m}"
        return None

    def filter(self, result: dict) -> tuple[dict, list[dict]]:
        clean, rejected = {}, []
        for sec in SECTIONS:
            clean[sec] = []
            for item in result.get(sec, []) or []:
                reason = self.check(item) if isinstance(item, dict) else "malformed item"
                if reason:
                    rejected.append({"section": sec, "item": item, "reason": reason})
                else:
                    entry = {"statement": item["statement"].strip(), "kind": item["kind"], "refs": item["refs"]}
                    if sec == "top_priorities":
                        rationale = str(item.get("rationale", "")).strip()
                        why = self.check({"statement": rationale, "kind": item["kind"], "refs": item["refs"]}) if rationale else None
                        if why:
                            rejected.append({"section": sec, "item": item, "reason": f"rationale: {why}"})
                            continue
                        entry["priority"] = item.get("priority") if item.get("priority") in ("critical", "high", "medium", "low") else "medium"
                        entry["rationale"] = rationale
                    clean[sec].append(entry)
        return clean, rejected


class Provider(Protocol):
    name: str
    model: str

    def analyze(self, pack: dict) -> dict: ...


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str = "claude-opus-5-5", effort: str = "high", api_key: str | None = None):
        self.model = model or "claude-opus-5-5"
        self.effort = effort or "high"
        self.api_key = api_key

    def analyze(self, pack: dict) -> dict:
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key) if self.api_key else anthropic.Anthropic()
        response = client.beta.messages.create(
            model=self.model,
            max_tokens=16000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            system=SYSTEM_PROMPT,
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}},
            messages=[{"role": "user", "content": "Evidence pack:\n" + json.dumps(pack, default=str)}],
        )
        if response.stop_reason == "refusal":
            raise RuntimeError(f"model declined the request: {getattr(response, 'stop_details', None)}")
        if response.stop_reason == "max_tokens":
            raise RuntimeError("response truncated (max_tokens)")
        text = "".join(b.text for b in response.content if getattr(b, "type", "") == "text")
        self.model = getattr(response, "model", self.model)
        return json.loads(text)


class OpenAICompatibleProvider:
    """OpenAI Chat Completions API, or any server implementing it (Ollama, LM Studio, vLLM, OpenRouter, ...)."""

    def __init__(self, base_url: str, model: str, api_key: str | None = None, name: str = "openai", timeout: float = 600):
        if not model:
            raise ValueError("a model name is required for this provider")
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.model, self.api_key, self.name, self.timeout = model, api_key, name, timeout

    def analyze(self, pack: dict) -> dict:
        import httpx

        schema_hint = json.dumps(OUTPUT_SCHEMA)
        body = {"model": self.model, "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": SYSTEM_PROMPT + "\n\nReturn ONLY a JSON object matching this JSON Schema:\n" + schema_hint},
                             {"role": "user", "content": "Evidence pack:\n" + json.dumps(pack, default=str)}]}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        r = httpx.post(f"{self.base_url}/chat/completions", json=body, headers=headers, timeout=self.timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
        data = r.json()
        choice = (data.get("choices") or [{}])[0]
        if choice.get("finish_reason") == "length":
            raise RuntimeError("response truncated (max tokens)")
        content = (choice.get("message") or {}).get("content") or ""
        self.model = data.get("model", self.model)
        return _parse_json_object(content)


def _parse_json_object(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    try:
        return json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start:end + 1])
        raise


class HeuristicProvider:
    """Deterministic rule-based analyst used offline or as a fallback. Every item cites its source records."""

    name = "heuristic"
    model = "rules-v1"

    def analyze(self, pack: dict) -> dict:
        out = {s: [] for s in SECTIONS}
        hosts, apps, findings = pack["hosts"], pack["web_apps"], pack["findings"]
        tier_prio = {"P1": "high", "P2": "medium", "P3": "low", "P4": "low"}
        ranked = []
        for f in findings:
            if f.get("severity") in ("high", "critical", "medium") and f.get("category") != "cve":
                ranked.append((0 if f.get("severity") in ("high", "critical") else 1, {
                    "kind": "fact", "refs": [f["id"]] + ([f["evidence"]] if f.get("evidence") else []),
                    "priority": "high" if f.get("severity") in ("high", "critical") else "medium",
                    "statement": f"{f.get('title')} on {f.get('subject')}.",
                    "rationale": f"Observation rated {f.get('severity')} ({f.get('category')}); verify manually."}))
        for p in pack["priorities"][:8]:
            a = next((x for x in apps + pack["services"] + hosts if x["id"] == p["id"]), None)
            if a:
                ranked.append((1 if p["tier"] == "P1" else 2, {
                    "kind": "hypothesis", "refs": [a["id"]], "priority": tier_prio.get(p["tier"], "low"),
                    "statement": f"Review {a['key']} early (prioritisation {p['tier']}, score {p['score']}).",
                    "rationale": f"Ranked {p['tier']} from exposure, environment, advisory and change factors."}))
        for c in pack["changes"]:
            if c["category"] in ("new_open_port", "new_subdomain", "new_web_application"):
                ranked.append((2, {"kind": "fact", "refs": [c["id"]] + ([c["asset_id"]] if c.get("asset_id") else []),
                                   "priority": "medium", "statement": c["summary"],
                                   "rationale": "Newly exposed since the previous scan."}))
        out["top_priorities"] = [item for _, item in sorted(ranked, key=lambda x: x[0])][:15]
        resolved = [h for h in hosts if h.get("resolved")]
        out["executive_summary"].append({"kind": "fact", "refs": [h["id"] for h in hosts][:20] or [pack["scan"]["id"]],
                                         "statement": f"{len(hosts)} hostnames were catalogued for {pack['target']['name']}, "
                                                      f"{len(resolved)} of which resolved, with {len(apps)} web applications observed."})
        ip_hosts = {}
        for h in resolved:
            for ip in h.get("ips", []):
                ip_hosts.setdefault(ip, []).append(h)
        for ip, hs in ip_hosts.items():
            if len(hs) > 1:
                ip_rec = next((i for i in pack["ips"] if i["key"] == ip), None)
                refs = [h["id"] for h in hs] + ([ip_rec["id"]] if ip_rec else [])
                out["asset_relationships"].append({"kind": "fact", "refs": refs, "statement":
                    f"{len(hs)} hostnames ({', '.join(h['key'] for h in hs[:6])}) resolve to the shared address {ip}; "
                    "they remain separate assets because sharing an IP does not imply they are the same application."})
        techs = {}
        for a in apps:
            for name, ver in (a.get("technologies") or {}).items():
                techs.setdefault(name, []).append((a, ver))
        for name, uses in sorted(techs.items(), key=lambda kv: -len(kv[1]))[:12]:
            versions = sorted({v for _, v in uses if v})
            out["technology_stack"].append({"kind": "fact", "refs": [a["id"] for a, _ in uses], "statement":
                f"{name}{' ' + '/'.join(versions) if versions else ''} identified on {len(uses)} web application(s)."})
        for p in pack["priorities"][:5]:
            a = next((x for x in apps + pack["services"] + hosts if x["id"] == p["id"]), None)
            if a:
                out["interesting_assets"].append({"kind": "hypothesis", "refs": [a["id"]], "statement":
                    f"{a['key']} ranks {p['tier']} ({p['score']}) in the prioritisation and may merit early manual review."})
        for c in pack["changes"][:15]:
            if c["category"] in ("new_subdomain", "new_open_port", "certificate_changed", "tech_version_changed",
                                 "security_headers_changed", "removed_subdomain", "new_web_application"):
                out["unusual_changes"].append({"kind": "fact", "refs": [c["id"]] + ([c["asset_id"]] if c.get("asset_id") else []),
                                               "statement": c["summary"]})
        for f in findings:
            if f.get("category") == "cve":
                out["cve_intelligence"].append({"kind": "hypothesis", "refs": [f["id"]] + ([f["evidence"]] if f.get("evidence") else []),
                    "statement": f"{f.get('product')} {f.get('version')} on {f.get('subject')} falls in the documented affected "
                                 f"range of {', '.join(f.get('cves') or [])}; the actual patch level needs verification."})
            elif f.get("severity") in ("medium", "high", "critical"):
                out["security_observations"].append({"kind": "fact", "refs": [f["id"]] + ([f["evidence"]] if f.get("evidence") else []),
                    "statement": f"{f.get('title')} on {f.get('subject')}."})
        for a in apps:
            title = (a.get("title") or "").lower()
            if any(k in title for k in ("sign in", "login", "admin", "staging", "dev")):
                out["manual_investigation"].append({"kind": "hypothesis", "refs": [a["id"]] + ([a["evidence"]] if a.get("evidence") else []),
                    "statement": f"Review whether {a['key']} (page title '{a.get('title')}') is intended to be reachable "
                                 "and how access is controlled."})
        for e in pack["endpoints"]:
            if e.get("kind") == "openapi":
                out["manual_investigation"].append({"kind": "hypothesis", "refs": [e["id"]],
                    "statement": f"The API specification at {e['key']} documents the API surface; compare documented operations "
                                 "with the authorised test plan before any further testing."})
        for r in pack["module_runs"]:
            if r["status"] in ("skipped", "failed") and "#" not in r["id"]:
                out["coverage_gaps"].append({"kind": "fact", "refs": [r["id"]],
                                             "statement": f"{r['id'].split(':', 1)[1]} {r['status']}: {r.get('reason')}"})
        unresolved = [h for h in hosts if not h.get("resolved")]
        if unresolved:
            out["coverage_gaps"].append({"kind": "fact", "refs": [h["id"] for h in unresolved], "statement":
                f"{len(unresolved)} discovered hostname(s) did not resolve and were not probed: "
                f"{', '.join(h['key'] for h in unresolved[:8])}."})
        return out


def get_provider(cfg, provider: str | None = None, overrides: dict | None = None) -> Provider:
    """Provider from dashboard settings (settings.json) / config, optionally overridden per request."""
    from ..settings import PROVIDER_INFO, load_settings, resolve_key

    ai = {**load_settings(cfg)["ai"], **{k: v for k, v in (overrides or {}).items() if v}}
    if provider:
        ai["provider"] = provider
    name = ai["provider"]
    if name == "heuristic":
        return HeuristicProvider()
    key = resolve_key(ai)
    if name == "anthropic":
        return AnthropicProvider(ai.get("model") or PROVIDER_INFO["anthropic"]["default_model"], ai.get("effort"), key)
    if name in ("openai", "openai_compatible"):
        if name == "openai" and not key:
            raise ValueError("OpenAI requires an API key (settings or OPENAI_API_KEY)")
        base = ai.get("base_url") or PROVIDER_INFO[name]["default_base_url"]
        return OpenAICompatibleProvider(base, ai.get("model"), key, name=name)
    raise ValueError(f"unknown provider {name}")


def ai_bundle(cfg, db: Database, scan_id: str) -> dict:
    """Everything needed to run the analysis in any AI chat (ChatGPT, Claude.ai, ...) by copy/paste."""
    with db.session() as s:
        data = build_report_data(s, scan_id)
    pack = build_evidence_pack(data, int(cfg.get("ai.max_assets", 400)))
    prompt = (SYSTEM_PROMPT + "\n\nReturn ONLY a JSON object matching this JSON Schema:\n" + json.dumps(OUTPUT_SCHEMA)
              + "\n\nEvidence pack:\n" + json.dumps(pack, default=str))
    return {"scan_id": scan_id, "target": data["target"]["name"], "system_prompt": SYSTEM_PROMPT,
            "output_schema": OUTPUT_SCHEMA, "evidence_pack": pack, "prompt": prompt,
            "instructions": "Paste `prompt` into the AI chat of your choice. To keep the evidence guard, import the JSON "
                            "answer back with POST /api/scans/{id}/ai-import (dashboard: AI analysis -> Import answer)."}


def import_analysis(cfg, db: Database, scan_id: str, raw: dict | str, provider_label: str = "manual import") -> str:
    """Run an externally produced answer through the evidence guard and store it."""
    with db.session() as s:
        data = build_report_data(s, scan_id)
    pack = build_evidence_pack(data, int(cfg.get("ai.max_assets", 400)))
    result = _parse_json_object(raw) if isinstance(raw, str) else raw
    clean, rejected = EvidenceGuard(pack).filter(result)
    with db.session() as s:
        row = AIAnalysis(id=new_id("ai"), scan_id=scan_id, provider=provider_label, model="external", status="completed",
                         created_at=utcnow(), result=clean, rejected=rejected)
        s.add(row)
        return row.id


def analyze_scan(cfg, db: Database, scan_id: str, provider: Provider | None = None) -> str:
    provider = provider or get_provider(cfg)
    with db.session() as s:
        data = build_report_data(s, scan_id)
    pack = build_evidence_pack(data, int(cfg.get("ai.max_assets", 400)))
    guard = EvidenceGuard(pack)
    error = None
    try:
        raw = provider.analyze(pack)
        name, model = provider.name, provider.model
    except Exception as exc:
        error = f"{provider.name} failed: {type(exc).__name__}: {exc}"
        fallback = HeuristicProvider()
        raw = fallback.analyze(pack)
        name, model = f"{fallback.name} (fallback)", fallback.model
    clean, rejected = guard.filter(raw)
    with db.session() as s:
        row = AIAnalysis(id=new_id("ai"), scan_id=scan_id, provider=name, model=model,
                         status="completed" if not error else "fallback", created_at=utcnow(),
                         result=clean, rejected=rejected, error=error)
        s.add(row)
        return row.id
