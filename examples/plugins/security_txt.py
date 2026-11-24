"""Example ReconForge plugin: records /.well-known/security.txt contact metadata.

Load it without touching the core by adding to the config:

    plugins: ["examples/plugins/security_txt.py"]

and adding `security_txt` to a profile's modules (or `reconforge scan <target> --add security_txt`).
"""
from __future__ import annotations

from reconforge.core.module import Module, SkipModule, register
from reconforge.core.net import HttpFetcher, format_http_evidence
from reconforge.core.observation import Obs, Rel


@register
class SecurityTxt(Module):
    name = "security_txt"
    description = "Fetches /.well-known/security.txt (GET) and records disclosure contacts."
    phase = "content"
    active = True
    produces = ["endpoint"]

    def run(self, ctx) -> None:
        apps = [a for a in ctx.live("web_app") if a.key.startswith("https://")]
        if not apps:
            raise SkipModule("no HTTPS web applications")
        fetcher = HttpFetcher(ctx)
        try:
            for app in apps:
                url = app.key + "/.well-known/security.txt"
                res = fetcher.get(url)
                if res.status != 200 or "contact:" not in res.text.lower():
                    continue
                fields = {}
                for line in res.text.splitlines():
                    if ":" in line and not line.startswith("#"):
                        k, v = line.split(":", 1)
                        fields.setdefault(k.strip().lower(), []).append(v.strip())
                ev = ctx.evidence("http_response", f"security.txt on {app.key}", format_http_evidence(res))
                ctx.emit(Obs("endpoint", url, {"url": url, "kind": "security_txt", "host": app.attributes.get("host"),
                                               "contacts": fields.get("contact", []), "expires": (fields.get("expires") or [None])[0],
                                               "+discovered_via": [self.name]}, evidence_id=ev,
                             relations=[Rel("has_endpoint", "web_app", app.key, confirmed=True, reverse=True)]))
        finally:
            fetcher.close()
