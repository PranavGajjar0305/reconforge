#!/usr/bin/env python3
"""ReconForge controlled lab.

Simulates a small fictional organisation ("Acme", zone `acme.test`, a reserved TLD that
never resolves on the internet) entirely on 127.0.0.1:

  * DNS server            127.0.0.1:5354/udp   authoritative for acme.test (+ PTR)
  * HTTP virtual hosts    127.0.0.1:8080
  * HTTPS virtual hosts   127.0.0.1:8443        per-SNI certificates from a lab CA
  * SSH-like banner       127.0.0.1:2222
  * Search service        127.0.0.1:9200        (phase 2 only — "new open port")
  * Feeds + sinks         127.0.0.1:8099        crt.sh / Wayback CDX / GitHub search emulators,
                                                Slack/Discord/Telegram webhook sinks
  * SMTP sink             127.0.0.1:2525        captures notification e-mails

`--domain example.com` serves the same organisation under another name (every "acme.test" / "Acme"
becomes "example.com" / "Example"); used to produce the README screenshots without real data.

`--phase 1` is the baseline; `--phase 2` introduces changes (new subdomain, removed
subdomain, new endpoints, version change, header change, re-issued certificate, new
port, new third party) so change detection and notifications can be demonstrated.

Nothing here is a real service; all data is synthetic.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import socketserver
import ssl
import sys
import threading
import time
from email import message_from_bytes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
RUNTIME = HERE / "runtime"
LOOP = "127.0.0.1"
PHASE = 1
SRC_DOMAIN = "acme.test"
DOMAIN = SRC_DOMAIN


def _pairs() -> list[tuple[str, str]]:
    brand = DOMAIN.split(".")[0]
    return [(SRC_DOMAIN, DOMAIN), ("ACME", brand.upper()), ("Acme", brand.capitalize()), ("acme", brand)]


def tr(text: str) -> str:
    """Lab names -> the --domain names (identity for the default acme.test)."""
    if DOMAIN == SRC_DOMAIN:
        return text
    for a, b in _pairs():
        text = text.replace(a, b)
    return text


def tr_b(data: bytes) -> bytes:
    if DOMAIN == SRC_DOMAIN:
        return data
    for a, b in _pairs():
        data = data.replace(a.encode(), b.encode())
    return data


def untr(text: str) -> str:
    """Incoming --domain names -> lab names, so the handlers below only ever see acme.test."""
    return text if DOMAIN == SRC_DOMAIN else text.replace(DOMAIN, SRC_DOMAIN)


# --------------------------------------------------------------------------- DNS
def zone(phase: int) -> dict[str, list[tuple[str, str]]]:
    return {tr(k): [(t, tr(v)) for t, v in recs] for k, recs in _zone(phase).items()}


def _zone(phase: int) -> dict[str, list[tuple[str, str]]]:
    z = {
        "acme.test": [("A", LOOP), ("NS", "ns1.acme.test."), ("MX", "10 mail.acme.test."),
                      ("TXT", '"v=spf1 include:_spf.google.com ~all"'), ("TXT", '"google-site-verification=lab-token-0001"'),
                      ("SOA", "ns1.acme.test. hostmaster.acme.test. 2026112101 3600 600 86400 300")],
        "_dmarc.acme.test": [("TXT", '"v=DMARC1; p=none; rua=mailto:dmarc@acme.test"')],
        "www.acme.test": [("CNAME", "acme.test.")],
        "api.acme.test": [("A", LOOP)],
        "dev.acme.test": [("A", LOOP)],
        "mail.acme.test": [("A", LOOP)],
        "ns1.acme.test": [("A", LOOP)],
        "internal-admin.acme.test": [("A", LOOP)],
        "old.acme.test": [("A", LOOP)],
        "assets.acme.test": [("CNAME", "acme-assets-prod.s3.amazonaws.com.")],
        "1.0.0.127.in-addr.arpa": [("PTR", "lab-host.acme.test.")],
        "vpn.acme.test": [("A", LOOP)],              # only discoverable by wordlist brute force
        "staging-api.acme.test": [("A", LOOP)],      # only discoverable by permutation of "api"
        "google._domainkey.acme.test": [("TXT", '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlab"')],
    }
    if phase >= 2:
        z.pop("old.acme.test")
        z["beta.acme.test"] = [("A", LOOP)]
        z["api.acme.test"].append(("TXT", '"v=api-gateway-2"'))
    return z


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            q = dns.message.from_wire(data)
        except Exception:
            return
        resp = dns.message.make_response(q)
        resp.flags |= dns.flags.AA
        z = zone(PHASE)
        for question in q.question:
            name = question.name.to_text().rstrip(".").lower()
            qtype = dns.rdatatype.to_text(question.rdtype)
            self._answer(resp, z, name, qtype, depth=0)
            if not resp.answer and name not in z:
                resp.set_rcode(dns.rcode.NXDOMAIN)
        sock.sendto(resp.to_wire(), self.client_address)

    def _answer(self, resp, z, name, qtype, depth):
        if depth > 5 or name not in z:
            return
        recs = z[name]
        cnames = [v for t, v in recs if t == "CNAME"]
        if cnames and qtype != "CNAME":
            resp.answer.append(dns.rrset.from_text(name + ".", 300, "IN", "CNAME", cnames[0]))
            self._answer(resp, z, cnames[0].rstrip(".").lower(), qtype, depth + 1)
            return
        vals = [v for t, v in recs if t == qtype]
        if vals:
            resp.answer.append(dns.rrset.from_text_list(name + ".", 300, "IN", qtype, vals))


# ------------------------------------------------------------------------ certs
def _key(path: Path):
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), None)
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return k


def ensure_ca(certdir: Path):
    key = _key(certdir / "ca.key")
    crt_path = certdir / "ca.crt"
    if crt_path.exists():
        return key, x509.load_pem_x509_certificate(crt_path.read_bytes())
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "ZZ"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ReconForge Lab"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "ReconForge Lab CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def ensure_leaf(certdir: Path, label: str, sans: list[str], days: int) -> tuple[Path, Path]:
    crt, keyp = certdir / f"{label}.crt", certdir / f"{label}.key"
    if crt.exists() and keyp.exists():
        return crt, keyp
    ca_key, ca = ensure_ca(certdir)
    key = _key(keyp)
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, tr("Acme Lab")),
                                     x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]))
            .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return crt, keyp


def tls_contexts(phase: int) -> dict[str, ssl.SSLContext]:
    certdir = RUNTIME / ("certs" if DOMAIN == SRC_DOMAIN else f"certs-{DOMAIN}")
    certdir.mkdir(parents=True, exist_ok=True)
    specs = {
        "www.acme.test": ("www", ["www.acme.test", "acme.test"], 365),
        "acme.test": ("www", ["www.acme.test", "acme.test"], 365),
        "api.acme.test": ("api-p2" if phase >= 2 else "api", ["api.acme.test", "internal-admin.acme.test"], 200),
        "internal-admin.acme.test": ("internal-admin", ["internal-admin.acme.test"], 10),
    }
    out = {}
    for host, (label, sans, days) in specs.items():
        host, sans = tr(host), [tr(x) for x in sans]
        crt, key = ensure_leaf(certdir, label, sans, days)
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        c.minimum_version = ssl.TLSVersion.TLSv1_2
        c.load_cert_chain(crt, key)
        out[host] = c
    return out


# ---------------------------------------------------------------------- web apps
def page(title: str, body: str, head: str = "") -> bytes:
    return f"<!doctype html><html><head><title>{title}</title>{head}</head><body>{body}</body></html>".encode()


APP_JS = """/* Acme storefront bundle (lab) */
const API = 'https://api.acme.test:8443';
async function boot() {
  const s = await fetch('/api/v1/session');
  const users = await axios.get('https://api.acme.test:8443/v1/users');
  await fetch('https://api.acme.test:8443/v1/orders', { method: 'POST', body: '{}' });
  const ws = new WebSocket('wss://api.acme.test:8443/ws/notifications');
}
const ASSET_BASE = 'https://acme-assets-prod.s3.amazonaws.com/img/';
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"; // AWS documentation example value
//# sourceMappingURL=app.js.map
"""
CHECKOUT_JS = """/* checkout (lab, phase 2) */
const stripe = Stripe('pk_test_lab');
fetch('https://api.acme.test:8443/v2/payments', { method: 'POST' });
"""
JQUERY_JS = "/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */\nwindow.jQuery={};\n"


def openapi(phase: int) -> dict:
    paths = {
        "/v1/users": {"get": {"summary": "List users", "parameters": [{"name": "limit", "in": "query"}, {"name": "offset", "in": "query"}]}},
        "/v1/users/{id}": {"get": {"summary": "Get user"}, "delete": {"summary": "Delete user"}},
        "/v1/orders": {"get": {"summary": "List orders"}, "post": {"summary": "Create order"}},
        "/v1/admin/export": {"get": {"summary": "Export data (admin)"}},
    }
    if phase >= 2:
        paths["/v2/orders"] = {"get": {"summary": "List orders v2"}, "post": {"summary": "Create order v2"}}
        paths["/v2/payments"] = {"post": {"summary": "Create payment"}}
    return {"openapi": "3.0.3", "info": {"title": "Acme Public API", "version": "1.4.2" if phase == 1 else "2.0.0"},
            "servers": [{"url": "https://api.acme.test:8443"}], "paths": paths,
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"},
                                               "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}}}


def vhost_response(host: str, path: str, https: bool, phase: int) -> tuple[int, list[tuple[str, str]], bytes]:
    h = host.split(":")[0].lower()
    path = urlsplit(path).path or "/"
    if h == "acme.test":
        return 301, [("Location", "https://www.acme.test:8443/"), ("Server", "nginx/1.18.0")], b""
    if h == "www.acme.test":
        if not https:
            return 301, [("Location", "https://www.acme.test:8443" + path), ("Server", "nginx/1.18.0")], b""
        server = "nginx/1.18.0" if phase == 1 else "nginx/1.24.0"
        hdrs = [("Server", server), ("Strict-Transport-Security", "max-age=31536000"), ("X-Frame-Options", "SAMEORIGIN"),
                ("X-Content-Type-Options", "nosniff")]
        if phase >= 2:
            hdrs.append(("Content-Security-Policy", "default-src 'self'; script-src 'self' js.stripe.com www.googletagmanager.com"))
        if path == "/":
            scripts = ('<script src="/static/js/jquery-3.4.1.min.js"></script><script src="/static/js/app.js"></script>'
                       '<script async src="https://www.googletagmanager.com/gtag/js?id=G-LAB0001"></script>')
            if phase >= 2:
                scripts += '<script src="https://js.stripe.com/v3/"></script><script src="/static/js/checkout.js"></script>'
            body = page("Acme Corp — Home",
                        '<h1>Acme</h1><a href="/about">About</a> <a href="/blog/">Blog</a> <a href="/contact">Contact</a> '
                        '<a href="https://api.acme.test:8443/docs">API docs</a> <a href="https://twitter.com/acme_lab">Twitter</a>'
                        + ' <a href="/search?q=widgets">Search</a> <a href="/files/annual-report-2025.pdf">Annual report</a>'
                        + scripts, '<meta name="generator" content="WordPress 6.4.2">'
                                   '<meta name="description" content="Acme Corp lab site">'
                                   '<meta property="og:title" content="Acme Corp">'
                                   '<meta property="og:url" content="https://www.acme.test:8443/">'
                                   '<link rel="canonical" href="https://www.acme.test:8443/">'
                                   '<link rel="stylesheet" href="/wp-content/themes/acme/style.css">')
            return 200, hdrs + [("Content-Type", "text/html; charset=utf-8"),
                                ("Set-Cookie", "wp_session=lab123; Path=/; Secure; HttpOnly")], body
        if path == "/robots.txt":
            return 200, hdrs + [("Content-Type", "text/plain")], b"User-agent: *\nDisallow: /wp-admin/\nSitemap: https://www.acme.test:8443/sitemap.xml\n"
        if path == "/.well-known/security.txt":
            return 200, hdrs + [("Content-Type", "text/plain")], (b"Contact: mailto:security@acme.test\n"
                                                                   b"Expires: 2027-12-31T23:59:59Z\nPolicy: https://www.acme.test:8443/security\n")
        if path == "/sitemap.xml":
            return 200, hdrs + [("Content-Type", "application/xml")], (
                b'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                b"<url><loc>https://www.acme.test:8443/</loc></url><url><loc>https://www.acme.test:8443/careers</loc></url>"
                b"<url><loc>https://www.acme.test:8443/account/register</loc></url></urlset>")
        if path == "/favicon.ico":
            return 200, hdrs + [("Content-Type", "image/x-icon")], bytes(range(256)) * 4
        if path == "/static/js/app.js.map":
            return 200, hdrs + [("Content-Type", "application/json")], json.dumps(
                {"version": 3, "file": "app.js", "sources": ["webpack:///src/index.js", "webpack:///src/api/client.js"],
                 "mappings": "AAAA"}).encode()
        if path == "/files/annual-report-2025.pdf":
            return 200, hdrs + [("Content-Type", "application/pdf"), ("Last-Modified", "Tue, 01 Apr 2025 10:00:00 GMT")], b"%PDF-1.4 lab placeholder"
        if path in ("/search", "/careers", "/account/register"):
            return 200, hdrs + [("Content-Type", "text/html")], page(path.strip("/").title(), "<p>lab page</p>")
        if path == "/about":
            return 200, hdrs + [("Content-Type", "text/html")], page("About Acme", '<p>About us</p><a href="/">Home</a>')
        if path == "/blog/":
            return 200, hdrs + [("Content-Type", "text/html")], page("Acme Blog", '<a href="/blog/hello-world">Hello</a>')
        if path == "/blog/hello-world":
            return 200, hdrs + [("Content-Type", "text/html")], page("Hello world", "<p>post</p>")
        if path == "/contact":
            return 200, hdrs + [("Content-Type", "text/html")], page(
                "Contact", '<form action="/contact/submit" method="post"><input name="email"></form>')
        if path == "/static/js/app.js":
            return 200, hdrs + [("Content-Type", "application/javascript")], APP_JS.encode()
        if path == "/static/js/jquery-3.4.1.min.js":
            return 200, hdrs + [("Content-Type", "application/javascript")], JQUERY_JS.encode()
        if path == "/static/js/checkout.js" and phase >= 2:
            return 200, hdrs + [("Content-Type", "application/javascript")], CHECKOUT_JS.encode()
        return 404, hdrs + [("Content-Type", "text/html")], page("Not found", "404")
    if h == "api.acme.test" and https:
        hdrs = [("Server", "uvicorn"), ("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")]
        if path == "/":
            return 200, hdrs + [("Content-Type", "application/json")], json.dumps(
                {"service": "acme-api", "version": "1.4.2" if phase == 1 else "2.0.0"}).encode()
        if path == "/openapi.json":
            return 200, hdrs + [("Content-Type", "application/json")], json.dumps(openapi(phase)).encode()
        if path == "/docs":
            return 200, hdrs + [("Content-Type", "text/html")], page(
                "Acme API - Swagger UI", '<div id="swagger-ui"></div><script src="/static/swagger-ui-bundle.js"></script>')
        if path == "/graphql":
            return 400, hdrs + [("Content-Type", "application/json")], b'{"errors":[{"message":"Must provide query string."}]}'
        return 404, hdrs + [("Content-Type", "application/json")], b'{"detail":"Not Found"}'
    if h == "dev.acme.test" and not https:
        hdrs = [("Server", "Apache/2.4.49 (Unix)"), ("X-Powered-By", "PHP/7.4.3"), ("Content-Type", "text/html"),
                ("Set-Cookie", "PHPSESSID=labdev42; path=/")]
        if path == "/":
            return 200, hdrs, page("Acme Dev Portal - staging build",
                                   "<p>debug mode enabled</p><a href='/status'>status</a>")
        if path == "/status":
            return 200, hdrs, page("Status", "<pre>ok</pre>")
        if path == "/.git/HEAD":
            return 200, [("Server", "Apache/2.4.49 (Unix)"), ("Content-Type", "text/plain")], b"ref: refs/heads/main\n"
        if path == "/.env":
            return 200, [("Server", "Apache/2.4.49 (Unix)"), ("Content-Type", "text/plain")], b"APP_ENV=staging\nDB_PASSWORD=lab-not-a-secret\n"
        return 404, hdrs, page("Not found", "404")
    if h == "internal-admin.acme.test" and https:
        hdrs = [("Server", "nginx/1.18.0"), ("Content-Type", "text/html"), ("X-Frame-Options", "DENY"),
                ("Strict-Transport-Security", "max-age=600"), ("X-Jenkins", "2.401.1")]
        if path == "/":
            return 200, hdrs, page("Admin Console - Sign in",
                                   '<form action="/login" method="post"><input name="user"><input type="password" name="pw"></form>'
                                   '<a href="/account/forgot-password">Forgot password?</a> '
                                   '<a href="https://acme-lab.okta.com/app/acme_admin/sso/saml">Sign in with SSO</a>')
        return 404, hdrs, page("Not found", "404")
    if h == "staging-api.acme.test" and not https:
        return 200, [("Server", "nginx/1.18.0"), ("Content-Type", "text/html")], page("Welcome to nginx!", "<h1>Welcome to nginx!</h1>")
    if h == "old.acme.test" and not https and phase == 1:
        return 200, [("Server", "Apache/2.2.15 (CentOS)"), ("Content-Type", "text/html")], page("Legacy site", "<p>old</p>")
    if h == "beta.acme.test" and not https and phase >= 2:
        return 200, [("X-Powered-By", "Next.js 14.1.0"), ("Content-Type", "text/html")], page(
            "Acme Beta", '<div id="__next"></div><script src="/_next/static/chunks/main.js"></script>')
    return 404, [("Content-Type", "text/plain")], b"no such virtual host"


class VHostHandler(BaseHTTPRequestHandler):
    server_version = "lab"
    sys_version = ""
    https = False

    def log_message(self, fmt, *args):
        with open(RUNTIME / "access.log", "a") as fh:
            fh.write(f"{time.strftime('%H:%M:%S')} {self.command} {self.headers.get('Host')} {self.path} {fmt % args}\n")

    def do_GET(self):
        status, headers, body = vhost_response(untr(self.headers.get("Host", "")), untr(self.path), self.https, PHASE)
        headers, body = [(k, tr(v)) for k, v in headers], tr_b(body)
        self.send_response_only(status)
        self.log_request(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_HEAD = do_GET

    def do_POST(self):  # the scanner must never send these; record if it does
        with open(RUNTIME / "unexpected_methods.log", "a") as fh:
            fh.write(f"{self.command} {self.headers.get('Host')} {self.path}\n")
        self.send_response(405)
        self.end_headers()

    do_PUT = do_DELETE = do_PATCH = do_POST


class HTTPSVHostHandler(VHostHandler):
    https = True


class SearchHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps({"name": "lab-node", "cluster_name": "acme-search", "version": {"number": "7.10.2"},
                           "tagline": "You Know, for Search"}).encode()
        body = tr_b(body)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------- feeds & sinks
def ct_rows(phase: int) -> list[dict]:
    names = ["acme.test", "www.acme.test", "api.acme.test", "dev.acme.test", "mail.acme.test", "assets.acme.test",
             "*.acme.test", "old.acme.test"]
    if phase >= 2:
        names = [n for n in names if n != "old.acme.test"] + ["beta.acme.test"]
    return [{"id": 9000 + i, "issuer_name": "C=ZZ, O=ReconForge Lab, CN=ReconForge Lab CA", "common_name": n,
             "name_value": n, "not_before": "2026-01-01T00:00:00", "not_after": "2027-01-01T00:00:00",
             "entry_timestamp": "2026-01-01T00:00:00"} for i, n in enumerate(names)]


def cdx_rows() -> list[list[str]]:
    return [["original", "timestamp", "statuscode", "mimetype"],
            ["https://www.acme.test:8443/", "20240101000000", "200", "text/html"],
            ["https://www.acme.test:8443/old-promo?ref=x&utm=y", "20230105000000", "200", "text/html"],
            ["https://www.acme.test:8443/api/v1/legacy-report", "20230310000000", "200", "application/json"],
            ["http://dev.acme.test:8080/phpinfo.php", "20220715000000", "200", "text/html"]]


def github_result() -> dict:
    return {"total_count": 1, "items": [{
        "name": "hosts.yml", "path": "deploy/hosts.yml", "html_url": "https://github.example/acme-lab/infra-config/blob/main/deploy/hosts.yml",
        "repository": {"full_name": "acme-lab/infra-config"},
        "text_matches": [{"fragment": "ci: jenkins.acme.test\napi: api.acme.test\npassword: hunter2-lab"}]}]}


class FeedHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _fake_llm(self, payload: str):
        req = json.loads(payload)
        user = next(m["content"] for m in req["messages"] if m["role"] == "user")
        pack = json.loads(user.split("Evidence pack:\n", 1)[1])
        answer = _fake_llm_answer(pack)
        self._json({"id": "lab-1", "object": "chat.completion", "model": f"lab-stub/{req.get('model')}",
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": json.dumps(answer)}}]})

    def _json(self, obj, status=200):
        body = tr_b(json.dumps(obj).encode())
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlsplit(untr(self.path))
        q = parse_qs(u.query)
        if u.path == "/" and q.get("output") == ["json"]:
            return self._json(ct_rows(PHASE))
        if u.path == "/cdx/search/cdx":
            return self._json(cdx_rows())
        if u.path == "/search/code":
            return self._json(github_result())
        if u.path == "/otx/api/v1/indicators/domain/acme.test/passive_dns":
            return self._json({"passive_dns": [{"hostname": "shop.acme.test", "address": "198.51.100.7"},
                                               {"hostname": "api.acme.test", "address": LOOP}]})
        if u.path == "/hackertarget/hostsearch/":
            body = tr_b(f"www.acme.test,{LOOP}\nmail.acme.test,{LOOP}\n".encode())
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if u.path == "/commoncrawl/collinfo.json":
            return self._json([{"id": "CC-MAIN-LAB", "cdx-api": "http://127.0.0.1:8099/commoncrawl/cc-index"}])
        if u.path == "/commoncrawl/cc-index":
            lines = [json.dumps({"url": "https://www.acme.test:8443/press/2024-launch?utm_source=x"}),
                     json.dumps({"url": "https://www.acme.test:8443/downloads/brochure.pdf"})]
            body = tr_b("\n".join(lines).encode())
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if u.path.startswith("/internetdb/"):
            return self._json({"ip": u.path.rsplit("/", 1)[1], "ports": [2222, 3306, 8080, 8443], "hostnames": ["lab-host.acme.test"],
                               "cpes": ["cpe:/a:nginx:nginx:1.18.0"], "vulns": [], "tags": ["lab"]})
        if u.path.startswith("/rdap/ip/"):
            return self._json({"name": "ACME-LAB-LOOPBACK", "handle": "NET-LAB-1", "startAddress": "127.0.0.0",
                               "endAddress": "127.255.255.255", "country": "ZZ", "type": "lab", "entities": [{"handle": "ACME-LAB"}]})
        if u.path.startswith("/rdap/domain/"):
            return self._json({"status": ["active"], "events": [{"eventAction": "registration", "eventDate": "2019-03-01T00:00:00Z"},
                                                                {"eventAction": "expiration", "eventDate": "2027-03-01T00:00:00Z"}],
                               "nameservers": [{"ldhName": "ns1.acme.test"}], "secureDNS": {"delegationSigned": False},
                               "entities": [{"roles": ["registrar"], "handle": "LAB-REG",
                                             "vcardArray": ["vcard", [["fn", {}, "text", "Lab Registrar Inc."]]]}]})
        if u.path == "/notifications":
            p = RUNTIME / "notifications.jsonl"
            return self._json([json.loads(l) for l in p.read_text().splitlines()] if p.exists() else [])
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(n).decode("utf-8", "replace")
        if self.path.startswith("/llm/v1/chat/completions"):
            return self._fake_llm(payload)
        channel = "slack" if "/hooks/slack" in self.path else "discord" if "/hooks/discord" in self.path else \
            "telegram" if "/sendMessage" in self.path else "unknown"
        with open(RUNTIME / "notifications.jsonl", "a") as fh:
            fh.write(json.dumps({"channel": channel, "path": self.path.split("/bot")[0], "received": time.time(),
                                 "payload": payload}) + "\n")
        self._json({"ok": True, "result": {"message_id": 1}} if channel == "telegram" else {"ok": True},
                   204 if channel == "discord" else 200)


def _fake_llm_answer(pack: dict) -> dict:
    """Lab stand-in for an OpenAI-compatible model: builds an answer from the evidence pack, plus one
    deliberately fabricated statement so the evidence guard can be seen rejecting it."""
    findings = sorted(pack.get("findings", []), key=lambda f: {"high": 0, "medium": 1, "low": 2}.get(f.get("severity"), 3))
    top = [{"statement": f"{f.get('title')} on {f.get('subject')}.", "kind": "fact", "refs": [f["id"]],
            "priority": "high" if f.get("severity") == "medium" else "medium",
            "rationale": f"{f.get('category')} observation rated {f.get('severity')}."} for f in findings[:4]]
    top.append({"statement": "secret-admin.acme.test exposes RDP on port 3389.", "kind": "fact",
                "refs": [findings[0]["id"]] if findings else [], "priority": "critical", "rationale": "fabricated by the stub"})
    hosts = pack.get("hosts", [])
    out = {k: [] for k in ("executive_summary", "asset_relationships", "technology_stack", "interesting_assets",
                           "unusual_changes", "security_observations", "cve_intelligence", "manual_investigation", "coverage_gaps")}
    out["top_priorities"] = top
    if hosts:
        out["executive_summary"].append({"statement": f"{len(hosts)} hostnames were analysed for {pack['target']['name']}.",
                                         "kind": "fact", "refs": [hosts[0]["id"]]})
    return out


class SMTPSink(socketserver.StreamRequestHandler):
    def handle(self):
        w = lambda s: self.wfile.write((s + "\r\n").encode())
        w("220 lab-smtp ESMTP ReconForge lab sink")
        data_mode, lines = False, []
        while True:
            line = self.rfile.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if data_mode:
                if text == ".":
                    data_mode = False
                    mail_dir = RUNTIME / "mail"
                    mail_dir.mkdir(exist_ok=True)
                    raw = "\r\n".join(lines).encode()
                    (mail_dir / f"{int(time.time() * 1000)}.eml").write_bytes(raw)
                    with open(RUNTIME / "notifications.jsonl", "a") as fh:
                        msg = message_from_bytes(raw)
                        fh.write(json.dumps({"channel": "email", "subject": msg.get("Subject"), "to": msg.get("To"),
                                             "received": time.time()}) + "\n")
                    lines = []
                    w("250 OK queued")
                else:
                    lines.append(text[1:] if text.startswith("..") else text)
                continue
            cmd = text.upper()
            if cmd.startswith(("EHLO", "HELO")):
                w("250-lab-smtp\r\n250 OK")
            elif cmd.startswith("DATA"):
                data_mode = True
                w("354 End data with <CR><LF>.<CR><LF>")
            elif cmd.startswith("QUIT"):
                w("221 bye")
                break
            else:
                w("250 OK")


class SSHBanner(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        time.sleep(0.2)


class ReusableTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ReusableUDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class ReusableHTTP(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def main():
    global PHASE, DOMAIN
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phase", type=int, default=1, choices=[1, 2])
    ap.add_argument("--reset-sinks", action="store_true", help="clear captured notifications")
    ap.add_argument("--domain", default=SRC_DOMAIN, help="serve the lab organisation under this domain (default acme.test)")
    args = ap.parse_args()
    PHASE = args.phase
    DOMAIN = args.domain.strip().lower().rstrip(".")
    RUNTIME.mkdir(parents=True, exist_ok=True)
    if args.reset_sinks:
        (RUNTIME / "notifications.jsonl").unlink(missing_ok=True)
    contexts = tls_contexts(PHASE)
    default_ctx = contexts[tr("www.acme.test")]

    def sni(sslsock, server_name, _ctx):
        if server_name and server_name.lower() in contexts:
            sslsock.context = contexts[server_name.lower()]

    default_ctx.sni_callback = sni
    servers = [serve(ReusableUDP((LOOP, 5354), DNSHandler)), serve(ReusableHTTP((LOOP, 8080), VHostHandler))]
    https = ReusableHTTP((LOOP, 8443), HTTPSVHostHandler)
    https.socket = default_ctx.wrap_socket(https.socket, server_side=True)
    servers += [serve(https), serve(ReusableTCP((LOOP, 2222), SSHBanner)), serve(ReusableHTTP((LOOP, 8099), FeedHandler)),
                serve(ReusableTCP((LOOP, 2525), SMTPSink))]
    if PHASE >= 2:
        servers.append(serve(ReusableHTTP((LOOP, 9200), SearchHandler)))
    (RUNTIME / "phase").write_text(str(PHASE))
    print(f"ReconForge lab running (phase {PHASE}, {DOMAIN}) on {LOOP}: dns:5354 http:8080 https:8443 ssh:2222 feeds:8099 smtp:2525"
          + (" search:9200" if PHASE >= 2 else ""), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()


if __name__ == "__main__":
    sys.exit(main())
