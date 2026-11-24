"""TLS certificate inspection (built-in ssl + cryptography, or tlsx)."""
from __future__ import annotations

import json
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..core.module import Module, SkipModule, register
from ..core.observation import Obs, Rel
from ..util import normalize_host
from .common import finding


def parse_certificate(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)

    def name_attr(name, oid):
        vals = name.get_attributes_for_oid(oid)
        return vals[0].value if vals else None

    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    pub = cert.public_key()
    key_type, key_bits = type(pub).__name__.replace("_", ""), None
    if isinstance(pub, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type, key_bits = f"EC ({pub.curve.name})", pub.curve.key_size
    nb = cert.not_valid_before_utc
    na = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    return {
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "subject_cn": name_attr(cert.subject, NameOID.COMMON_NAME),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_cn": name_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "sans": sorted({normalize_host(s) for s in sans}),
        "serial": format(cert.serial_number, "x"),
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "days_remaining": (na - now).days,
        "expired": na < now,
        "self_signed": cert.issuer == cert.subject,
        "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
        "key_type": key_type,
        "key_bits": key_bits,
    }


def host_matches(host: str, names: list[str]) -> bool:
    for n in names:
        if n == host or (n.startswith("*.") and host.endswith(n[1:]) and host.count(".") == n.count(".")):
            return True
    return False


def grab(ip: str, port: int, sni: str, timeout: float) -> tuple[bytes, dict]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
            meta = {"tls_version": tls.version(), "cipher": tls.cipher()[0] if tls.cipher() else None}
    # second handshake with the system trust store to learn whether the chain validates
    vctx = ssl.create_default_context()
    vctx.check_hostname = False
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=sni):
                meta["trusted"] = True
    except ssl.SSLCertVerificationError as exc:
        meta["trusted"] = False
        meta["trust_error"] = exc.verify_message
    except (OSError, ssl.SSLError) as exc:
        meta["trusted"] = None
        meta["trust_error"] = str(exc)
    return der, meta


@register
class TlsInspect(Module):
    name = "tls_inspect"
    description = "Retrieves and analyses TLS certificates of HTTPS services; discovers names from SANs."
    phase = "fingerprint"
    active = True
    tools = ["tlsx", "sslscan"]
    produces = ["certificate", "finding"]

    def run(self, ctx) -> None:
        apps = [a for a in ctx.live("web_app") if (a.attributes or {}).get("scheme") == "https"
                and ctx.in_filter((a.attributes or {}).get("host"))]
        if not apps:
            raise SkipModule("no HTTPS services discovered")
        timeout = float(ctx.option("tls", "timeout", 6.0))
        warn_days = int(ctx.option("tls", "expiry_warning_days", 30))
        use_sslscan = ctx.option(self.name, "engine", "builtin") == "sslscan" and ctx.tool("sslscan").available
        for app in apps:
            a = app.attributes or {}
            host, ip, port = a.get("host"), a.get("ip"), int(a.get("port") or 443)
            if not ip or not ctx.scope.ip_allowed(ip):
                continue
            if ctx.incremental and not ctx.needs_refresh(app, self.name):
                ctx.mark_skipped_input(host)
                continue
            try:
                ctx.limiter.wait()
                der, meta = grab(ip, port, host, timeout)
            except (OSError, ssl.SSLError) as exc:
                ctx.log.info("tls handshake failed for %s (%s:%s): %s", host, ip, port, exc)
                continue
            info = parse_certificate(der)
            ctx.action("tls handshake %s:%s sni=%s -> %s %s", ip, port, host, meta.get("tls_version"), meta.get("cipher"))
            info.update(meta)
            info["hostname_match"] = host_matches(host, info["sans"] or [info.get("subject_cn") or ""])
            ev = ctx.evidence("certificate", f"TLS certificate presented by {host}:{port}",
                              json.dumps(info, indent=2) + "\n\n" + ssl.DER_cert_to_PEM_cert(der))
            self.emit_certificate(ctx, info, app.key, host, ev, warn_days)
            if use_sslscan:
                self._sslscan(ctx, app.key, host, ip, port)

    def _sslscan(self, ctx, app_key: str, host: str, ip: str, port: int) -> None:
        """Enumerate supported protocols/ciphers with sslscan and flag deprecated/weak ones."""
        try:
            proc = ctx.run_tool("sslscan", ["--no-colour", "--xml=-", "--connect-timeout=8",
                                            f"--sni-name={host}", f"{ip}:{port}"],
                                timeout=90, keep_partial=True, echo=lambda s, l: None)
        except Exception as exc:  # pragma: no cover - environment specific
            ctx.log.info("sslscan failed for %s (%s:%s): %s", host, ip, port, exc)
            return
        protocols, weak = _parse_sslscan(proc.stdout)
        if not protocols and not weak:
            return
        ev = ctx.evidence("tool_output", f"sslscan {host}:{port}", proc.stdout, ".xml")
        ctx.action("sslscan %s:%s sni=%s -> protocols %s", ip, port, host, ",".join(sorted(protocols)) or "none")
        deprecated = sorted(p for p in protocols if p in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"))
        if deprecated:
            finding(ctx, "tls.deprecated_protocol", app_key,
                    f"Deprecated TLS/SSL protocol{'s' if len(deprecated) > 1 else ''} enabled: {', '.join(deprecated)}",
                    "medium", f"{host}:{port} negotiates {', '.join(deprecated)}, which is deprecated and considered insecure.",
                    ev, "Disable legacy protocols; serve TLS 1.2+ only.", category="tls", subject_type="web_app",
                    extra={"protocols": sorted(protocols), "subject": f"{host}:{port}"})
        if weak:
            finding(ctx, "tls.weak_cipher", app_key, f"Weak TLS cipher(s) accepted ({len(weak)})", "low",
                    f"{host}:{port} accepts cipher(s) considered weak: {', '.join(weak[:8])}"
                    + (" …" if len(weak) > 8 else ""), ev,
                    "Restrict the cipher suite to strong AEAD ciphers.", category="tls", subject_type="web_app",
                    extra={"weak_ciphers": weak[:40], "subject": f"{host}:{port}"})

    def emit_certificate(self, ctx, info: dict, app_key: str, host: str, ev: str, warn_days: int) -> None:
        fp = info["fingerprint_sha256"]
        in_scope_sans = [s for s in info["sans"] if ctx.scope.host_in_scope(s)]
        cert_attrs = {k: v for k, v in info.items() if k not in ("tls_version", "cipher", "trusted", "trust_error", "hostname_match")}
        cert_attrs["sans_out_of_scope_count"] = len(info["sans"]) - len(in_scope_sans)
        cert_attrs["trusted"] = info.get("trusted")
        rels = []
        for san in in_scope_sans:
            rels.append(Rel("covers", "subdomain", san, confirmed=(san == host),
                            target_attrs={"+discovered_via": ["tls_san"]}))
        ctx.emit(Obs("certificate", fp, cert_attrs, display=f"{info.get('subject_cn') or fp[:16]} ({fp[:12]})",
                     evidence_id=ev, relations=rels))
        ctx.emit(Obs("web_app", app_key, {"tls": {"fingerprint_sha256": fp, "version": info.get("tls_version"),
                                                  "cipher": info.get("cipher"), "trusted": info.get("trusted"),
                                                  "hostname_match": info.get("hostname_match"),
                                                  "not_after": info.get("not_after"),
                                                  "issuer_cn": info.get("issuer_cn")}},
                     relations=[Rel("presents", "certificate", fp, confirmed=True)]))
        for san in in_scope_sans:
            if san != host:
                root = ctx.scope.root_for(san)
                rel = [Rel("has_subdomain", "domain", root, reverse=True)] if root and root != san else []
                ctx.emit(Obs("subdomain", san, {"+discovered_via": ["tls_san"]}, source="tls_san", evidence_id=ev,
                             relations=rel))
        subj = f"{host}:{fp[:12]}"
        if info["expired"]:
            finding(ctx, "tls.expired", app_key, "TLS certificate has expired", "medium",
                    f"Certificate {fp[:16]} expired on {info['not_after']}.", ev, "Renew the certificate.",
                    category="tls", subject_type="web_app", extra={"certificate": fp})
        elif info["days_remaining"] <= warn_days:
            finding(ctx, "tls.expiring", app_key, f"TLS certificate expires in {info['days_remaining']} days", "low",
                    f"Certificate {fp[:16]} expires on {info['not_after']}.", ev, "Plan renewal.",
                    category="tls", subject_type="web_app", extra={"certificate": fp, "days_remaining": info["days_remaining"]})
        if info.get("self_signed"):
            finding(ctx, "tls.self_signed", app_key, "Self-signed TLS certificate", "low",
                    f"{subj} presents a self-signed certificate.", ev, "Use a certificate from a trusted CA.",
                    category="tls", subject_type="web_app")
        elif info.get("trusted") is False:
            finding(ctx, "tls.untrusted_chain", app_key, "TLS certificate chain not trusted by system store", "low",
                    f"Verification error: {info.get('trust_error')}", ev,
                    "Serve the full chain from a publicly trusted CA (or confirm this is an internal CA).",
                    category="tls", subject_type="web_app")
        if not info.get("hostname_match"):
            finding(ctx, "tls.hostname_mismatch", app_key, "Certificate does not cover the hostname", "low",
                    f"{host} is not listed in the certificate names {info['sans'][:10]}.", ev,
                    "Issue a certificate covering this hostname.", category="tls", subject_type="web_app")
        if info.get("key_type") == "RSA" and (info.get("key_bits") or 0) < 2048:
            finding(ctx, "tls.weak_key", app_key, "Weak RSA key size", "medium", f"RSA {info['key_bits']} bits.", ev,
                    "Use RSA ≥ 2048 or ECDSA keys.", category="tls", subject_type="web_app")
        if (info.get("signature_algorithm") or "").lower() in ("sha1", "md5"):
            finding(ctx, "tls.weak_signature", app_key, "Weak certificate signature algorithm", "medium",
                    f"Signature algorithm {info['signature_algorithm']}.", ev, "Reissue with SHA-256 or better.",
                    category="tls", subject_type="web_app")
        if info.get("tls_version") in ("TLSv1", "TLSv1.1", "SSLv3"):
            finding(ctx, "tls.legacy_protocol", app_key, f"Legacy protocol negotiated ({info['tls_version']})", "medium",
                    "The server negotiated a deprecated TLS version with a modern client.", ev,
                    "Disable TLS < 1.2.", category="tls", subject_type="web_app")


def parse_tlsx(output: str) -> list[dict]:
    rows = []
    for line in output.splitlines():
        if line.strip():
            r = json.loads(line)
            rows.append({
                "host": r.get("host"), "ip": r.get("ip"), "port": int(r.get("port", 443)),
                "fingerprint_sha256": (r.get("fingerprint_hash") or {}).get("sha256"),
                "subject_cn": r.get("subject_cn"), "sans": sorted({normalize_host(s) for s in r.get("subject_an", []) or []}),
                "issuer_cn": r.get("issuer_cn"), "issuer": r.get("issuer_dn"), "not_before": r.get("not_before"),
                "not_after": r.get("not_after"), "tls_version": r.get("tls_version"), "cipher": r.get("cipher"),
                "self_signed": bool(r.get("self_signed")), "expired": bool(r.get("expired")),
                "hostname_match": not r.get("mismatched", False),
            })
    return rows


def _parse_sslscan(xml_text: str) -> tuple[set[str], list[str]]:
    """Return (enabled protocols, weak cipher names) from sslscan --xml output."""
    import xml.etree.ElementTree as ET

    protocols: set[str] = set()
    weak: list[str] = []
    if not xml_text or "<" not in xml_text:
        return protocols, weak
    try:
        root = ET.fromstring(xml_text[xml_text.index("<"):])
    except ET.ParseError:
        return protocols, weak
    for p in root.iter("protocol"):
        if p.get("enabled") == "1":
            t, v = p.get("type", "tls"), p.get("version", "")
            protocols.add(("SSL" if t == "ssl" else "TLS") + ("v" + v if v else ""))
    for c in root.iter("cipher"):
        name = c.get("cipher", "")
        strength = (c.get("strength") or "").lower()
        bits = c.get("bits")
        try:
            weak_bits = bits is not None and int(bits) < 128
        except ValueError:
            weak_bits = False
        if strength in ("null", "weak", "anonymous") or weak_bits or "RC4" in name or "3DES" in name or "_MD5" in name or "DES-" in name:
            if name and name not in weak:
                weak.append(name)
    return protocols, weak
