"""Screenshot collection using a local headless Chrome/Chromium.

Chrome is pinned to the scope-checked IP with --host-resolver-rules and every other
hostname is mapped to NOTFOUND, so the browser cannot reach unapproved addresses or
load third-party resources. Pages are loaded with a
throw-away profile.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from ..core.module import Module, SkipModule, register
from ..core.observation import Obs

CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome",
]


def phash(path) -> str | None:
    """64-bit difference hash; similar pages have small Hamming distance. Needs Pillow."""
    try:
        from PIL import Image
    except ImportError:
        return None
    from PIL import ImageOps

    img = Image.open(path).convert("L")
    bbox = ImageOps.invert(img).point(lambda v: 255 if v > 24 else 0).getbbox()  # area with visible content
    if bbox is None:
        return "0000000000000000"
    img = img.crop(bbox).resize((9, 8))
    px = list(img.get_flattened_data() if hasattr(img, "get_flattened_data") else img.getdata())
    bits = "".join("1" if px[r * 9 + c] > px[r * 9 + c + 1] else "0" for r in range(8) for c in range(8))
    return f"{int(bits, 2):016x}"


def hamming(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def group_by_similarity(items: list[tuple[str, str]], threshold: int = 6) -> list[list[str]]:
    """items: [(key, phash)] -> groups of keys whose screenshots look alike."""
    groups: list[tuple[str, list[str]]] = []
    for key, h in items:
        for rep, members in groups:
            if hamming(rep, h) <= threshold:
                members.append(key)
                break
        else:
            groups.append((h, [key]))
    return [m for _, m in groups]


def find_chrome(configured: str | None) -> str | None:
    if configured and configured != "auto":
        return configured if Path(configured).exists() or shutil.which(configured) else None
    for c in CANDIDATES:
        if Path(c).exists():
            return c
        if shutil.which(c):
            return shutil.which(c)
    return None


@register
class Screenshots(Module):
    name = "screenshots"
    description = "Captures screenshots of discovered web applications with headless Chrome."
    phase = "capture"
    active = True
    produces = []

    def run(self, ctx) -> None:
        chrome = find_chrome(ctx.option("screenshots", "chrome_path", "auto"))
        if not chrome:
            raise SkipModule("no Chrome/Chromium binary found (set screenshots.chrome_path)")
        apps = [a for a in ctx.live("web_app") if ctx.in_filter((a.attributes or {}).get("host"))
                and (a.attributes or {}).get("ip") and ctx.scope.ip_allowed((a.attributes or {}).get("ip"))]
        if not apps:
            raise SkipModule("no web applications")
        timeout = int(ctx.option("screenshots", "timeout", 25))
        size = ctx.option("screenshots", "window_size", "1280,800")
        ctx.tools_used.add("chrome-headless")
        for app in apps:
            a = app.attributes or {}
            if ctx.incremental and not ctx.needs_refresh(app, self.name):
                ctx.mark_skipped_input(a.get("host", app.key))
                continue
            out = ctx.scan_path("screenshots", f"{app.id}.png")
            with tempfile.TemporaryDirectory(prefix="chrome-", dir=ctx.work_dir) as profile:  # target cache stays in data/work
                cmd = [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
                       "--no-default-browser-check", "--disable-extensions", "--disable-background-networking",
                       "--ignore-certificate-errors", f"--user-data-dir={profile}", f"--window-size={size}",
                       f"--host-resolver-rules=MAP {a['host']} {a['ip']}, MAP * ~NOTFOUND",
                       f"--user-agent={ctx.config.get('network.user_agent')}", f"--screenshot={out}", app.key + "/"]
                ctx.limiter.wait()
                ctx.action("exec: %s", " ".join(cmd[:1] + ["--headless=new", f"--host-resolver-rules=MAP {a['host']} {a['ip']}",
                                                             f"--screenshot=<evidence>", app.key + "/"]))
                try:
                    subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
                except subprocess.TimeoutExpired:
                    ctx.log.info("screenshot timed out for %s", app.key)
                    continue
            if not out.exists() or out.stat().st_size == 0:
                continue
            ev = ctx.evidence("screenshot", f"Screenshot of {app.key}", out.read_bytes(), ".png")
            ctx.emit(Obs("web_app", app.key, {"screenshot_evidence": ev, "screenshot_phash": phash(out)}, evidence_id=ev))
            out.unlink(missing_ok=True)
