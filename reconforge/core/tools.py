"""External tool discovery and execution.

Each external tool is optional. A tool is used only when enabled in config and found
on disk, and (for ambiguous names such as `httpx`) when its version banner matches the
expected project. Commands run without a shell, with a timeout, and their output is
stored as evidence.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

# Expected substrings in `<tool> -version` output, to avoid running a different binary
# that happens to share the name (e.g. the Python `httpx` CLI vs ProjectDiscovery httpx).
SIGNATURES = {
    "subfinder": (["-version"], "projectdiscovery|current version|engine version"),
    "dnsx": (["-version"], "projectdiscovery|current version|engine version"),
    "httpx": (["-version"], "projectdiscovery|current version|engine version"),
    "tlsx": (["-version"], "projectdiscovery|current version|engine version"),
    "katana": (["-version"], "projectdiscovery|current version|engine version"),
    "nuclei": (["-version"], "projectdiscovery|current version|engine version"),
    "naabu": (["-version"], "projectdiscovery|current version|engine version"),
    "nmap": (["--version"], "nmap"),
    "whatweb": (["--version"], "whatweb"),
    "gau": (["--version"], ""),
}


@dataclass
class ToolInfo:
    name: str
    path: str | None
    available: bool
    reason: str = ""


_cache: dict[tuple[str, str], ToolInfo] = {}


def detect_tool(name: str, cfg: dict) -> ToolInfo:
    enabled = cfg.get("enabled", "auto")
    path_cfg = cfg.get("path", name)
    if enabled is False or str(enabled).lower() == "false":
        return ToolInfo(name, None, False, "disabled in config")
    cache_key = (name, path_cfg)
    if cache_key in _cache:
        return _cache[cache_key]
    path = shutil.which(path_cfg)
    if not path:
        info = ToolInfo(name, None, False, f"'{path_cfg}' not found on PATH")
    else:
        args, needle = SIGNATURES.get(name, (["-version"], ""))
        info = ToolInfo(name, path, True)
        if needle:
            try:
                out = subprocess.run([path, *args], capture_output=True, text=True, timeout=15)
                banner = (out.stdout + out.stderr).lower()
                if not any(n in banner for n in needle.split("|")):
                    info = ToolInfo(name, None, False, f"'{path}' does not look like the expected {name} ({needle})")
            except Exception as exc:  # pragma: no cover - environment specific
                info = ToolInfo(name, None, False, f"version check failed: {exc}")
    _cache[cache_key] = info
    return info


def run_command(cmd: list[str], input_text: str | None = None, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout, check=False)


class Stopped(Exception):
    """Raised when a running tool was stopped by the user; carries whatever it printed so far."""

    def __init__(self, proc: subprocess.CompletedProcess):
        super().__init__("stopped by user")
        self.proc = proc


def stream_command(cmd: list[str], input_text: str | None = None, timeout: float = 600, on_line=None,
                   cancel=None, cwd: str | None = None) -> subprocess.CompletedProcess:
    """Run a command, reading stdout/stderr as they are produced.

    `on_line(stream, line)` is called for every line (for live logging). `cancel` is a
    threading.Event: when set, the process is terminated (then killed) and `Stopped` is
    raised with the partial output. Exceeding `timeout` raises subprocess.TimeoutExpired.
    """
    import threading
    import time

    proc = subprocess.Popen(cmd, cwd=cwd, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, errors="replace")
    out: list[str] = []
    err: list[str] = []

    def pump(stream, sink, name):
        for line in iter(stream.readline, ""):
            sink.append(line)
            if on_line is not None:
                try:
                    on_line(name, line.rstrip("\n"))
                except Exception:  # pragma: no cover - logging must never break a tool run
                    pass
        stream.close()

    def feed():
        try:
            proc.stdin.write(input_text)
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    threads = [threading.Thread(target=pump, args=(proc.stdout, out, "stdout"), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, err, "stderr"), daemon=True)]
    if input_text is not None:
        threads.append(threading.Thread(target=feed, daemon=True))
    for t in threads:
        t.start()
    deadline = time.monotonic() + timeout
    reason = None
    while proc.poll() is None:
        if cancel is not None and cancel.is_set():
            reason = "cancel"
        elif time.monotonic() > deadline:
            reason = "timeout"
        if reason:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            break
        time.sleep(0.25)
    for t in threads[:2]:
        t.join(5)
    result = subprocess.CompletedProcess(cmd, proc.returncode, "".join(out), "".join(err))
    if reason == "cancel":
        raise Stopped(result)
    if reason == "timeout":
        raise subprocess.TimeoutExpired(cmd, timeout, output=result.stdout, stderr=result.stderr)
    return result


def clear_caches() -> None:
    """Forget tool detection results (after installing a tool while the server runs)."""
    _cache.clear()


# --------------------------------------------------------------------------- discovery
import os  # noqa: E402
from pathlib import Path  # noqa: E402

HOME = Path.home()
# Where installers usually put binaries (go install, pip --user, Homebrew, snap, our own installer).
EXTRA_DIRS = [HOME / "go" / "bin", HOME / ".local" / "bin", HOME / ".local" / "share" / "reconforge" / "bin",
              HOME / ".local" / "share" / "reconforge" / "npm" / "node_modules" / ".bin", HOME / ".cargo" / "bin",
              Path("/opt/homebrew/bin"), Path("/usr/local/bin"), Path("/usr/local/go/bin"), HOME / ".local" / "go" / "bin",
              Path("/usr/bin"), Path("/snap/bin")]


def tool_dirs() -> list[Path]:
    venv_bin = Path(__file__).resolve().parents[2] / ".venv" / "bin"
    gopath = os.environ.get("GOPATH")
    extra = [Path(gopath) / "bin"] if gopath else []
    return [d for d in [*extra, *EXTRA_DIRS, venv_bin] if d.is_dir()]


def augment_path() -> None:
    """Make tool directories visible to child processes (e.g. shuffledns -> massdns)."""
    parts = os.environ.get("PATH", "").split(os.pathsep)
    for d in tool_dirs():
        if str(d) not in parts:
            parts.append(str(d))
    os.environ["PATH"] = os.pathsep.join(p for p in parts if p)


def _candidates(exe: str) -> list[str]:
    seen, out = set(), []
    for d in [*os.environ.get("PATH", "").split(os.pathsep), *map(str, tool_dirs())]:
        p = Path(d) / exe
        if d and p.is_file() and os.access(p, os.X_OK):
            rp = str(p.resolve())
            if rp not in seen:
                seen.add(rp)
                out.append(str(p))
    return out


def _check(path: str, args: list[str], needle: str) -> tuple[bool, str | None]:
    try:
        out = subprocess.run([path, *args], capture_output=True, text=True, timeout=20)
    except Exception:
        return False, None
    text = (out.stdout + out.stderr).strip()
    version = next((l.strip() for l in text.splitlines() if any(c.isdigit() for c in l)), None)
    low = text.lower()
    return (not needle or any(n.strip().lower() in low for n in needle.split("|"))), (version or "")[:120]


def discover_tools(entries: list[dict]) -> dict[str, dict]:
    """For each registry tool, find the first binary (PATH + common install dirs) that passes the
    signature check. Returns {name: {path, version, rejected: [paths that were the wrong program]}}."""
    found: dict[str, dict] = {}
    for e in entries:
        name = e["name"]
        if name == "chrome":
            from ..modules.screenshots import find_chrome

            p = find_chrome("auto")
            if p:
                found[name] = {"path": p, "version": None, "rejected": []}
            continue
        if e.get("profile") == "reference" and not e.get("version_args"):
            continue
        args = e.get("version_args") or ["--version"]
        needle = e.get("signature") or ""
        rejected = []
        for cand in _candidates(name):
            ok, version = _check(cand, args, needle)
            if ok:
                found[name] = {"path": cand, "version": version, "rejected": rejected}
                break
            rejected.append(cand)
        else:
            if rejected:
                found[name] = {"path": None, "version": None, "rejected": rejected}
    return found


def tool_paths_file() -> Path:
    return Path(os.environ.get("RECONFORGE_HOME", HOME / ".reconforge")) / "tool-paths.yaml"


def write_tool_paths(found: dict[str, dict], path: Path | None = None) -> Path:
    import yaml

    path = path or tool_paths_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"generated_by": "reconforge tools --detect", "tools": {n: {"path": v["path"], "version": v["version"]}
                                                                  for n, v in sorted(found.items()) if v.get("path")}}
    path.write_text("# Absolute paths of verified recon tools. Regenerate with: reconforge tools --detect\n"
                    + yaml.safe_dump(data, sort_keys=True))
    return path
