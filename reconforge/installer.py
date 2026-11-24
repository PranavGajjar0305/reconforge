"""Install a single recon tool on demand, from the dashboard.

The dashboard's "Install" button calls this. It shells out to the project's own
``install.sh --only <tool>`` (the same script used at setup time), which reuses an
existing copy or installs one via Homebrew / apt / ``go install`` / a release binary /
pip / npm, then records the verified absolute path in ``~/.reconforge/tool-paths.yaml``.

Only tools the installer actually knows how to install are accepted — the name is
checked against ``install.sh``'s table, never passed to a shell unchecked — so a browser
request can never run an arbitrary command.
"""
from __future__ import annotations

import re
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .core import tools as core_tools
from .util import iso, new_id, utcnow

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"

# Pseudo-tools install.sh handles outside its table.
_EXTRA = {"waymore", "retire", "chrome", "chromium", "nuclei-templates", "dirsearch"}


def installable_names() -> set[str]:
    """Tool names install.sh can install (its table plus the pseudo-tools)."""
    names = set(_EXTRA)
    try:
        text = INSTALL_SH.read_text()
        table = text.split("TOOLS_TABLE='", 1)[1].split("'", 1)[0]
        for line in table.splitlines():
            line = line.strip()
            if line and "|" in line:
                names.add(line.split("|", 1)[0])
    except (OSError, IndexError):  # pragma: no cover - install.sh should always be present
        pass
    return names


@dataclass
class InstallJob:
    id: str
    tool: str
    status: str = "running"            # running | installed | present | failed
    lines: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: iso(utcnow()))
    finished_at: str | None = None
    result: str | None = None

    def as_dict(self) -> dict:
        return {"id": self.id, "tool": self.tool, "status": self.status, "lines": self.lines[-400:],
                "started_at": self.started_at, "finished_at": self.finished_at, "result": self.result}


class InstallManager:
    """Runs one install at a time per tool; keeps a short in-memory log for the UI."""

    def __init__(self) -> None:
        self.jobs: dict[str, InstallJob] = {}
        self._active: dict[str, str] = {}   # tool -> job id
        self._lock = threading.Lock()

    def start(self, tool: str) -> InstallJob:
        if tool not in installable_names():
            raise ValueError(f"'{tool}' is not an installable tool")
        if not INSTALL_SH.exists():
            raise RuntimeError("install.sh not found next to the package")
        with self._lock:
            active = self._active.get(tool)
            if active and self.jobs[active].status == "running":
                return self.jobs[active]
            job = InstallJob(id=new_id("inst"), tool=tool)
            self.jobs[job.id] = job
            self._active[tool] = job.id
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def _run(self, job: InstallJob) -> None:
        try:
            proc = core_tools.stream_command(
                ["bash", str(INSTALL_SH), "--only", job.tool],
                timeout=1800,
                on_line=lambda _s, line: job.lines.append(_strip_ansi(line)),
            )
            tail = (proc.stdout + proc.stderr)
            if re.search(r"^installed:", tail, re.M):
                job.status, job.result = "installed", f"{job.tool} installed"
            elif re.search(r"^already present:", tail, re.M):
                job.status, job.result = "present", f"{job.tool} was already present"
            else:
                job.status, job.result = "failed", _fail_reason(job.lines) or f"{job.tool} could not be installed"
        except Exception as exc:  # pragma: no cover - environment specific
            job.status, job.result = "failed", str(exc)
        finally:
            job.finished_at = iso(utcnow())
            core_tools.clear_caches()  # a freshly installed tool becomes visible immediately


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI.sub("", s)


def _fail_reason(lines: list[str]) -> str | None:
    for line in reversed(lines):
        if "could not be installed" in line or line.startswith("failed:") or "not found" in line:
            return line.strip(" ✗!").strip()
    return None
