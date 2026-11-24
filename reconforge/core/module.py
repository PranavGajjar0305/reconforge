"""Module base class and plugin registry.

Adding a tool never requires touching the core: subclass `Module`, decorate it with
`@register`, and make it importable via one of:
  * the built-in package `reconforge.modules`
  * a Python entry point in the `reconforge.modules` group
  * the `plugins:` list in the config (``package.module:Class`` or a ``.py`` path)
"""
from __future__ import annotations

import importlib
import importlib.util
import logging
import pkgutil
from importlib.metadata import entry_points
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:  # pragma: no cover
    from .context import ScanContext

log = logging.getLogger("reconforge.registry")

PHASES = {
    "passive": 10,
    "resolve": 20,
    "network": 30,
    "http": 40,
    "fingerprint": 50,
    "content": 60,
    "assessment": 70,
    "capture": 80,
}


class SkipModule(Exception):
    """Raised by a module to indicate it cannot run (missing tool, offline, no input)."""


class Module:
    name: ClassVar[str] = "base"
    description: ClassVar[str] = ""
    phase: ClassVar[str] = "passive"
    active: ClassVar[bool] = False            # sends traffic to target-controlled hosts
    requires_internet: ClassVar[bool] = False  # queries third-party public services
    tools: ClassVar[list[str]] = []           # optional external tools it can drive
    produces: ClassVar[list[str]] = []        # asset types it can discover (for coverage/removal logic)
    needs_domains: ClassVar[bool] = False     # works from root domains only; skipped for IP-only scans

    def run(self, ctx: "ScanContext") -> None:  # pragma: no cover - interface
        raise NotImplementedError

    @classmethod
    def order(cls) -> int:
        return PHASES.get(cls.phase, 50)


REGISTRY: dict[str, type[Module]] = {}


def register(cls: type[Module]) -> type[Module]:
    if cls.name in REGISTRY and REGISTRY[cls.name] is not cls:
        log.warning("module %s re-registered by %s", cls.name, cls.__module__)
    REGISTRY[cls.name] = cls
    return cls


_loaded = False


def load_modules(plugins: list[str] | None = None) -> dict[str, type[Module]]:
    global _loaded
    if not _loaded:
        from .. import modules as builtin

        for info in pkgutil.iter_modules(builtin.__path__):
            importlib.import_module(f"{builtin.__name__}.{info.name}")
        try:
            for ep in entry_points(group="reconforge.modules"):
                try:
                    register(ep.load())
                except Exception as exc:  # pragma: no cover - third party
                    log.error("failed to load entry point %s: %s", ep.name, exc)
        except Exception:  # pragma: no cover
            pass
        _loaded = True
    for spec in plugins or []:
        _load_plugin(spec)
    return REGISTRY


def _load_plugin(spec: str) -> None:
    if spec.endswith(".py"):
        path = Path(spec).expanduser().resolve()
        mod_spec = importlib.util.spec_from_file_location(f"reconforge_plugin_{path.stem}", path)
        if not mod_spec or not mod_spec.loader:
            raise ImportError(f"cannot load plugin {spec}")
        module = importlib.util.module_from_spec(mod_spec)
        mod_spec.loader.exec_module(module)  # @register decorators run on import
        return
    mod_name, _, attr = spec.partition(":")
    module = importlib.import_module(mod_name)
    if attr:
        register(getattr(module, attr))
