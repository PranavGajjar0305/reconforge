"""Windowed access to large, append-only text (scan logs, tool output, evidence files).

The dashboard never downloads a whole log to show it. It asks for a slice of lines (`start`, `limit`), and this module
keeps a byte-offset index of every line that matches the requested filter. The index is built once and then extended
incrementally as the log grows, so polling a running scan's log every second costs only the newly written bytes.
"""
from __future__ import annotations

import os
import re
import threading
from array import array
from collections import OrderedDict
from pathlib import Path

MAX_LIMIT = 2000
MAX_LINE = 4000  # characters per returned line; longer lines are cut (the download keeps them whole)

# console categories, shared with the Live page's filter tabs
KINDS: dict[str, re.Pattern] = {
    "commands": re.compile(r"\] (exec:|GET |HEAD |dns |tcp |tls |provider |DNS |dns brute)"),
    "modules": re.compile(r"\] (starting|completed|skipped|failed)|rediscovery|scan .* (started|finished)"),
    "errors": re.compile(r" (ERROR|WARNING) "),
}


def module_tag(module: str) -> re.Pattern:
    return re.compile(r"\[" + re.escape(module) + r"(#\d+)?\]")


class _Index:
    __slots__ = ("ident", "scanned", "offsets", "pending", "lock")

    def __init__(self, ident):
        self.ident = ident        # (inode, device) of the file the offsets belong to
        self.scanned = 0          # bytes of the file already indexed
        self.offsets = array("q")  # start offset of every matching line
        self.pending = 0          # start offset of a trailing line without its newline yet
        self.lock = threading.Lock()


class LineIndexCache:
    """LRU of line indexes keyed by (path, filter). Thread-safe; one dashboard process shares it."""

    def __init__(self, size: int = 48):
        self.size = size
        self._items: OrderedDict[tuple, _Index] = OrderedDict()
        self._lock = threading.Lock()

    def _get(self, key: tuple, ident) -> _Index:
        with self._lock:
            idx = self._items.get(key)
            if idx is None or idx.ident != ident:
                idx = _Index(ident)
                self._items[key] = idx
            self._items.move_to_end(key)
            while len(self._items) > self.size:
                self._items.popitem(last=False)
            return idx

    def window(self, path: str | os.PathLike, start: int | None = None, limit: int = 500, module: str | None = None,
               kind: str | None = None, q: str | None = None) -> dict:
        """Lines [start, start+limit) of the filtered view of `path`; start=None means the last `limit` lines."""
        p = Path(path)
        st = p.stat()
        q = (q or "").strip().lower() or None
        kind = kind if kind in KINDS else None
        key = (str(p), module or "", kind or "", q or "")
        idx = self._get(key, (st.st_ino, st.st_dev))
        with idx.lock:
            if st.st_size < idx.scanned:  # truncated or rewritten: start over
                idx.scanned, idx.pending, idx.offsets = 0, 0, array("q")
            if st.st_size > idx.scanned:
                _extend(p, idx, st.st_size, module_tag(module) if module else None, KINDS.get(kind or ""), q)
            total = len(idx.offsets)
            limit = max(0, min(int(limit), MAX_LIMIT))
            if start is None or start < 0:
                start = max(0, total - limit)
            start = min(start, total)
            offs = idx.offsets[start:start + limit]
            end_bound = idx.scanned
        lines = _read(p, offs, end_bound)
        return {"total": total, "start": start, "lines": lines, "bytes": st.st_size}


def _extend(p: Path, idx: _Index, size: int, tag, kindrx, q) -> None:
    """Index the bytes written since the last call. Only complete lines are indexed; a partial last line waits."""
    with open(p, "rb") as fh:
        fh.seek(idx.pending)
        pos = idx.pending
        while pos < size:
            raw = fh.readline()
            if not raw:
                break
            if not raw.endswith(b"\n") and pos + len(raw) >= size:
                break  # incomplete line: index it next time
            if tag is None and kindrx is None and q is None:
                idx.offsets.append(pos)
            else:
                line = raw.decode("utf-8", "replace")
                if (tag is None or tag.search(line)) and (kindrx is None or kindrx.search(line)) and (q is None or q in line.lower()):
                    idx.offsets.append(pos)
            pos += len(raw)
        idx.pending = pos
        idx.scanned = size


def _read(p: Path, offsets, bound: int) -> list[str]:
    out = []
    if not offsets:
        return out
    with open(p, "rb") as fh:
        for off in offsets:
            if off >= bound:
                break
            fh.seek(off)
            raw = fh.readline(MAX_LINE * 4 + 1)
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            out.append(line[:MAX_LINE])
    return out


def text_window(text: str, start: int | None = None, limit: int = 500, q: str | None = None) -> dict:
    """Same contract as LineIndexCache.window for text held in memory (inline evidence)."""
    lines = text.splitlines()
    q = (q or "").strip().lower()
    if q:
        lines = [l for l in lines if q in l.lower()]
    total = len(lines)
    limit = max(0, min(int(limit), MAX_LIMIT))
    if start is None or start < 0:
        start = max(0, total - limit)
    start = min(start, total)
    return {"total": total, "start": start, "lines": [l[:MAX_LINE] for l in lines[start:start + limit]], "bytes": len(text)}


LINES = LineIndexCache()
