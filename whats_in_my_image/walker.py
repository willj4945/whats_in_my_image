"""Replay every image layer in order and record which layer last wrote each file.

This is the heart of the provenance answer: a container image is a stack of
layers, and each layer was produced by one specific build step. By replaying the
stack (including deletions, a.k.a. "whiteouts") we know, for every file that ends
up in the final image, exactly which layer - and therefore which party - put it
there.
"""

from __future__ import annotations

import hashlib
import posixpath
import re
import tarfile
from dataclasses import dataclass, field

from .parsers import ecosystems, gobuild

ELF_MAGIC = b"\x7fELF"
MAX_BINARY_SCAN = 768 << 20
MAX_CAPTURE = 256 << 20

RPMDB_FILES = {
    "var/lib/rpm/rpmdb.sqlite",
    "var/lib/rpm/rpmdb.sqlite-wal",
    "var/lib/rpm/Packages",
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "usr/lib/sysimage/rpm/rpmdb.sqlite-wal",
    "usr/lib/sysimage/rpm/Packages",
}
DNF_HISTORY = {"var/lib/dnf/history.sqlite", "var/lib/dnf/history.sqlite-wal"}
OS_RELEASE = {"etc/os-release", "usr/lib/os-release", "etc/redhat-release", "etc/alpine-release", "etc/debian_version"}
PY_META = re.compile(
    r"(^|/)(site|dist)-packages/[^/]+\.(dist-info|egg-info)/"
    r"(METADATA|PKG-INFO|RECORD|INSTALLER|direct_url\.json)$"
    r"|(^|/)(site|dist)-packages/[^/]+\.egg-info$"
)
NPM_META = re.compile(r"(^|/)node_modules/(@[^/]+/)?[^/]+/package\.json$")
JAVA_EXT = (".jar", ".war", ".ear", ".hpi", ".jpi")


def capture_kind(path: str) -> str | None:
    if path in RPMDB_FILES:
        return "rpmdb"
    if path in DNF_HISTORY:
        return "dnf"
    if path == "var/lib/dpkg/status" or path.startswith("var/lib/dpkg/status.d/"):
        return "dpkg"
    if path.startswith("var/lib/dpkg/info/") and path.endswith(".list"):
        return "dpkg-list"
    if path == "lib/apk/db/installed":
        return "apk"
    if path in OS_RELEASE:
        return "os"
    if PY_META.search(path):
        return "python"
    if NPM_META.search(path):
        return "npm"
    if path.endswith(JAVA_EXT):
        return "java"
    return None


@dataclass
class FileRec:
    path: str
    layer: int
    size: int
    kind: str  # f=file d=dir l=symlink h=hardlink o=other
    mode: int
    link: str = ""
    elf: bool = False
    sha256: str = ""  # of the contents, for regular files (and hard links, from their target)
    go: dict | None = None
    prev_layer: int | None = None  # layer whose version of this path was overwritten


@dataclass
class LayerScan:
    index: int
    added: int = 0
    replaced: int = 0
    metadata_only: int = 0  # rewritten with the same contents: chown/chmod -R, fix-permissions, touch
    deleted: int = 0
    bytes_written: int = 0
    captured: dict[str, bytes] = field(default_factory=dict)
    java: dict[str, list[dict]] = field(default_factory=dict)
    error: str = ""


def _norm(name: str) -> str:
    name = name.replace("\\", "/")
    while name.startswith(("./", "/")):
        name = name[2:] if name.startswith("./") else name[1:]
    return posixpath.normpath(name) if name and name != "." else ""


class Walker:
    def __init__(self) -> None:
        self.files: dict[str, FileRec] = {}
        self.children: dict[str, set[str]] = {}
        self.layers: list[LayerScan] = []
        self._dir_cache: dict[str, str] = {}

    # ---- filesystem model

    def _put(self, rec: FileRec) -> None:
        if rec.path not in self.files:
            self.children.setdefault(posixpath.dirname(rec.path), set()).add(rec.path)
        self.files[rec.path] = rec

    def _delete(self, path: str, below_layer: int) -> int:
        removed = 0
        rec = self.files.get(path)
        if rec is not None and rec.layer < below_layer:
            del self.files[path]
            self.children.get(posixpath.dirname(path), set()).discard(path)
            removed += 1
        for child in list(self.children.get(path, ())):
            removed += self._delete(child, below_layer)
        return removed

    # ---- scanning

    def scan(self, image, log=print) -> None:
        for layer in image.layers:
            ls = LayerScan(layer.index)
            self.layers.append(ls)
            log(f"  analysing layer {layer.index + 1}/{len(image.layers)}")
            try:
                with layer.open() as stream:
                    self._scan_layer(ls, stream)
            except (tarfile.TarError, OSError, EOFError) as e:
                ls.error = f"layer could not be fully read: {e}"
                log(f"  warning: layer {layer.index + 1}: {ls.error}")
        self._dir_cache.clear()

    def _scan_layer(self, ls: LayerScan, stream) -> None:
        idx = ls.index
        with tarfile.open(fileobj=stream, mode="r|", errorlevel=0) as tf:
            for m in tf:
                path = _norm(m.name)
                if not path:
                    continue
                parent, base = posixpath.split(path)
                if base == ".wh..wh..opq":
                    for child in list(self.children.get(parent, ())):
                        ls.deleted += self._delete(child, idx)
                    continue
                if base.startswith(".wh."):
                    ls.deleted += self._delete(posixpath.join(parent, base[4:]), idx)
                    continue
                kind = "d" if m.isdir() else "l" if m.issym() else "h" if m.islnk() else "f" if m.isreg() else "o"
                prev = self.files.get(path)
                rec = FileRec(
                    path,
                    idx,
                    m.size if kind == "f" else 0,
                    kind,
                    m.mode,
                    _norm(m.linkname) if kind == "h" else m.linkname,
                    prev_layer=prev.layer if prev and prev.kind != "d" else None,
                )
                if kind == "f":
                    ls.bytes_written += m.size
                    self._inspect(ls, rec, tf.extractfile(m), m.size)
                elif kind == "h":
                    target = self.files.get(rec.link)
                    if target is not None:
                        rec.elf, rec.sha256, rec.go = target.elf, target.sha256, target.go
                        cap = capture_kind(path)
                        if cap and rec.link in ls.captured:
                            ls.captured[path] = ls.captured[rec.link]
                if kind != "d":
                    if prev is not None and prev.kind != "d":
                        if _same_content(prev, rec):
                            # Only permissions, ownership or timestamps changed. The contents are still the ones the
                            # earlier layer put there, so that layer keeps the credit (#10).
                            rec.layer, rec.prev_layer = prev.layer, prev.prev_layer
                            ls.metadata_only += 1
                        else:
                            ls.replaced += 1
                    else:
                        ls.added += 1
                self._put(rec)

    def _inspect(self, ls: LayerScan, rec: FileRec, f, size: int) -> None:
        """Hash the contents (so a later rewrite of the same bytes can be recognised), capture package metadata,
        and look inside programs."""
        if f is None:
            return
        cap = capture_kind(rec.path)
        if cap and size <= MAX_CAPTURE:
            data = f.read()
            rec.sha256 = hashlib.sha256(data).hexdigest()
            if cap == "java":
                ls.java[rec.path] = ecosystems.parse_jar(data, rec.path)
            else:
                ls.captured[rec.path] = data
            return
        head = f.read(4)
        h = hashlib.sha256(head)
        rec.elf = size >= 64 and head == ELF_MAGIC
        if rec.elf and size <= MAX_BINARY_SCAN:
            rest = f.read()
            h.update(rest)
            if gobuild.MAGIC in rest:
                rec.go = gobuild.parse(rest)
        else:
            while chunk := f.read(1 << 20):
                h.update(chunk)
        rec.sha256 = h.hexdigest()

    # ---- queries

    def content(self, path: str) -> bytes | None:
        """Bytes of a captured metadata file as it exists in the final image."""
        rec = self.files.get(path)
        if rec is None:
            return None
        return self.layers[rec.layer].captured.get(path)

    def content_at(self, path: str, layer: int) -> bytes | None:
        """Latest captured version of ``path`` written at or before ``layer``."""
        for i in range(layer, -1, -1):
            if path in self.layers[i].captured:
                return self.layers[i].captured[path]
        return None

    def resolve(self, path: str) -> str:
        """Canonicalise a package-manager path through directory symlinks (e.g. /bin -> usr/bin)."""
        path = path.lstrip("/")
        d, b = posixpath.split(path)
        return posixpath.join(self._resolve_dir(d), b) if d else path

    def _resolve_dir(self, d: str, depth: int = 0) -> str:
        if d in self._dir_cache:
            return self._dir_cache[d]
        parts = d.split("/")
        out: list[str] = []
        for i, p in enumerate(parts):
            out.append(p)
            cur = "/".join(out)
            rec = self.files.get(cur)
            if rec is not None and rec.kind == "l" and depth < 16:
                tgt = rec.link
                joined = tgt.lstrip("/") if tgt.startswith("/") else posixpath.join(posixpath.dirname(cur), tgt)
                newp = posixpath.normpath("/".join([joined] + parts[i + 1 :])).lstrip("/")
                result = self._resolve_dir(newp, depth + 1) if newp not in (".", "") else ""
                self._dir_cache[d] = result
                return result
        self._dir_cache[d] = d
        return d


def _same_content(prev: FileRec, rec: FileRec) -> bool:
    """True if ``rec`` rewrites ``prev`` without changing what is there: same bytes for a file or hard link, same
    target for a symlink."""
    if prev.kind in ("f", "h") and rec.kind in ("f", "h"):
        return bool(prev.sha256) and prev.sha256 == rec.sha256
    if prev.kind == rec.kind == "l":
        return prev.link == rec.link
    return False
