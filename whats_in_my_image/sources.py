"""Load an image from a registry, a docker/podman archive, an OCI layout, or a local daemon.

Every loader produces the same :class:`Image`: the image config plus an ordered
list of layers that can each be opened as an (already decompressed) tar stream.
"""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import os
import shutil
import subprocess
import tarfile
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import BinaryIO, Callable

from .registry import RegistryClient, RegistryError, parse_ref, pick_platform


class SourceError(Exception):
    pass


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


@dataclass
class Layer:
    index: int
    diff_id: str
    digest: str
    size: int
    media_type: str
    _opener: Callable[[], BinaryIO] = field(repr=False)

    def open_raw(self) -> BinaryIO:
        return self._opener()

    @contextlib.contextmanager
    def open(self):
        """Yield the layer as an uncompressed tar stream."""
        with contextlib.ExitStack() as stack:
            raw = stack.enter_context(self._opener())
            yield stack.enter_context(_decompress(raw))


def _decompress(f: BinaryIO) -> BinaryIO:
    head = f.read(4)
    f.seek(0)
    if head[:2] == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=f, mode="rb")
    if head == b"\x28\xb5\x2f\xfd":
        try:
            from compression import zstd  # Python 3.14+

            return zstd.ZstdFile(f)
        except ImportError:
            pass
        try:
            import zstandard

            return zstandard.ZstdDecompressor().stream_reader(f)
        except ImportError:
            raise SourceError(
                "This image uses zstd-compressed layers. Use Python 3.14+ or `pip install zstandard`."
            ) from None
    return contextlib.nullcontext(f)  # type: ignore[return-value]


@dataclass
class Image:
    name: str
    source: str
    config_raw: bytes
    layers: list[Layer]
    manifest_digest: str | None = None
    index_digest: str | None = None
    annotations: dict = field(default_factory=dict)
    platform: str = ""
    registry_client: RegistryClient | None = field(default=None, repr=False)

    @property
    def config(self) -> dict:
        if not hasattr(self, "_config"):
            self._config = json.loads(self.config_raw)
        return self._config

    @property
    def labels(self) -> dict:
        return (self.config.get("config") or {}).get("Labels") or {}

    @property
    def diff_ids(self) -> list[str]:
        return list((self.config.get("rootfs") or {}).get("diff_ids") or [lyr.diff_id for lyr in self.layers])

    @property
    def created(self) -> str:
        return self.config.get("created", "")

    def layer_history(self) -> tuple[list[dict], bool]:
        """Map each filesystem layer to the Dockerfile step that produced it.

        Returns (entries, aligned). ``aligned`` is False when the image's history does
        not line up with its layers (squashed or hand-assembled images).
        """
        entries, pending = [], []
        for h in self.config.get("history") or []:
            if h.get("empty_layer"):
                pending.append(h)
                continue
            entries.append({**h, "metadata_steps": pending})
            pending = []
        n = len(self.diff_ids)
        aligned = len(entries) == n
        entries = (entries + [{} for _ in range(n)])[:n]
        return entries, aligned

    def write_docker_archive(self, path: Path) -> Path:
        """Write a `docker save`-style archive (used to hand the image to Trivy/Grype)."""
        with tarfile.open(path, "w") as tf:

            def add(name: str, f: BinaryIO, size: int) -> None:
                ti = tarfile.TarInfo(name)
                ti.size = size
                tf.addfile(ti, f)

            add("config.json", io.BytesIO(self.config_raw), len(self.config_raw))
            names = []
            for layer in self.layers:
                name = f"layers/{layer.index:03d}.tar"
                with layer.open_raw() as f:
                    f.seek(0, io.SEEK_END)
                    size = f.tell()
                    f.seek(0)
                    add(name, f, size)
                names.append(name)
            tag = self.name if ":" in self.name.rsplit("/", 1)[-1] else "wimi-scan:latest"
            manifest = json.dumps([{"Config": "config.json", "RepoTags": [tag], "Layers": names}]).encode()
            add("manifest.json", io.BytesIO(manifest), len(manifest))
        return path


# --------------------------------------------------------------------------- archives / layouts


class _TarStore:
    def __init__(self, path: Path):
        self.tf = tarfile.open(path, "r:")
        self.members = {m.name.removeprefix("./"): m for m in self.tf.getmembers() if m.isfile()}

    def has(self, name: str) -> bool:
        return name.removeprefix("./") in self.members

    def read(self, name: str) -> bytes:
        with self.open(name) as f:
            return f.read()

    def open(self, name: str) -> BinaryIO:
        return self.tf.extractfile(self.members[name.removeprefix("./")])

    def size(self, name: str) -> int:
        return self.members[name.removeprefix("./")].size


class _DirStore:
    def __init__(self, path: Path):
        self.root = path

    def has(self, name: str) -> bool:
        return (self.root / name).is_file()

    def read(self, name: str) -> bytes:
        return (self.root / name).read_bytes()

    def open(self, name: str) -> BinaryIO:
        try:
            return open(self.root / name, "rb")
        except OSError as e:  # layers open lazily, after load_image() has returned
            raise _unreadable(self.root / name, e) from None

    def size(self, name: str) -> int:
        return (self.root / name).stat().st_size


def _unreadable(spec, e: Exception) -> SourceError:
    if isinstance(e, OSError) and e.strerror:
        return SourceError(f"cannot read {e.filename or spec}: {e.strerror.lower()}")
    return SourceError(f"cannot read {spec}: {e}")


def _blob_path(digest: str) -> str:
    algo, _, hexd = digest.partition(":")
    return f"blobs/{algo}/{hexd}"


def _load_from_store(store, name: str, source: str, platform: str) -> Image:
    if store.has("manifest.json"):
        m = json.loads(store.read("manifest.json"))[0]
        config_raw = store.read(m["Config"])
        diff_ids = json.loads(config_raw)["rootfs"]["diff_ids"]
        layers = []
        for i, lp in enumerate(m["Layers"]):
            digest = "sha256:" + Path(lp).name if lp.startswith("blobs/sha256/") else diff_ids[i]
            layers.append(Layer(i, diff_ids[i], digest, store.size(lp), "", partial(store.open, lp)))
        tags = m.get("RepoTags") or []
        return Image(tags[0] if tags else name, source, config_raw, layers, platform=platform)
    if store.has("index.json"):
        doc = json.loads(store.read("index.json"))
        ann: dict = {}
        while "manifests" in doc:
            desc = pick_platform(doc["manifests"], platform) if len(doc["manifests"]) > 1 else doc["manifests"][0]
            ann = {**ann, **(desc.get("annotations") or {})}
            digest = desc["digest"]
            doc = json.loads(store.read(_blob_path(digest)))
        config_raw = store.read(_blob_path(doc["config"]["digest"]))
        diff_ids = json.loads(config_raw)["rootfs"]["diff_ids"]
        layers = [
            Layer(
                i,
                diff_ids[i],
                d["digest"],
                d.get("size", 0),
                d.get("mediaType", ""),
                partial(store.open, _blob_path(d["digest"])),
            )
            for i, d in enumerate(doc["layers"])
        ]
        ref_name = ann.get("io.containerd.image.name") or ann.get("org.opencontainers.image.ref.name") or name
        return Image(
            ref_name,
            source,
            config_raw,
            layers,
            manifest_digest=digest,
            annotations=doc.get("annotations") or {},
            platform=platform,
        )
    raise SourceError(f"{name} is not a docker-archive or OCI image layout")


def load_archive(path: Path, platform: str, cache_dir: Path, display_name: str | None = None) -> Image:
    if not path.exists():
        raise SourceError(f"File not found: {path}")
    with open(path, "rb") as f:
        compressed = f.read(2) == b"\x1f\x8b"
    if compressed:  # `docker save | gzip` - random access into a .gz is very slow, so unpack once
        plain = cache_dir / "archives" / (path.name + ".tar")
        if not plain.exists():
            plain.parent.mkdir(parents=True, exist_ok=True)
            partial_file = plain.with_name(f"{plain.name}.{os.getpid()}.partial")
            try:  # only a complete archive may land at `plain`, or later runs would reuse a truncated one
                with gzip.open(path, "rb") as src, open(partial_file, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
                partial_file.replace(plain)
            finally:
                partial_file.unlink(missing_ok=True)
        path = plain
    return _load_from_store(_TarStore(path), display_name or path.name, "archive", platform)


def load_oci_dir(path: Path, platform: str) -> Image:
    return _load_from_store(_DirStore(path), path.name, "oci-layout", platform)


def load_daemon(name: str, tool: str | None, platform: str, cache_dir: Path, log) -> Image:
    tool = tool or next((t for t in ("docker", "podman") if shutil.which(t)), None)
    if not tool or not shutil.which(tool):
        raise SourceError("Neither docker nor podman was found on this machine")
    out = cache_dir / "daemon-export" / (name.replace("/", "_").replace(":", "_") + ".tar")
    out.parent.mkdir(parents=True, exist_ok=True)
    log(f"Exporting {name} from local {tool} ...")
    # fixed argv, no shell; "--" stops an image name beginning with "-" being read as an option
    res = subprocess.run([tool, "save", "-o", str(out), "--", name], capture_output=True, text=True)  # nosec B603
    if res.returncode != 0:
        raise SourceError(f"`{tool} save {name}` failed: {res.stderr.strip()}")
    return load_archive(out, platform, cache_dir, display_name=name)


def load_registry(
    spec: str, platform: str, cache_dir: Path, *, fetch_layers: bool = True, log=print, **client_opts
) -> Image:
    ref = parse_ref(spec)
    client = RegistryClient(ref, **client_opts)
    log(f"Resolving {ref} ...")
    manifest, config_raw, digest, index_digest = client.resolve(platform)
    diff_ids = json.loads(config_raw)["rootfs"]["diff_ids"]
    descs = manifest.get("layers") or []
    if len(descs) != len(diff_ids):
        raise SourceError("The image manifest and config disagree on the number of layers")
    layers = []
    total = len(descs)
    for i, d in enumerate(descs):
        dest = cache_dir / "blobs" / d["digest"].replace(":", "_")
        if fetch_layers:
            size = d.get("size", 0)
            log(
                f"  layer {i + 1}/{total}  {human_size(size):>9}  {d['digest'][:19]}"
                + ("  (cached)" if dest.exists() else "")
            )
            client.fetch_blob(d["digest"], dest)
        layers.append(
            Layer(i, diff_ids[i], d["digest"], d.get("size", 0), d.get("mediaType", ""), partial(open, dest, "rb"))
        )
    return Image(
        str(ref),
        "registry",
        config_raw,
        layers,
        manifest_digest=digest,
        index_digest=index_digest,
        annotations=manifest.get("annotations") or {},
        platform=platform,
        registry_client=client,
    )


def load_image(
    spec: str, *, platform: str = "linux/amd64", cache_dir: Path, fetch_layers: bool = True, log=print, **client_opts
) -> Image:
    """Load from any supported source.

    ``docker-archive:FILE`` / ``oci-archive:FILE`` / a ``.tar`` path  - saved archive
    ``oci:DIR`` / a directory                                         - OCI image layout
    ``docker:NAME`` / ``podman:NAME``                                 - local container engine
    anything else                                                     - registry reference
    """
    try:
        return _load_image(spec, platform, cache_dir, fetch_layers, log, client_opts)
    except (OSError, EOFError, tarfile.TarError) as e:  # EOFError: a truncated .gz
        raise _unreadable(spec, e) from None


def _load_image(spec: str, platform: str, cache_dir: Path, fetch_layers: bool, log, client_opts: dict) -> Image:
    for prefix in ("docker-archive:", "oci-archive:"):
        if spec.startswith(prefix):
            return load_archive(Path(spec[len(prefix) :]), platform, cache_dir)
    if spec.startswith("oci:"):
        return load_oci_dir(Path(spec[4:]), platform)
    for tool in ("docker", "podman"):
        if spec.startswith(tool + ":") and not spec.startswith(tool + "://"):
            return load_daemon(spec[len(tool) + 1 :], tool, platform, cache_dir, log)
    p = Path(spec)
    if p.exists():
        return load_archive(p, platform, cache_dir) if p.is_file() else load_oci_dir(p, platform)
    try:
        return load_registry(spec, platform, cache_dir, fetch_layers=fetch_layers, log=log, **client_opts)
    except RegistryError as e:
        raise SourceError(str(e)) from None
