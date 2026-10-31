"""Run Trivy or Grype against the exact layers wimi analysed.

For each scanner, in order:

1. its binary is on PATH: run it directly;
2. otherwise, a container engine socket is reachable and the scanner's image is already present locally: run the
   scanner as a short-lived sidecar container;
3. otherwise: skip it.

Sidecars get the image archive copied in through the engine API (so no host paths are involved), no added
capabilities, the engine's default network, and only the environment variables meant
for that scanner (``TRIVY_*`` / ``GRYPE_*`` plus any named in ``WIMI_SCANNER_ENV``). If a forwarded variable points
at a path (for example ``TRIVY_CACHE_DIR=/vulndb/trivy``), the volume wimi has mounted at that path is mounted at the
same path in the sidecar, so the same settings work for binaries and sidecars alike.

Everything forwarded is visible to the scanner image, so only forward what that image may read. Shared paths are
read-only, except the scanner's database directory (``TRIVY_CACHE_DIR`` / ``GRYPE_DB_CACHE_DIR``), which it may need
to update.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from . import engine as eng
from .registry import find_credentials, parse_ref

SCAN_DIR = "/wimi-scan"
MODES = ("auto", "binary", "container", "off")


@dataclass(frozen=True)
class Tool:
    key: str
    label: str
    env_prefix: str
    image_var: str
    default_images: tuple[str, ...]


TOOLS = {
    "trivy": Tool("trivy", "Trivy", "TRIVY_", "WIMI_TRIVY_IMAGE", ("aquasec/trivy", "ghcr.io/aquasecurity/trivy")),
    "grype": Tool("grype", "Grype", "GRYPE_", "WIMI_GRYPE_IMAGE", ("anchore/grype", "ghcr.io/anchore/grype")),
}

# Applied to sidecars only, and only when the operator has not set them. Trivy's scan cache lives next to its
# database by default; a throwaway container gains nothing from it, and keeping it in memory means the database
# volume can be mounted read-only.
SIDECAR_DEFAULT_ENV = {"trivy": {"TRIVY_CACHE_BACKEND": "memory"}, "grype": {}}

# Paths a scanner is expected to write to (its vulnerability database, which it may download or refresh). Every other
# path shared with a sidecar is mounted read-only: the scanner image usually runs as root, which on a rootful engine is
# host uid 0 and can write root-owned files without any capability, so a writable CA bundle or config file would let a
# compromised scanner image change the host's trust store.
WRITABLE_ENV = frozenset({"TRIVY_CACHE_DIR", "GRYPE_DB_CACHE_DIR"})


@dataclass
class ScanRun:
    tool: str  # "trivy" | "grype"
    doc: dict  # the scanner's JSON report
    info: dict = field(default_factory=dict)  # how the scan was run, for the report


def scanner_args(key: str, archive: str, result: str | None = None) -> list[str]:
    """Arguments after the scanner's executable. With `result`, the JSON report goes to that file and the scanner's
    log output is left on (it is only read back if the scan fails); without it, the report goes to stdout."""
    if key == "trivy":
        args = ["image", "--input", archive, "--format", "json", "--scanners", "vuln"]
        return args + (["--output", result, "--no-progress"] if result else ["--quiet"])
    args = [f"docker-archive:{archive}", "-o", "json"]
    return args + (["--file", result] if result else ["-q"])


def mode_from_env() -> str:
    mode = (os.environ.get("WIMI_SCANNER_MODE") or "auto").strip().lower()
    if mode not in MODES:
        raise ValueError(f"WIMI_SCANNER_MODE must be one of {', '.join(MODES)} (got {mode!r})")
    return mode


# --------------------------------------------------------------------------- entry point


def run(which: str, write_archive: Callable[[Path], Path], log: Callable[[str], None]) -> ScanRun | None:
    """Run the first scanner that is available and succeeds. `which` is "auto", "trivy" or "grype"."""
    try:
        mode = mode_from_env()
    except ValueError as e:
        log(f"  {e}; skipping vulnerability scan")
        return None
    if mode == "off":
        log("  WIMI_SCANNER_MODE=off; skipping vulnerability scan")
        return None
    keys = ["trivy", "grype"] if which == "auto" else [which]
    ctx = _Context(log)
    with tempfile.TemporaryDirectory(prefix="wimi-scan-") as tmp:
        archive: Path | None = None
        for key in keys:
            tool = TOOLS[key]
            binary = shutil.which(key) if mode in ("auto", "binary") else None
            if binary:
                archive = archive or write_archive(Path(tmp) / "image.tar")
                res = _run_binary(tool, binary, archive, log)
                if res:
                    return res
                continue  # the installed binary is authoritative; don't second-guess it with a sidecar
            if mode == "binary":
                log(f"  {key}: not installed; skipping (WIMI_SCANNER_MODE=binary)")
                continue
            engine = ctx.engine()
            if engine is None:
                log(f"  {key}: not installed, and {ctx.engine_reason}; skipping")
                continue
            image = resolve_image(engine, tool, log)
            if image is None:
                continue
            archive = archive or write_archive(Path(tmp) / "image.tar")
            res = _run_sidecar(engine, tool, image, archive, ctx, log)
            if res:
                return res
    return None


class _Context:
    """Connects to the container engine lazily (only if a sidecar is needed) and at most once."""

    def __init__(self, log):
        self.log = log
        self._engine: eng.Engine | None = None
        self._tried = False
        self.engine_reason = ""

    def engine(self) -> eng.Engine | None:
        if self._tried:
            return self._engine
        self._tried = True
        path, how = eng.find_socket()
        if path is None:
            self.engine_reason = how
            return None
        e = eng.Engine(path)
        self.engine_reason = e.unavailable()
        if self.engine_reason:
            return None
        self._engine = e
        _remove_stale(e)
        return e


# --------------------------------------------------------------------------- installed binaries


def _run_binary(tool: Tool, binary: str, archive: Path, log) -> ScanRun | None:
    log(f"Running {tool.key} vulnerability scan ({binary}; this can take a few minutes the first time) ...")
    cmd = [binary, *scanner_args(tool.key, str(archive))]
    # fixed argv, no shell; the scanner binary was resolved with shutil.which
    res = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603
    if res.returncode != 0 or not res.stdout.strip():
        log(f"  {tool.key} failed: {res.stderr.strip()[:400]}")
        return None
    try:
        doc = json.loads(res.stdout)
    except ValueError as e:
        log(f"  {tool.key} produced unreadable output: {e}")
        return None
    info = {"tool": tool.label, "mode": "binary", "binary": binary}
    info.update(_describe(tool, doc, trivy_cache=os.environ.get("TRIVY_CACHE_DIR") or _default_trivy_cache()))
    return ScanRun(tool.key, doc, info)


# --------------------------------------------------------------------------- scanner images


def image_candidates(tool: Tool) -> list[str]:
    raw = os.environ.get(tool.image_var, "")
    refs = [r.strip() for r in raw.split(",") if r.strip()]
    return refs or list(tool.default_images)


def _has_tag(ref: str) -> bool:
    return "@" in ref or ":" in ref.rsplit("/", 1)[-1]


def resolve_image(engine: eng.Engine, tool: Tool, log) -> dict | None:
    """Find the scanner image locally (and pull it if WIMI_SCANNER_PULL is set). Returns the image's inspect data
    with an added "_ref" key, or None."""
    refs = image_candidates(tool)
    try:
        for ref in refs:
            found = _local_image(engine, ref)
            if found:
                return found
        if _truthy(os.environ.get("WIMI_SCANNER_PULL")):
            for ref in refs:
                pull_ref = ref if _has_tag(ref) else f"{ref}:latest"
                log(f"  {tool.key}: pulling {pull_ref} ...")
                try:
                    engine.pull(pull_ref, auth=_pull_auth(pull_ref))
                except eng.EngineError as e:
                    log(f"  {tool.key}: could not pull {pull_ref}: {e}")
                    continue
                found = _local_image(engine, pull_ref)
                if found:
                    return found
    except eng.EngineError as e:
        log(f"  {tool.key}: could not query the container engine: {e}")
        return None
    hint = "" if os.environ.get(tool.image_var) else f" (set {tool.image_var} if your registry uses another name)"
    log(f"  {tool.key}: not installed and no image found locally ({', '.join(refs)}){hint}; skipping")
    return None


def _local_image(engine: eng.Engine, ref: str) -> dict | None:
    if _has_tag(ref):
        info = engine.image_inspect(ref)
        if info:
            info["_ref"] = ref
        return info
    # No tag given: use the newest local tag of that repository, so a retagged "trivy:0.75.0" is found as "trivy".
    best = None
    for img in engine.images(ref):
        if best is None or img.get("Created", 0) > best.get("Created", 0):
            best = img
    if best is None:
        return None
    info = engine.image_inspect(best["Id"])
    if info:
        tags = [t for t in best.get("RepoTags") or [] if t.rsplit(":", 1)[0] in (ref, f"docker.io/{ref}")]
        info["_ref"] = (tags or best.get("RepoTags") or [ref])[0]
    return info


def _pull_auth(ref: str) -> tuple[str, str] | None:
    try:
        return find_credentials(parse_ref(ref).registry)
    except Exception:  # credentials are optional; the engine may not need them
        return None


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


# --------------------------------------------------------------------------- environment and mounts


def forwarded_env(tool: Tool) -> dict[str, str]:
    """Variables passed to the sidecar: the scanner's own prefix, plus names listed in WIMI_SCANNER_ENV."""
    extra = {n.strip() for n in os.environ.get("WIMI_SCANNER_ENV", "").split(",") if n.strip()}
    env = {k: v for k, v in os.environ.items() if k.startswith(tool.env_prefix) or k in extra}
    for k, v in SIDECAR_DEFAULT_ENV[tool.key].items():
        env.setdefault(k, v)
    return env


def _is_socket_mount(m: dict, socket_path: str) -> bool:
    paths = {m.get("Source") or "", m.get("Destination") or m.get("Target") or ""}
    return socket_path in paths or any(p.endswith(".sock") for p in paths)


def _under(path: str, root: str) -> bool:
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root + "/") or root == "/"


def parse_mount_override(spec: str) -> list[dict]:
    """WIMI_VULNDB_MOUNT="SOURCE:TARGET[:ro|rw],...": SOURCE is a named volume or an absolute host path."""
    mounts = []
    for entry in (e.strip() for e in spec.split(",")):
        if not entry:
            continue
        parts = entry.split(":")
        bad_mode = len(parts) == 3 and parts[2] not in ("ro", "rw")
        if len(parts) not in (2, 3) or not parts[1].startswith("/") or bad_mode:
            raise ValueError(f"WIMI_VULNDB_MOUNT entry {entry!r} should look like SOURCE:/path[:ro|rw]")
        src, dst = parts[0], parts[1]
        mounts.append(
            {
                "Type": "bind" if src.startswith("/") else "volume",
                "Source": src,
                "Target": dst,
                "ReadOnly": not (len(parts) == 3 and parts[2] == "rw"),
            }
        )
    return mounts


def sidecar_mounts(engine: eng.Engine, env: dict[str, str], log) -> list[dict]:
    """Mounts that make the paths named in `env` visible at the same location inside the sidecar."""
    override = os.environ.get("WIMI_VULNDB_MOUNT", "")
    if override.strip():
        return parse_mount_override(override)
    paths = sorted({v for v in env.values() if v.startswith("/")})
    if not paths:
        return []
    writable = {v for k, v in env.items() if k in WRITABLE_ENV and v.startswith("/")}
    if not eng.in_container():
        # wimi runs on the host next to a local engine: share the same host paths. Only the database directories are
        # writable (so a connected scanner can download or refresh its database there); everything else is read-only.
        return [
            {"Type": "bind", "Source": p, "Target": p, "ReadOnly": p not in writable} for p in paths if Path(p).exists()
        ]
    me = None
    for cid in eng.own_container_ids():
        me = engine.container_inspect(cid)
        if me:
            break
    if not me:
        log(
            "  could not identify wimi's own container, so its volumes cannot be shared with the scanner; "
            "set WIMI_CONTAINER_ID or WIMI_VULNDB_MOUNT"
        )
        return []
    own = [m for m in me.get("Mounts") or [] if m.get("Type") in ("bind", "volume")]
    own = [m for m in own if not _is_socket_mount(m, engine.socket_path)]
    chosen: dict[str, dict] = {}
    for p in paths:
        hits = [m for m in own if _under(p, m["Destination"])]
        if not hits:
            names = ", ".join(k for k, v in env.items() if v == p)
            log(f"  {names}={p} is not on a mounted volume, so the scanner container cannot see it")
            continue
        m = max(hits, key=lambda m: len(m["Destination"]))
        # Read-only unless wimi itself has it writable AND it holds a scanner database. One volume can hold several
        # forwarded paths, so it becomes writable as soon as any database path lies on it.
        rw = m.get("RW", True) and p in writable
        prev = chosen.get(m["Destination"])
        chosen[m["Destination"]] = {
            "Type": m["Type"],
            "Source": m.get("Name") if m["Type"] == "volume" else m["Source"],
            "Target": m["Destination"],
            "ReadOnly": not (rw or (prev is not None and not prev["ReadOnly"])),
        }
    return list(chosen.values())


# --------------------------------------------------------------------------- sidecar containers


DEFAULT_TIMEOUT = 1800.0
_SIZE = re.compile(r"(\d+(?:\.\d+)?)\s*([kmgt]?)(?:ib|i|b)?", re.IGNORECASE)
_UNITS = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}


def parse_size(v: str) -> int:
    """Bytes from "4g", "4gb", "4GiB", "512Mi", "1.5g" or a plain number of bytes."""
    m = _SIZE.fullmatch(v.strip())
    if not m:
        raise ValueError(f"not a size: {v!r} (examples: 512m, 4g, 4GiB)")
    return int(float(m.group(1)) * _UNITS[m.group(2).lower()])


def sidecar_limits(log) -> tuple[float, int | None]:
    """(timeout in seconds, memory limit in bytes or None) from the environment. A bad value is reported and the
    default used, rather than stopping the whole analysis over a typo."""
    timeout = DEFAULT_TIMEOUT
    raw = (os.environ.get("WIMI_SCANNER_TIMEOUT") or "").strip()
    if raw:
        try:
            timeout = float(raw)
            if timeout <= 0:
                raise ValueError
        except ValueError:
            log(f"  WIMI_SCANNER_TIMEOUT={raw!r} is not a positive number of seconds; using {DEFAULT_TIMEOUT:.0f}")
            timeout = DEFAULT_TIMEOUT
    memory = None
    raw = (os.environ.get("WIMI_SCANNER_MEMORY") or "").strip()
    if raw:
        try:
            memory = parse_size(raw)
        except ValueError as e:
            log(f"  WIMI_SCANNER_MEMORY: {e}; running without a memory limit")
    return timeout, memory


def container_spec(
    tool: Tool,
    image: dict,
    env: dict[str, str],
    mounts: list[dict],
    memory: int | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    host = {
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges"],
        "Mounts": mounts,
    }
    if memory:
        host["Memory"] = memory
    # The container is only fair game for another run's clean-up once it has outlived this run's own timeout.
    expires = int(time.time() + timeout + 300)
    spec = {
        "Image": image["Id"],
        "Cmd": scanner_args(tool.key, f"{SCAN_DIR}/image.tar", f"{SCAN_DIR}/result.json"),
        # Scanners write temporary files (Grype unpacks the image there); the image's /tmp may be writable only by
        # root, so point them at the scan directory, which any user can write (see tar_stream).
        "Env": [f"{k}={v}" for k, v in sorted({"TMPDIR": SCAN_DIR, **env}.items())],
        "Labels": {"wimi.scan": "1", "wimi.tool": tool.key, "wimi.expires": str(expires)},
        "HostConfig": host,
    }
    if os.environ.get("WIMI_SCANNER_USER"):
        spec["User"] = os.environ["WIMI_SCANNER_USER"]
    return spec


def tar_stream(archive: Path) -> tuple[Iterator[bytes], int]:
    """A tar stream holding `wimi-scan/image.tar`, built on the fly so the image archive is never copied on disk."""
    d = tarfile.TarInfo(SCAN_DIR.lstrip("/"))
    d.type, d.mode = tarfile.DIRTYPE, 0o1777  # writable by whatever user the scanner image runs as
    f = tarfile.TarInfo(f"{SCAN_DIR.lstrip('/')}/image.tar")
    f.size, f.mode = archive.stat().st_size, 0o644
    head = d.tobuf(tarfile.GNU_FORMAT) + f.tobuf(tarfile.GNU_FORMAT)
    pad = -f.size % tarfile.BLOCKSIZE
    length = len(head) + f.size + pad + 2 * tarfile.BLOCKSIZE

    def gen() -> Iterator[bytes]:
        yield head
        with archive.open("rb") as fh:
            while chunk := fh.read(1 << 20):
                yield chunk
        yield b"\0" * (pad + 2 * tarfile.BLOCKSIZE)

    return gen(), length


def _read_result(tar_bytes: bytes) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        for m in tf:
            if m.isfile() and m.name.endswith("result.json"):
                fh = tf.extractfile(m)
                return fh.read() if fh else b""
    return b""


def _run_sidecar(engine: eng.Engine, tool: Tool, image: dict, archive: Path, ctx: _Context, log) -> ScanRun | None:
    ref = image["_ref"]
    log(f"Running {tool.key} vulnerability scan in a container from {ref} ({image['Id'][7:19]}) ...")
    env = forwarded_env(tool)
    try:
        mounts = sidecar_mounts(engine, env, log)
    except ValueError as e:
        log(f"  {e}")
        return None
    for m in mounts:
        log(f"  sharing {m['Source']} at {m['Target']}{' (read-only)' if m['ReadOnly'] else ''}")
    timeout, memory = sidecar_limits(log)
    cid = None
    try:
        with _terminate_as_interrupt():
            cid = engine.create(container_spec(tool, image, env, mounts, memory=memory, timeout=timeout))
            stream, length = tar_stream(archive)
            engine.put_archive(cid, "/", stream, length)
            engine.start(cid)
            code = engine.wait(cid, timeout)
            raw = b""
            try:
                raw = _read_result(engine.get_archive(cid, f"{SCAN_DIR}/result.json"))
            except eng.EngineError:
                pass
            if code != 0 or not raw.strip():
                log(f"  {tool.key} container failed (exit code {code}): {_tail(engine.logs(cid))}")
                _hint(tool, env, log)
                return None
    except (eng.EngineError, TimeoutError) as e:
        log(f"  {tool.key} container failed: {e}")
        return None
    finally:
        if cid:
            engine.remove(cid)
    try:
        doc = json.loads(raw)
    except ValueError as e:
        log(f"  {tool.key} produced unreadable output: {e}")
        return None
    info = {"tool": tool.label, "mode": "container", "image": ref, "image_id": image["Id"]}
    digests = image.get("RepoDigests") or []
    if digests:
        info["image_digest"] = digests[0]
    # Trivy's database date is read from its cache directory, which wimi can only see if it is shared.
    cache = env.get("TRIVY_CACHE_DIR", "")
    shared = bool(cache) and any(_under(cache, m["Target"]) for m in mounts)
    info.update(_describe(tool, doc, image, trivy_cache=cache if shared else None))
    return ScanRun(tool.key, doc, info)


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _tail(text: str, n: int = 400) -> str:
    text = " ".join(_ANSI.sub("", text).strip().split())
    return ("..." + text[-n:]) if len(text) > n else (text or "no output")


def _hint(tool: Tool, env: dict[str, str], log) -> None:
    """Most first-time sidecar failures on a disconnected network are a scanner trying to download its database."""
    if tool.key == "trivy" and not _truthy(env.get("TRIVY_SKIP_DB_UPDATE")):
        log("  hint: on a disconnected network set TRIVY_SKIP_DB_UPDATE=true and TRIVY_CACHE_DIR=<database dir>")
    if tool.key == "grype" and _truthy(env.get("GRYPE_DB_AUTO_UPDATE", "true")):
        log("  hint: on a disconnected network set GRYPE_DB_AUTO_UPDATE=false and GRYPE_DB_CACHE_DIR=<database dir>")


LEGACY_STALE_AFTER = 24 * 3600  # sidecars from versions that did not label an expiry time


def is_stale(container: dict, now: float) -> bool:
    """A sidecar left behind by a wimi run that was killed. Another run may be using a sidecar at any moment from
    its creation until its own timeout, so only containers past the expiry recorded at creation qualify."""
    expires = (container.get("Labels") or {}).get("wimi.expires", "")
    if expires.isdigit():
        return int(expires) < now
    return now - float(container.get("Created") or now) > LEGACY_STALE_AFTER


def _remove_stale(engine: eng.Engine) -> None:
    try:
        now = time.time()
        for c in engine.containers("wimi.scan"):
            if is_stale(c, now):
                engine.remove(c["Id"])
    except eng.EngineError:
        pass


class _terminate_as_interrupt:
    """Turn SIGTERM (docker stop, CI cancellation) into KeyboardInterrupt so the sidecar is removed on the way out."""

    def __enter__(self):
        self._old = None
        if threading.current_thread() is threading.main_thread():
            self._old = signal.signal(signal.SIGTERM, self._raise)
        return self

    @staticmethod
    def _raise(signum, frame):
        raise KeyboardInterrupt

    def __exit__(self, *exc):
        if self._old is not None:
            signal.signal(signal.SIGTERM, self._old)
        return False


# --------------------------------------------------------------------------- what to say in the report


def _describe(tool: Tool, doc: dict, image: dict | None = None, trivy_cache: str | None = None) -> dict:
    """Scanner version and vulnerability database date, as far as they can be determined."""
    out: dict = {}
    if tool.key == "trivy":
        out["version"] = (doc.get("Trivy") or {}).get("Version", "")
        built = _trivy_db_updated(trivy_cache) if trivy_cache else ""
        if built:
            out["db_built"] = built
    else:
        desc = doc.get("descriptor") or {}
        out["version"] = desc.get("version", "")
        status = ((desc.get("db") or {}).get("status")) or {}
        if status.get("built"):
            out["db_built"] = status["built"]
        if status.get("schemaVersion"):
            out["db_schema"] = status["schemaVersion"]
    if not out.get("version") and image:
        labels = (image.get("Config") or {}).get("Labels") or {}
        out["version"] = labels.get("org.opencontainers.image.version", "")
    return {k: v for k, v in out.items() if v}


def _default_trivy_cache() -> str:
    return str(Path.home() / ".cache" / "trivy")


def _trivy_db_updated(cache: str) -> str:
    """Trivy does not put its database date in the report; read it from the database's metadata.json in `cache`.
    For a sidecar, the caller passes the cache only when it is a volume shared with wimi at the same path, so this
    never picks up an unrelated database from wimi's own home directory."""
    try:
        meta = json.loads((Path(cache) / "db" / "metadata.json").read_text())
    except (OSError, ValueError):
        return ""
    return meta.get("UpdatedAt") or ""
