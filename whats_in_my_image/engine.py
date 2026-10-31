"""A small client for the Docker Engine API (also served by Podman), over a Unix socket.

Used to run Trivy / Grype as short-lived sidecar containers when their binaries are not installed but their
images are. Standard library only, so wimi keeps installing on air-gapped hosts with nothing to vet. Only the
handful of calls wimi needs are implemented; see https://docs.docker.com/reference/api/engine/.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import re
import socket
import urllib.parse
from collections.abc import Iterable
from pathlib import Path

DEFAULT_SOCKETS = ("/var/run/docker.sock", "/run/podman/podman.sock")
# Python on Windows has no Unix sockets, and Docker Desktop there serves its API on a named pipe; sidecars are then
# unavailable (run wimi in its Linux container instead, which reaches the engine through the mounted socket).
HAS_UNIX_SOCKETS = hasattr(socket, "AF_UNIX")


class EngineError(Exception):
    pass


def find_socket() -> tuple[str | None, str]:
    """Locate the container engine's API socket. Returns (path or None, how it was found / why not)."""
    if not HAS_UNIX_SOCKETS:
        return None, "this platform has no Unix sockets for the container engine API (run wimi in its container)"
    for var in ("DOCKER_HOST", "CONTAINER_HOST"):
        val = os.environ.get(var, "")
        if not val:
            continue
        if val.startswith("unix://"):
            return val[len("unix://") :], var
        return None, f"{var}={val} is not a unix:// socket (only local sockets are supported)"
    candidates = list(DEFAULT_SOCKETS)
    if os.environ.get("XDG_RUNTIME_DIR"):
        candidates.append(str(Path(os.environ["XDG_RUNTIME_DIR"]) / "podman" / "podman.sock"))
    for path in candidates:
        if Path(path).is_socket():
            return path, path
    return None, "no container engine socket found (mount /var/run/docker.sock or set DOCKER_HOST)"


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float | None):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self._path)
        except OSError:
            s.close()
            raise
        self.sock = s


def _quote(ref: str) -> str:
    return urllib.parse.quote(ref, safe="/:@")


class Engine:
    def __init__(self, socket_path: str, timeout: float = 60):
        self.socket_path = socket_path
        self.timeout = timeout

    # ------------------------------------------------------------------ transport

    def _request(
        self,
        method: str,
        path: str,
        query: dict | None = None,
        body: bytes | Iterable[bytes] | None = None,
        headers: dict | None = None,
        timeout: float | None = None,
    ) -> tuple[int, bytes]:
        if query:
            path += "?" + urllib.parse.urlencode(query)
        conn = _UnixConnection(self.socket_path, timeout if timeout is not None else self.timeout)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.read()
        except (OSError, http.client.HTTPException) as e:
            raise EngineError(f"{method} {path.split('?')[0]}: {e}") from e
        finally:
            conn.close()

    def _call(self, method: str, path: str, ok=(200, 201, 204), **kw) -> bytes:
        status, data = self._request(method, path, **kw)
        if status not in ok:
            try:
                msg = json.loads(data).get("message", "")
            except ValueError:
                msg = data[:300].decode(errors="replace")
            raise EngineError(f"{method} {path}: HTTP {status} {msg}".strip())
        return data

    def _json(self, method: str, path: str, **kw):
        data = self._call(method, path, **kw)
        return json.loads(data) if data.strip() else None

    # ------------------------------------------------------------------ system

    def unavailable(self) -> str:
        """Why this engine can't be used, or "" if it answers."""
        path = self.socket_path
        try:
            status = self._request("GET", "/_ping", timeout=5)[0]
        except EngineError as e:
            if isinstance(e.__cause__, PermissionError):
                return (
                    f"permission denied on {path}: run as a member of its group, e.g. --group-add $(stat -c %g {path})"
                )
            if isinstance(e.__cause__, FileNotFoundError):
                return f"there is no container engine socket at {path}"
            if isinstance(e.__cause__, ConnectionRefusedError):
                return f"nothing is listening on {path} (is the container engine running?)"
            if isinstance(e.__cause__, socket.timeout):
                return f"the container engine at {path} did not answer within 5 seconds"
            return f"the container engine at {path} is not responding ({e})"
        return "" if status == 200 else f"the container engine at {path} answered /_ping with HTTP {status}"

    def version(self) -> dict:
        return self._json("GET", "/version")

    # ------------------------------------------------------------------ images

    def image_inspect(self, ref: str) -> dict | None:
        status, data = self._request("GET", f"/images/{_quote(ref)}/json")
        if status == 404:
            return None
        if status != 200:
            raise EngineError(f"inspect image {ref}: HTTP {status}")
        return json.loads(data)

    def images(self, reference: str) -> list[dict]:
        """Local images whose name matches `reference` (a repository name, any tag)."""
        flt = json.dumps({"reference": [reference]})
        return self._json("GET", "/images/json", query={"filters": flt}) or []

    def pull(self, ref: str, auth: tuple[str, str] | None = None, timeout: float = 1800) -> None:
        headers = {}
        if auth:
            payload = json.dumps({"username": auth[0], "password": auth[1]}).encode()
            headers["X-Registry-Auth"] = base64.urlsafe_b64encode(payload).decode()
        data = self._call("POST", "/images/create", query={"fromImage": ref}, headers=headers, timeout=timeout)
        # The pull streams progress as JSON lines; an error is reported in-band with HTTP 200.
        for line in data.splitlines():
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("error"):
                raise EngineError(f"pull {ref}: {msg['error']}")

    # ------------------------------------------------------------------ containers

    def container_inspect(self, cid: str) -> dict | None:
        status, data = self._request("GET", f"/containers/{_quote(cid)}/json")
        if status == 404:
            return None
        if status != 200:
            raise EngineError(f"inspect container {cid}: HTTP {status}")
        return json.loads(data)

    def containers(self, label: str) -> list[dict]:
        flt = json.dumps({"label": [label]})
        return self._json("GET", "/containers/json", query={"all": "1", "filters": flt}) or []

    def create(self, spec: dict) -> str:
        body = json.dumps(spec).encode()
        res = self._json("POST", "/containers/create", body=body, headers={"Content-Type": "application/json"})
        return res["Id"]

    def put_archive(self, cid: str, path: str, stream: Iterable[bytes], length: int) -> None:
        headers = {"Content-Type": "application/x-tar", "Content-Length": str(length)}
        self._call("PUT", f"/containers/{cid}/archive", query={"path": path}, body=stream, headers=headers, timeout=600)

    def get_archive(self, cid: str, path: str) -> bytes:
        return self._call("GET", f"/containers/{cid}/archive", query={"path": path}, timeout=600)

    def start(self, cid: str) -> None:
        self._call("POST", f"/containers/{cid}/start", ok=(204, 304))

    def wait(self, cid: str, timeout: float) -> int:
        try:
            res = self._json("POST", f"/containers/{cid}/wait", timeout=timeout)
        except EngineError as e:
            if isinstance(e.__cause__, (socket.timeout, TimeoutError)):
                raise TimeoutError(f"container did not finish within {timeout:.0f}s") from e
            raise
        return int((res or {}).get("StatusCode", -1))

    def logs(self, cid: str, tail: int = 40) -> str:
        """Last lines of the container's output (best effort; some log drivers cannot be read back)."""
        try:
            data = self._call("GET", f"/containers/{cid}/logs", query={"stdout": "1", "stderr": "1", "tail": tail})
        except EngineError:
            return ""
        return _demux(data)

    def remove(self, cid: str) -> None:
        try:
            self._call("DELETE", f"/containers/{cid}", query={"force": "1", "v": "1"}, ok=(200, 204, 404))
        except EngineError:
            pass


def _demux(data: bytes) -> str:
    """Decode the multiplexed stdout/stderr log stream (8-byte frame headers), or plain text from a TTY."""
    out, i = [], 0
    while i + 8 <= len(data) and data[i] in (0, 1, 2) and data[i + 1 : i + 4] == b"\0\0\0":
        size = int.from_bytes(data[i + 4 : i + 8], "big")
        out.append(data[i + 8 : i + 8 + size])
        i += 8 + size
    if i < len(data):
        out.append(data[i:])
    return b"".join(out).decode(errors="replace")


# ---------------------------------------------------------------------- which container are we in?

_MOUNTINFO_ID = re.compile(r"containers/([0-9a-f]{64})/")


def in_container() -> bool:
    return Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()


def own_container_ids() -> list[str]:
    """Candidate IDs for the container wimi is running in, most reliable first."""
    ids = []
    if os.environ.get("WIMI_CONTAINER_ID"):
        ids.append(os.environ["WIMI_CONTAINER_ID"])
    try:
        # Docker and Podman bind-mount /etc/hostname etc. from a per-container directory named by the full ID.
        for m in _MOUNTINFO_ID.finditer(Path("/proc/self/mountinfo").read_text()):
            if m.group(1) not in ids:
                ids.append(m.group(1))
    except OSError:
        pass
    host = socket.gethostname()
    if re.fullmatch(r"[0-9a-f]{12,64}", host) and host not in ids:
        ids.append(host)  # default container hostname is the short ID
    return ids
