"""Parsers for Debian/Ubuntu, Alpine, Python, npm and Java package metadata."""

from __future__ import annotations

import io
import json
import re
import zipfile
from email.parser import HeaderParser

# --------------------------------------------------------------------------- os-release


def parse_os_release(data: bytes) -> dict[str, str]:
    out = {}
    for line in data.decode("utf-8", "replace").splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip() and not k.startswith("#"):
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


# --------------------------------------------------------------------------- dpkg


def parse_dpkg_status(data: bytes) -> list[dict]:
    """Return installed packages from a dpkg status file (or a distroless status.d entry)."""
    pkgs = []
    for para in re.split(r"\n\s*\n", data.decode("utf-8", "replace")):
        fields: dict[str, str] = {}
        key = None
        for line in para.splitlines():
            if line[:1] in (" ", "\t") and key:
                continue  # continuation (long description / conffiles)
            k, sep, v = line.partition(":")
            if sep:
                key = k.strip()
                fields[key] = v.strip()
        if not fields.get("Package"):
            continue
        status = fields.get("Status", "install ok installed")
        if "installed" not in status.split() or "not-installed" in status:
            continue
        pkgs.append(fields)
    return pkgs


def parse_dpkg_list(data: bytes) -> list[str]:
    return [lyr.strip() for lyr in data.decode("utf-8", "replace").splitlines() if lyr.strip() not in ("", "/.")]


def parse_dpkg_md5sums(data: bytes) -> list[str]:
    """Paths from a dpkg md5sums file (``<md5>  <path relative to />``), as distroless ships in status.d/."""
    paths = []
    for line in data.decode("utf-8", "replace").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            paths.append(parts[1])
    return paths


# --------------------------------------------------------------------------- apk


def parse_apk_installed(data: bytes) -> list[dict]:
    pkgs = []
    for block in data.decode("utf-8", "replace").split("\n\n"):
        fields: dict = {"files": []}
        cur_dir = ""
        for line in block.splitlines():
            if len(line) < 2 or line[1] != ":":
                continue
            k, v = line[0], line[2:]
            if k == "F":
                cur_dir = v
            elif k == "R":
                fields["files"].append(f"{cur_dir}/{v}" if cur_dir else v)
            else:
                fields.setdefault(k, v)
        if fields.get("P"):
            pkgs.append(fields)
    return pkgs


# --------------------------------------------------------------------------- python


def parse_python_metadata(data: bytes) -> dict[str, str]:
    msg = HeaderParser().parsestr(data.decode("utf-8", "replace"))
    out = {k: (msg.get(k) or "") for k in ("Name", "Version", "Summary", "Home-page", "Author", "License")}
    for v in msg.get_all("Project-URL") or []:
        label, _, url = v.partition(",")
        if label.strip().lower() in ("source", "homepage", "repository", "source code") and not out["Home-page"]:
            out["Home-page"] = url.strip()
    if not out["License"]:
        out["License"] = msg.get("License-Expression") or ""
    return out


def parse_record(data: bytes) -> list[str]:
    return [row.split(",", 1)[0] for row in data.decode("utf-8", "replace").splitlines() if row]


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# --------------------------------------------------------------------------- npm


def parse_package_json(data: bytes) -> dict | None:
    try:
        doc = json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        return None
    if not isinstance(doc, dict) or not doc.get("name") or not doc.get("version"):
        return None
    lic = doc.get("license") or ""
    if isinstance(lic, dict):
        lic = lic.get("type", "")
    author = doc.get("author") or ""
    if isinstance(author, dict):
        author = author.get("name", "")
    repo = doc.get("repository") or ""
    if isinstance(repo, dict):
        repo = repo.get("url", "")
    return {
        "name": str(doc["name"]),
        "version": str(doc["version"]),
        "license": str(lic),
        "author": str(author),
        "resolved": str(doc.get("_resolved") or ""),
        "repository": str(repo),
    }


# --------------------------------------------------------------------------- java

_JAR_NAME = re.compile(r"^(?P<name>.+?)-(?P<version>\d[\w.\-+]*?)\.(jar|war|ear|hpi|jpi)$")


def parse_jar(data: bytes, filename: str, depth: int = 0) -> list[dict]:
    """Identify the Java libraries inside an archive, including fat-jar nested libs."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError):
        return []
    found: list[dict] = []
    poms = []
    nested = []
    manifest = {}
    with zf:
        for info in zf.infolist():
            n = info.filename
            if n.startswith("META-INF/maven/") and n.endswith("/pom.properties"):
                poms.append(n)
            elif n == "META-INF/MANIFEST.MF":
                try:
                    manifest = _parse_manifest(zf.read(n))
                except (zipfile.BadZipFile, OSError, KeyError):
                    pass
            elif depth < 2 and n.lower().endswith((".jar", ".war")) and info.file_size < 256 << 20:
                nested.append(n)
        for n in poms:
            try:
                props = _parse_properties(zf.read(n))
            except (zipfile.BadZipFile, OSError, KeyError):
                continue
            if props.get("artifactId") and props.get("version"):
                found.append(
                    {
                        "group": props.get("groupId", ""),
                        "artifact": props["artifactId"],
                        "version": props["version"],
                        "inner": filename,
                        "evidence": "pom.properties",
                    }
                )
        if not found:
            title = manifest.get("Implementation-Title") or manifest.get("Bundle-SymbolicName", "").split(";")[0]
            version = manifest.get("Implementation-Version") or manifest.get("Bundle-Version", "")
            vendor = manifest.get("Implementation-Vendor") or manifest.get("Bundle-Vendor", "")
            m = _JAR_NAME.match(filename.rsplit("/", 1)[-1])
            if m and not version:
                version = m.group("version")
            if m and not title:
                title = m.group("name")
            if title:
                found.append(
                    {
                        "group": vendor,
                        "artifact": title,
                        "version": version or "unknown",
                        "inner": filename,
                        "evidence": "MANIFEST.MF" if manifest else "file name",
                    }
                )
        for n in nested:
            try:
                found.extend(parse_jar(zf.read(n), f"{filename}!/{n}", depth + 1))
            except (zipfile.BadZipFile, OSError, KeyError, RuntimeError):
                continue
    return found


def _parse_properties(data: bytes) -> dict[str, str]:
    out = {}
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")):
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def _parse_manifest(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    key = None
    for line in data.decode("utf-8", "replace").splitlines():
        if line.startswith(" ") and key:
            out[key] += line[1:]
            continue
        k, sep, v = line.partition(":")
        if sep:
            key = k.strip()
            out[key] = v.strip()
    return out
