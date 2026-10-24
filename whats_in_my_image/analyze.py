"""Attribute every layer and every component of an image to the party that put it there."""

from __future__ import annotations

import posixpath
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime

from . import suppliers
from .parsers import ecosystems, rpm
from .walker import DNF_HISTORY, Walker

TYPE_LABELS = {
    "rpm": "Operating-system package (RPM)",
    "deb": "Operating-system package (Debian)",
    "apk": "Operating-system package (Alpine)",
    "python": "Python library",
    "npm": "JavaScript library",
    "java": "Java library",
    "go-binary": "Go program",
    "go-module": "Go library (compiled into a program)",
    "binary": "Untraceable program file",
}
OS_ECOSYSTEMS = ("rpm", "deb", "apk")


@dataclass
class Origin:
    key: str
    label: str
    kind: str  # base | app | unknown
    reference: str = ""
    match: str = ""  # how the attribution was established
    layers: list[int] = field(default_factory=list)
    note: str = ""


@dataclass
class Component:
    id: str
    name: str
    version: str
    ecosystem: str
    supplier: str
    source: str = ""
    layer: int = 0
    introduced_layer: int = 0
    origin: str = ""
    change: str = "added"  # added | upgraded | downgraded | changed
    previous_version: str = ""
    paths: list[str] = field(default_factory=list)
    license: str = ""
    evidence: list[str] = field(default_factory=list)
    flags: list[dict] = field(default_factory=list)
    managed_by: str = ""
    parent: str = ""
    purl: str = ""

    @property
    def type_label(self) -> str:
        return TYPE_LABELS.get(self.ecosystem, self.ecosystem)


# --------------------------------------------------------------------------- origins


def base_label(ref: str) -> str:
    low = ref.lower()
    if "registry1.dso.mil" in low or "/ironbank/" in low or low.startswith("ironbank/"):
        path = ref.split("/ironbank/", 1)[-1] if "/ironbank/" in ref else ref.split("/", 1)[-1]
        return f"Iron Bank base: {path}"
    return f"Base image: {ref}"


def compute_origins(
    diff_ids: list[str], bases: list[dict], history: list[dict], labels: dict, app_name: str
) -> tuple[list[Origin], list[str], list[str]]:
    """Return (origins, origin key per layer, notes).

    ``bases`` entries: {"ref", "label", "diff_ids"}, optionally "source" ("catalog") and "also"
    (other tags with identical layers). Attribution is by exact layer-digest match:
    if the first N layers of the image are byte-for-byte identical to the N layers of a base
    image, those layers came from that base. This is cryptographic evidence, not a guess.
    """
    n = len(diff_ids)
    notes: list[str] = []
    origins: list[Origin] = []
    per_layer = ["app"] * n
    matched = []
    for b in bases:
        prefix = 0
        for x, y in zip(diff_ids, b["diff_ids"]):
            if x != y:
                break
            prefix += 1
        b = {**b, "prefix": prefix}
        if prefix == 0:
            notes.append(
                f"The image was NOT built on {b['ref']}: none of its {len(b['diff_ids'])} layers match. "
                "It was probably built from a different version or tag of that base."
            )
            continue
        if prefix < len(b["diff_ids"]):
            # Shared leading layers prove a common ancestor, not that the image was built on this base: it may be
            # another release of it, or the image the base is itself built on (alpine under node:alpine).
            b["partial"] = True
            b["label"] = f"Base shared with {b['label']}"
            notes.append(
                f"Only the first {prefix} of {len(b['diff_ids'])} layers of {b['ref']} match, so the image was "
                "not built on it. Both share an older base: either another release of this image, or the image "
                "it is itself built on. Catalogue that base (`wimi catalog add`) or use --base for an exact match."
            )
        matched.append(b)
    matched.sort(key=lambda b: b["prefix"])
    start = 0
    for i, b in enumerate(matched):
        end = b["prefix"]
        if end <= start:
            continue
        o = Origin(
            f"base{i}",
            b["label"],
            "base",
            b["ref"],
            "partial layer-digest match" if b.get("partial") else "exact layer-digest match",
            list(range(start, end)),
        )
        notes_o = []
        if b.get("partial"):
            notes_o.append("Built on a different version of this base; only shared layers are attributed to it.")
        if b.get("source") == "catalog":
            notes_o.append("Identified automatically from the base image catalog.")
        if b.get("also"):
            notes_o.append("Identical to: " + ", ".join(b["also"][:5]) + ("..." if len(b["also"]) > 5 else ""))
        o.note = " ".join(notes_o)
        origins.append(o)
        for li in o.layers:
            per_layer[li] = o.key
        start = end

    if not matched:
        est = _estimate_boundary(history)
        ironbank = (
            any(k.startswith(("mil.dso.ironbank", "io.dso.")) for k in labels)
            or "ironbank" in labels.get("org.opencontainers.image.vendor", "").lower()
        )
        if est:
            label = "Iron Bank base (estimated)" if ironbank else "Base image (estimated)"
            origins.append(
                Origin(
                    "base0",
                    label,
                    "base",
                    labels.get("org.opencontainers.image.base.name", ""),
                    "estimated from build timestamps",
                    list(range(est)),
                    "Estimated: re-run with --base <exact base image> for a definitive answer.",
                )
            )
            for li in range(est):
                per_layer[li] = "base0"
            start = est
            span = "layer 1 looks" if est == 1 else f"layers 1-{est} look"
            notes.append(
                f"No matching base image was available, so the base/application boundary was estimated "
                f"from build timestamps ({span} like the base). Add the base to the catalog (`wimi catalog add`) "
                "or use --base for proof by layer digest."
            )
        else:
            notes.append(
                "No matching base image was available and the boundary could not be estimated. "
                "Add the base to the catalog (`wimi catalog add`) or re-run with --base <the image you build FROM> "
                "for an exact attribution."
            )
            origins.append(Origin("unknown", "Unattributed layers", "unknown", "", "none", list(range(n))))
            return origins, ["unknown"] * n, notes
    if matched and start < n:
        # The proven base may not be the whole story: a long pause in build times inside the remaining
        # layers usually means another base image sits in between (e.g. Iron Bank Python on top of UBI).
        gap_at = _estimate_boundary(history[start:])
        if gap_at:
            first, last = start + 1, start + gap_at
            span = f"Layer {first} was" if first == last else f"Layers {first}-{last} were"
            notes.append(
                f"Possible unidentified base image: {span} built long before the layers after them, which "
                "usually means they come from another base image rather than this build. They are counted as "
                "part of the application build until that base is identified: add it with "
                "`wimi catalog add` or --base."
            )
    if start < n:
        origins.append(Origin("app", app_name, "app", "", "layers added on top of the base", list(range(start, n))))
    return origins, per_layer, notes


def _parse_time(s: str) -> datetime | None:
    if not s:
        return None
    s = re.sub(r"(\.\d{6})\d+", r"\1", s.replace("Z", "+00:00"))
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _estimate_boundary(history: list[dict]) -> int:
    """Base layers are built days or months before the application layers that go on top."""
    times = [_parse_time(h.get("created", "")) for h in history]
    best, best_gap = 0, 0.0
    for i in range(1, len(times)):
        a, b = times[i - 1], times[i]
        if a and b:
            gap = (b - a).total_seconds()
            if gap > best_gap:
                best, best_gap = i, gap
    return best if best_gap >= 6 * 3600 else 0


# --------------------------------------------------------------------------- package tracking


def _track(snapshots: list[tuple[int, list]], key_of, version_of):
    """Follow each package through successive package-database snapshots."""
    prev: dict = {}
    removed: list[tuple[int, str, str]] = []
    for layer, pkgs in snapshots:
        groups: dict = defaultdict(list)
        for p in pkgs:
            groups[key_of(p)].append(p)
        new = {}
        for k, plist in groups.items():
            versions = sorted(version_of(p) for p in plist)
            old = prev.get(k)
            if old is None:
                new[k] = {
                    "pkgs": plist,
                    "versions": versions,
                    "introduced": layer,
                    "layer": layer,
                    "change": "added",
                    "prev": "",
                }
            elif old["versions"] != versions:
                cmp = suppliers.compare_versions(versions[-1], old["versions"][-1])
                new[k] = {
                    "pkgs": plist,
                    "versions": versions,
                    "introduced": old["introduced"],
                    "layer": layer,
                    "change": "upgraded" if cmp > 0 else "downgraded" if cmp < 0 else "changed",
                    "prev": ", ".join(old["versions"]),
                }
            else:
                new[k] = {**old, "pkgs": plist}
        for k in set(prev) - set(new):
            removed.append((layer, k[0], ", ".join(prev[k]["versions"])))
        prev = new
    return prev, removed


class Analyzer:
    def __init__(self, image, walker: Walker, origins: list[Origin], per_layer: list[str]):
        self.image = image
        self.w = walker
        self.origins = origins
        self.per_layer = per_layer
        self.components: list[Component] = []
        self.by_id: dict[str, Component] = {}
        self.owner: dict[str, str] = {}  # canonical path -> OS component id
        self.lang_owned: set[str] = set()
        self.npm_dirs: set[str] = set()
        self.notes: list[str] = []
        self.os_release: dict[str, str] = {}
        self.removed_packages: list[dict] = []
        self._ids: Counter = Counter()
        self.trusted_keys = dict(suppliers.KNOWN_KEYS)

    def _id(self, eco: str, name: str, version: str) -> str:
        base = f"{eco}:{name}@{version}"
        self._ids[base] += 1
        return base if self._ids[base] == 1 else f"{base}#{self._ids[base]}"

    def _add(self, c: Component) -> Component:
        c.origin = self.per_layer[c.layer] if 0 <= c.layer < len(self.per_layer) else "unknown"
        self.components.append(c)
        self.by_id[c.id] = c
        return c

    def run(self) -> None:
        for p in ("etc/os-release", "usr/lib/os-release"):
            data = self.w.content(p)
            if data:
                self.os_release = ecosystems.parse_os_release(data)
                break
        self._rpm()
        self._dpkg()
        self._apk()
        self._python()
        self._npm()
        self._java()
        self._binaries()

    # ---- RPM

    def _rpm(self) -> None:
        snaps = []
        last_db_path = None
        for ls in self.w.layers:
            for prefix in ("var/lib/rpm", "usr/lib/sysimage/rpm"):
                sq, bdb = f"{prefix}/rpmdb.sqlite", f"{prefix}/Packages"
                try:
                    if sq in ls.captured or f"{sq}-wal" in ls.captured:
                        db = self.w.content_at(sq, ls.index)
                        wal = ls.captured.get(f"{sq}-wal")
                        if db:
                            snaps.append((ls.index, rpm.read_sqlite(db, wal)))
                            last_db_path = sq
                            break
                    if bdb in ls.captured:
                        snaps.append((ls.index, rpm.read_bdb(ls.captured[bdb])))
                        last_db_path = bdb
                        break
                except Exception as e:  # corrupt / unsupported database: report, don't abort
                    self.notes.append(f"Could not read the RPM database in layer {ls.index + 1}: {e}")
        if not snaps:
            return
        if last_db_path and last_db_path not in self.w.files:
            self.notes.append(
                "The RPM package database was deleted from the final image. The OS package list "
                "below is the last one recorded before deletion and may be incomplete."
            )
        final, removed = _track(snaps, lambda p: (p.name, p.arch), lambda p: p.evr)
        self.removed_packages += [{"layer": lyr, "name": n, "version": v, "ecosystem": "rpm"} for lyr, n, v in removed]

        for st in final.values():  # keys imported into the image: gpg-pubkey-<shortid>-<date>
            for p in st["pkgs"]:
                if p.name == "gpg-pubkey":
                    label = p.summary.removeprefix("gpg(").removesuffix(")")
                    self.trusted_keys.setdefault("short:" + p.version.lower(), label)

        repos: dict = {}
        for path in DNF_HISTORY:
            if path.endswith(".sqlite") and (db := self.w.content(path)):
                try:
                    repos = rpm.read_dnf_history(db, self.w.content(path + "-wal"))
                except Exception:
                    repos = {}
        vendors = Counter(p.vendor for st in final.values() for p in st["pkgs"] if p.name != "gpg-pubkey")
        primary = vendors.most_common(1)[0][0] if vendors else ""

        for st in sorted(final.values(), key=lambda s: s["pkgs"][0].name):
            for p in st["pkgs"]:
                if p.name == "gpg-pubkey":
                    continue
                c = Component(
                    self._id("rpm", p.name, p.evr),
                    p.name,
                    p.evr,
                    "rpm",
                    suppliers.rpm_vendor_label(p.vendor),
                    layer=st["layer"],
                    introduced_layer=st["introduced"],
                    change=st["change"],
                    previous_version=st["prev"],
                    license=p.license,
                    purl=f"pkg:rpm/{p.name}@{p.evr}?arch={p.arch}",
                )
                repo = repos.get((p.name, f"{p.version}-{p.release}", p.arch), "")
                c.source = suppliers.rpm_repo_label(repo) if repo else ""
                if p.vendor:
                    c.evidence.append(f"Vendor field in package: {p.vendor}")
                if p.buildhost:
                    c.evidence.append(f"Built on host: {p.buildhost}")
                if p.sourcerpm:
                    c.evidence.append(f"Source package: {p.sourcerpm}")
                if repo:
                    c.evidence.append(f"Installed from repository: {repo}")
                key_label = self._key_label(p.sig_key_id)
                if p.sig_key_id:
                    c.evidence.append(
                        f"Signed with key {p.sig_key_id.upper()}"
                        + (f" ({key_label})" if key_label else " (key not recognised)")
                    )
                    if not key_label:
                        c.flags.append({"severity": "low", "message": "Signed by a key that is not a known vendor key"})
                else:
                    c.flags.append({"severity": "medium", "message": "Package is not signed by any vendor key"})
                if repo == "@commandline":
                    c.flags.append(
                        {
                            "severity": "medium",
                            "message": "Installed from a loose RPM file instead of a vendor repository",
                        }
                    )
                if primary and p.vendor != primary:
                    c.flags.append(
                        {
                            "severity": "low",
                            "message": f"Third-party package: supplied by "
                            f"{suppliers.rpm_vendor_label(p.vendor)}, not {suppliers.rpm_vendor_label(primary)}",
                        }
                    )
                self._add(c)
                for f in p.files:
                    self.owner[self.w.resolve(f)] = c.id

    def _key_label(self, kid: str) -> str:
        if not kid:
            return ""
        return self.trusted_keys.get(kid.lower()) or self.trusted_keys.get("short:" + kid.lower()[-8:], "")

    # ---- dpkg

    def _dpkg(self) -> None:
        snaps = []
        md5sums: dict[str, str] = {}  # package -> its status.d md5sums file (distroless has no info/*.list)
        for ls in self.w.layers:
            if any(p == "var/lib/dpkg/status" or p.startswith("var/lib/dpkg/status.d/") for p in ls.captured):
                pkgs = []
                status = self.w.content_at("var/lib/dpkg/status", ls.index)
                if status:
                    pkgs += ecosystems.parse_dpkg_status(status)
                sd = {
                    p
                    for lyr in self.w.layers[: ls.index + 1]
                    for p in lyr.captured
                    if p.startswith("var/lib/dpkg/status.d/")
                }
                for p in sorted(sd):
                    if not p.endswith(".md5sums") and (data := self.w.content_at(p, ls.index)):
                        entry = ecosystems.parse_dpkg_status(data)
                        pkgs += entry
                        for pkg in entry:
                            md5sums[pkg["Package"]] = p + ".md5sums"
                snaps.append((ls.index, pkgs))
        if not snaps:
            return
        final, removed = _track(
            snaps, lambda p: (p["Package"], p.get("Architecture", "")), lambda p: p.get("Version", "")
        )
        self.removed_packages += [{"layer": lyr, "name": n, "version": v, "ecosystem": "deb"} for lyr, n, v in removed]
        distro = suppliers.distro_label(self.os_release)
        for st in sorted(final.values(), key=lambda s: s["pkgs"][0]["Package"]):
            for p in st["pkgs"]:
                name, ver, arch = p["Package"], p.get("Version", ""), p.get("Architecture", "")
                c = Component(
                    self._id("deb", name, ver),
                    name,
                    ver,
                    "deb",
                    distro,
                    layer=st["layer"],
                    introduced_layer=st["introduced"],
                    change=st["change"],
                    previous_version=st["prev"],
                    purl=f"pkg:deb/{self.os_release.get('ID', 'debian')}/{name}@{ver}?arch={arch}",
                )
                if p.get("Maintainer"):
                    c.evidence.append(f"Maintainer: {p['Maintainer']}")
                    if not _distro_maintainer(p["Maintainer"], self.os_release):
                        c.supplier = f"{p['Maintainer'].split('<')[0].strip()} (third party)"
                        c.flags.append(
                            {"severity": "low", "message": f"Third-party package, not maintained by {distro}"}
                        )
                if p.get("Source"):
                    c.evidence.append(f"Source package: {p['Source']}")
                self._add(c)
                files = []
                for lp in (f"var/lib/dpkg/info/{name}.list", f"var/lib/dpkg/info/{name}:{arch}.list"):
                    if data := self.w.content(lp):
                        files += ecosystems.parse_dpkg_list(data)
                if not files and name in md5sums and (data := self.w.content(md5sums[name])):
                    files = ecosystems.parse_dpkg_md5sums(data)
                for f in files:
                    self.owner[self.w.resolve(f)] = c.id

    # ---- apk

    def _apk(self) -> None:
        snaps = [
            (ls.index, ecosystems.parse_apk_installed(ls.captured["lib/apk/db/installed"]))
            for ls in self.w.layers
            if "lib/apk/db/installed" in ls.captured
        ]
        if not snaps:
            return
        final, removed = _track(snaps, lambda p: (p["P"], p.get("A", "")), lambda p: p.get("V", ""))
        self.removed_packages += [{"layer": lyr, "name": n, "version": v, "ecosystem": "apk"} for lyr, n, v in removed]
        distro = suppliers.distro_label(self.os_release)
        for st in sorted(final.values(), key=lambda s: s["pkgs"][0]["P"]):
            for p in st["pkgs"]:
                c = Component(
                    self._id("apk", p["P"], p.get("V", "")),
                    p["P"],
                    p.get("V", ""),
                    "apk",
                    distro,
                    layer=st["layer"],
                    introduced_layer=st["introduced"],
                    change=st["change"],
                    previous_version=st["prev"],
                    license=p.get("L", ""),
                    purl=f"pkg:apk/{self.os_release.get('ID', 'alpine')}/{p['P']}@{p.get('V', '')}",
                )
                if p.get("o"):
                    c.evidence.append(f"Source package: {p['o']}")
                if p.get("m"):
                    c.evidence.append(f"Maintainer: {p['m']}")
                self._add(c)
                for f in p["files"]:
                    self.owner[self.w.resolve(f)] = c.id

    # ---- language ecosystems

    def _os_owner(self, path: str) -> Component | None:
        cid = self.owner.get(path)
        return self.by_id.get(cid) if cid else None

    def _managed(self, c: Component, path: str) -> None:
        owner = self._os_owner(path)
        if owner:
            c.managed_by = f"{owner.ecosystem}:{owner.name}"
            c.supplier = f"{owner.supplier} (bundled in OS package {owner.name})"
            c.evidence.append(f"Installed as part of OS package {owner.name} {owner.version}")
            c.layer = owner.layer

    def _python(self) -> None:
        for path in sorted(self.w.files):
            base = posixpath.basename(path)
            is_egg_file = path.endswith(".egg-info") and self.w.files[path].kind == "f"
            if not (
                base in ("METADATA", "PKG-INFO")
                and path.rsplit("/", 2)[-2].endswith((".dist-info", ".egg-info"))
                or is_egg_file
            ):
                continue
            data = self.w.content(path)
            if not data:
                continue
            meta = ecosystems.parse_python_metadata(data)
            if not meta["Name"]:
                continue
            dist = path if is_egg_file else posixpath.dirname(path)
            site = posixpath.dirname(dist)
            rec = self.w.files[path]
            c = Component(
                self._id("python", meta["Name"], meta["Version"]),
                meta["Name"],
                meta["Version"],
                "python",
                "PyPI (Python Package Index)",
                layer=rec.layer,
                introduced_layer=rec.layer,
                paths=[dist],
                license=meta["License"][:120],
                purl=f"pkg:pypi/{ecosystems.normalize_pypi(meta['Name'])}@{meta['Version']}",
            )
            installer = (self.w.content(f"{dist}/INSTALLER") or b"").decode(errors="replace").strip()
            direct = self.w.content(f"{dist}/direct_url.json")
            if installer:
                c.evidence.append(f"Installed by: {installer}")
            if direct:
                url = re.search(rb'"url"\s*:\s*"([^"]+)"', direct)
                u = url.group(1).decode(errors="replace") if url else ""
                if u.startswith("file:"):
                    c.supplier = "Local source code (not from a package index)"
                    c.flags.append(
                        {"severity": "low", "message": "Installed from local files rather than a package index"}
                    )
                else:
                    c.supplier = f"Direct download from {u}"
                    c.flags.append({"severity": "low", "message": "Installed straight from a URL, not a package index"})
                c.source = u
            elif installer == "conda":
                c.supplier = "Conda package channel"
            elif not installer and not self._os_owner(path):
                c.evidence.append("No installer recorded")
            self._managed(c, path)
            self._add(c)
            record = self.w.content(f"{dist}/RECORD")
            if record:
                for entry in ecosystems.parse_record(record):
                    self.lang_owned.add(posixpath.normpath(posixpath.join(site, entry)))

    def _npm(self) -> None:
        for path in sorted(self.w.files):
            if not path.endswith("/package.json") or "node_modules/" not in path:
                continue
            data = self.w.content(path)
            meta = ecosystems.parse_package_json(data) if data else None
            if not meta:
                continue
            rec = self.w.files[path]
            pkg_dir = posixpath.dirname(path)
            self.npm_dirs.add(pkg_dir)
            name = meta["name"]
            c = Component(
                self._id("npm", name, meta["version"]),
                name,
                meta["version"],
                "npm",
                suppliers.registry_from_url(meta["resolved"], "npm public registry (npmjs.com)"),
                source=meta["resolved"],
                layer=rec.layer,
                introduced_layer=rec.layer,
                paths=[pkg_dir],
                license=meta["license"],
                purl=f"pkg:npm/{name.replace('@', '%40')}@{meta['version']}",
            )
            if meta["repository"]:
                c.evidence.append(f"Source repository: {meta['repository']}")
            self._managed(c, path)
            self._add(c)

    def _java(self) -> None:
        for path, rec in sorted(self.w.files.items()):
            found = self.w.layers[rec.layer].java.get(path) if rec.kind == "f" else None
            if not found:
                continue
            for j in found:
                name = (
                    f"{j['group']}:{j['artifact']}"
                    if j["group"] and j["evidence"] == "pom.properties"
                    else j["artifact"]
                )
                c = Component(
                    self._id("java", name, j["version"]),
                    name,
                    j["version"],
                    "java",
                    suppliers.java_supplier(j["group"], j["evidence"]),
                    layer=rec.layer,
                    introduced_layer=rec.layer,
                    paths=[j["inner"]],
                    purl=(
                        f"pkg:maven/{j['group']}/{j['artifact']}@{j['version']}"
                        if j["evidence"] == "pom.properties"
                        else ""
                    ),
                )
                c.evidence.append(f"Identified from {j['evidence']}")
                if j["inner"] != path:
                    c.parent = path
                    c.evidence.append(f"Bundled inside {path}")
                self._managed(c, path)
                self._add(c)

    # ---- binaries

    def _in_npm(self, path: str) -> bool:
        d = posixpath.dirname(path)
        while d:
            if d in self.npm_dirs:
                return True
            d = posixpath.dirname(d)
        return False

    def _binaries(self) -> None:
        unowned_by_layer: dict[int, int] = Counter()
        replaced: dict[str, list[str]] = defaultdict(list)
        comp_by_id = self.by_id
        for path, rec in sorted(self.w.files.items()):
            if not rec.elf or rec.kind not in ("f", "h"):
                continue
            owner_id = self.owner.get(path)
            if owner_id:
                owner = comp_by_id.get(owner_id)
                if owner and rec.layer > owner.layer and rec.kind == "f":
                    replaced[owner_id].append(f"{path} (layer {rec.layer + 1})")
            if rec.go:
                g = rec.go
                main_mod, main_ver = g["main"] or ("", "")
                name = g["path"] or posixpath.basename(path)
                c = Component(
                    self._id("go-binary", name, main_ver or g["go_version"]),
                    name,
                    main_ver if main_ver and main_ver != "(devel)" else "",
                    "go-binary",
                    f"Compiled Go program ({main_mod or name})",
                    layer=rec.layer,
                    introduced_layer=rec.layer,
                    paths=[path],
                    evidence=[f"Built with {g['go_version']}", f"SHA-256 {rec.sha256}"],
                )
                if g.get("settings", {}).get("vcs.revision"):
                    c.evidence.append(f"Source revision {g['settings']['vcs.revision']}")
                if owner_id:
                    self._managed(c, path)
                else:
                    c.flags.append(
                        {
                            "severity": "low",
                            "message": "Program was copied in directly, not installed by a package manager",
                        }
                    )
                self._add(c)
                for mod, ver in g["deps"]:
                    m = Component(
                        self._id("go-module", mod, ver),
                        mod,
                        ver,
                        "go-module",
                        suppliers.go_module_supplier(mod),
                        layer=rec.layer,
                        introduced_layer=rec.layer,
                        paths=[path],
                        parent=path,
                        purl=f"pkg:golang/{mod}@{ver}",
                        evidence=[f"Compiled into {path}"],
                    )
                    if c.managed_by:
                        m.managed_by = c.managed_by
                    self._add(m)
                c.evidence.append(f"Contains {len(g['deps'])} third-party Go modules")
                c.purl = f"pkg:golang/{main_mod}@{main_ver}" if main_mod else ""
                continue
            if owner_id or path in self.lang_owned or self._in_npm(path):
                continue
            unowned_by_layer[rec.layer] += 1
            c = Component(
                self._id("binary", posixpath.basename(path), ""),
                posixpath.basename(path),
                "",
                "binary",
                "Unknown - not installed by any package manager",
                layer=rec.layer,
                introduced_layer=rec.layer,
                paths=[path],
                evidence=[f"SHA-256 {rec.sha256}"] if rec.sha256 else [],
            )
            c.flags.append(
                {
                    "severity": "medium",
                    "message": "No package record: this file can only be traced to the build step that added it",
                }
            )
            self._add(c)
        for cid, paths in replaced.items():
            c = comp_by_id[cid]
            c.flags.append(
                {
                    "severity": "medium",
                    "message": f"{len(paths)} program file(s) from this package were "
                    f"replaced after installation: " + ", ".join(paths[:3]),
                }
            )


def _distro_maintainer(maintainer: str, os_release: dict) -> bool:
    m = maintainer.lower()
    if (os_release.get("ID") or "").lower() == "ubuntu":
        return "ubuntu" in m or "canonical" in m or "debian" in m
    return True  # Debian maintainers are individuals; third parties cannot be told apart reliably


def as_dict(c: Component) -> dict:
    d = asdict(c)
    d["type_label"] = c.type_label
    return d
