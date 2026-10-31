"""Import vulnerability findings (Trivy, Grype, Harbor) and attribute each one to an origin.

The scanner says *what* is vulnerable; this module answers *who put it there*, by
tying each finding to the component (and therefore the layer) we traced earlier.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path

from . import scanners
from .parsers.ecosystems import normalize_pypi

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# What the software vendor says about fixing each vulnerability, normalised across scanners.
# Ordered from most to least actionable; the labels are what the report shows.
FIX_STATUSES = {
    "fixed": "Fix available",
    "affected": "No fix released yet",
    "fix_deferred": "Fix deferred by vendor",
    "will_not_fix": "Vendor will not fix",
    "end_of_life": "No longer supported by vendor",
    "under_investigation": "Vendor still investigating",
    "not_affected": "Vendor says not affected",
    "unknown": "No fix listed",
}
_FIX_ALIASES = {
    "not_fixed": "affected",  # Grype
    "wont_fix": "will_not_fix",  # Grype
    "won't_fix": "will_not_fix",
    "deferred": "fix_deferred",
    "eol": "end_of_life",
}


def fix_status(raw: str | None, fixed_version: str) -> str:
    """Normalise a scanner's fix state. A known fixed version always means a fix is available."""
    if fixed_version:
        return "fixed"
    s = (raw or "").strip().lower().replace("-", "_").replace(" ", "_")
    s = _FIX_ALIASES.get(s, s)
    if s == "fixed":  # status says fixed but no version was given
        return "fixed"
    return s if s in FIX_STATUSES else "unknown"


@dataclass
class Vuln:
    id: str
    severity: str
    package: str
    version: str
    fixed_version: str
    title: str
    path: str = ""
    layer: int | None = None
    component_id: str = ""
    origin: str = "unknown"
    tool: str = ""
    attribution: str = ""  # how the layer was determined
    fix_status: str = "unknown"  # key of FIX_STATUSES
    purl: str = ""  # package URL, as the scanner reported it
    ecosystem: str = ""  # see _ecosystem(); empty when the scanner doesn't say
    match: str = "none"  # purl | name+ecosystem+version | name+version | prefix | layer | none

    def to_dict(self) -> dict:
        return asdict(self)


# Package URL types and scanner package types, as the ecosystem names below. Anything else stays as it is: wimi traces
# no such components (Ruby gems, Rust crates, ...), so a finding of that type can't match a same-named package.
_ECOSYSTEM_ALIASES = {
    "rpm": (
        "redhat",
        "centos",
        "rocky",
        "alma",
        "amazon",
        "oracle",
        "fedora",
        "suse",
        "opensuse",
        "photon",
        "azurelinux",
    ),
    "deb": ("debian", "ubuntu"),
    "apk": ("alpine", "wolfi", "chainguard"),
    "python": ("pypi", "python-pkg", "pip", "pipenv", "poetry", "uv"),
    "npm": ("node-pkg", "yarn", "pnpm", "bun"),
    "java": ("maven", "jar", "pom", "gradle", "sbt", "java-archive", "jenkins-plugin"),
    "go": ("golang", "gobinary", "gomod", "go-module"),
}
_ECOSYSTEMS = {alias: eco for eco, aliases in _ECOSYSTEM_ALIASES.items() for alias in (eco, *aliases)}
_COMPONENT_ECOSYSTEMS = {"go": ("go-binary", "go-module")}
_OS_PURL_TYPES = ("rpm", "deb", "apk")  # their namespace is the distribution, which scanners and wimi name differently


def _ecosystem(package_type: str | None) -> str:
    t = (package_type or "").lower()
    if t.startswith(("cbl-mariner", "sles", "suse")):
        return "rpm"
    return _ECOSYSTEMS.get(t, t)


def _purl_ecosystem(purl: str) -> str:
    return _ecosystem(purl[4:].split("/", 1)[0]) if purl.startswith("pkg:") else ""


def _sev(s: str) -> str:
    s = (s or "UNKNOWN").upper()
    return {"NEGLIGIBLE": "LOW", "MODERATE": "MEDIUM", "IMPORTANT": "HIGH"}.get(s, s if s in SEVERITIES else "UNKNOWN")


def parse_trivy(doc: dict, diff_index: dict[str, int]) -> list[Vuln]:
    out = []
    for res in doc.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            layer = diff_index.get((v.get("Layer") or {}).get("DiffID", ""))
            fixed = v.get("FixedVersion", "") or ""
            purl = (v.get("PkgIdentifier") or {}).get("PURL") or ""
            out.append(
                Vuln(
                    v.get("VulnerabilityID", ""),
                    _sev(v.get("Severity")),
                    v.get("PkgName", ""),
                    v.get("InstalledVersion", ""),
                    fixed,
                    (v.get("Title") or v.get("Description") or "")[:240],
                    v.get("PkgPath") or "",
                    layer,
                    tool="Trivy",
                    fix_status=fix_status(v.get("Status"), fixed),
                    purl=purl,
                    ecosystem=_purl_ecosystem(purl) or _ecosystem(res.get("Type")),
                )
            )
    return out


def parse_grype(doc: dict, diff_index: dict[str, int]) -> list[Vuln]:
    out = []
    for m in doc.get("matches") or []:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        layer, path = None, ""
        for loc in a.get("locations") or []:
            path = path or loc.get("path", "")
            if loc.get("layerID") in diff_index:
                layer = diff_index[loc["layerID"]]
                break
        fix = v.get("fix") or {}
        fixed = ", ".join(fix.get("versions") or [])
        out.append(
            Vuln(
                v.get("id", ""),
                _sev(v.get("severity")),
                a.get("name", ""),
                a.get("version", ""),
                fixed,
                (v.get("description") or "")[:240],
                path.lstrip("/"),
                layer,
                tool="Grype",
                fix_status=fix_status(fix.get("state"), fixed),
                purl=a.get("purl") or "",
                ecosystem=_purl_ecosystem(a.get("purl") or "") or _ecosystem(a.get("type")),
            )
        )
    return out


def parse_harbor(doc: dict, diff_index: dict[str, int]) -> list[Vuln]:
    reports = [doc] if "vulnerabilities" in doc else [r for r in doc.values() if isinstance(r, dict)]
    out = []
    for rep in reports:
        for v in rep.get("vulnerabilities") or []:
            layer = diff_index.get((v.get("layer") or {}).get("diff_id", ""))
            out.append(
                Vuln(
                    v.get("id", ""),
                    _sev(v.get("severity")),
                    v.get("package", ""),
                    v.get("version", ""),
                    v.get("fix_version", "") or "",
                    (v.get("description") or "")[:240],
                    "",
                    layer,
                    tool="Harbor (Trivy)",
                    # Harbor's report carries no vendor status, only a fixed version when there is one.
                    fix_status=fix_status(None, v.get("fix_version", "") or ""),
                )
            )
    return out


def load_report(path: Path, diff_index: dict[str, int]) -> list[Vuln]:
    doc = json.loads(path.read_text())
    if isinstance(doc, dict) and "Results" in doc:
        return parse_trivy(doc, diff_index)
    if isinstance(doc, dict) and "matches" in doc:
        return parse_grype(doc, diff_index)
    if isinstance(doc, dict):
        return parse_harbor(doc, diff_index)
    raise ValueError(f"{path} is not a Trivy, Grype or Harbor vulnerability report")


def run_scanner(which: str, image, log) -> tuple[str, list[Vuln], dict] | None:
    """Run Trivy or Grype against the exact layers we analysed: the installed binary if there is one, otherwise the
    scanner's container image if a container engine is reachable (see scanners.py). Returns (tool, findings, info),
    where info describes how the scan ran (binary or container, version, database date) for the report."""
    diff_index = {d: i for i, d in enumerate(image.diff_ids)}
    res = scanners.run(which, image.write_docker_archive, log)
    if res is None:
        return None
    parse = parse_trivy if res.tool == "trivy" else parse_grype
    return res.tool, parse(res.doc, diff_index), res.info


def fetch_harbor(image, log) -> list[Vuln] | None:
    """Pull the vulnerability report Harbor already produced for this artifact."""
    client = image.registry_client
    if client is None:
        log("  --harbor-vulns needs an image pulled from the Harbor registry")
        return None
    project, _, repo = client.ref.repository.partition("/")
    repo_enc = urllib.parse.quote(urllib.parse.quote(repo, safe=""), safe="")
    diff_index = {d: i for i, d in enumerate(image.diff_ids)}
    for digest in filter(None, (image.manifest_digest, image.index_digest)):
        url = (
            f"https://{client.ref.registry}/api/v2.0/projects/{project}/repositories/{repo_enc}"
            f"/artifacts/{digest}/additions/vulnerabilities"
        )
        try:
            doc = client.get_json(url)
        except Exception as e:
            log(f"  Harbor report not available for {digest[:19]}: {e}")
            continue
        vulns = parse_harbor(doc, diff_index)
        if vulns or doc:
            return vulns
    return None


# --------------------------------------------------------------------------- attribution


def _strip_epoch(v: str) -> str:
    return re.sub(r"^\d+:", "", v or "")


def _norm_name(name: str, eco: str) -> str:
    return normalize_pypi(name) if eco == "python" else name.lower()


def _purl_key(purl: str) -> tuple[tuple[str, str, str], str] | None:
    """(type, name, version) and the architecture, normalised so that a scanner's package URL and ours can be compared.
    The two spell a distribution differently (redhat, rhel, none) and put the epoch in different places."""
    if not purl.startswith("pkg:"):
        return None
    path, _, query = purl[4:].partition("#")[0].partition("?")
    path, _, version = path.rpartition("@")
    kind, _, name = path.partition("/")
    name = urllib.parse.unquote(name).lower()
    if kind in _OS_PURL_TYPES:
        name = name.rsplit("/", 1)[-1]
    elif kind == "pypi":
        name = normalize_pypi(name)
    version = _strip_epoch(urllib.parse.unquote(version))
    return (kind, name, version), urllib.parse.parse_qs(query).get("arch", [""])[0]


def _same_ecosystem(v: Vuln, c: dict) -> bool:
    return c["ecosystem"] in _COMPONENT_ECOSYSTEMS.get(v.ecosystem, (v.ecosystem,))


def _prefix_of(short: str, long: str) -> bool:
    """1.2 is a prefix of 1.2.3 and 1.2-4, but not of 1.24.0."""
    return bool(short) and long.startswith(short) and not long[len(short) :][:1].isalnum()


def _match(v: Vuln, by_name: dict, by_purl: dict) -> tuple[list[dict], str]:
    """The components a finding could be, and how they were matched, from the strongest evidence to the weakest."""
    key = _purl_key(v.purl)
    if key:
        arch = key[1]
        cands = [c for c, c_arch in by_purl.get(key[0], []) if not (arch and c_arch and arch != c_arch)]
        if cands:
            return cands, "purl"
    named = by_name.get(v.package.lower()) or by_name.get(normalize_pypi(v.package)) or []
    if v.ecosystem:  # a known ecosystem rules out same-named packages from any other
        named = [c for c in named if _same_ecosystem(v, c)]
    ver = _strip_epoch(v.version)
    exact = [c for c in named if _strip_epoch(c["version"]) == ver]
    if exact:
        return exact, "name+ecosystem+version" if v.ecosystem else "name+version"
    prefix = [
        c for c in named if _prefix_of(ver, _strip_epoch(c["version"])) or _prefix_of(_strip_epoch(c["version"]), ver)
    ]
    # some scanners shorten version strings, but the layer a scanner reports is better evidence than a shortened version
    if prefix and (v.layer is None or any(c["layer"] == v.layer for c in prefix)):
        return prefix, "prefix"
    return [], "layer" if v.layer is not None else "none"


def _pick(v: Vuln, cands: list[dict]) -> list[dict]:
    """Narrow several candidates with the scanner's evidence: the layer it reported, then the file path."""
    cands = [c for c in cands if c["layer"] == v.layer] or cands
    if v.path:
        cands = [c for c in cands if any(v.path.startswith(p) or p.startswith(v.path) for p in c["paths"])] or cands
    return cands


def attribute(vulns: list[Vuln], components: list[dict], per_layer: list[str]) -> None:
    by_name: dict[str, list[dict]] = {}
    by_purl: dict[tuple[str, str, str], list[tuple[dict, str]]] = {}
    for c in components:
        by_name.setdefault(_norm_name(c["name"], c["ecosystem"]), []).append(c)
        if c["ecosystem"] == "java" and ":" in c["name"]:
            by_name.setdefault(c["name"].split(":", 1)[1].lower(), []).append(c)
        key = _purl_key(c["purl"])
        if key:
            by_purl.setdefault(key[0], []).append((c, key[1]))
    for v in vulns:
        cands, v.match = _match(v, by_name, by_purl)
        if cands:
            cands = _pick(v, cands)
            c = cands[0]
            v.component_id, v.layer = c["id"], c["layer"]
            if len({other["layer"] for other in cands}) > 1:  # nothing says which copy; don't present it as proof
                v.attribution = f"matched to one of {len(cands)} copies in different layers"
            elif v.match == "prefix":
                v.attribution = "matched to traced component by a shortened version"
            else:
                v.attribution = "matched to traced component"
        elif v.layer is not None:
            v.attribution = f"layer reported by {v.tool}"
        else:
            v.attribution = "could not be attributed"
        v.origin = per_layer[v.layer] if v.layer is not None and 0 <= v.layer < len(per_layer) else "unknown"
