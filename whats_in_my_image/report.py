"""Assemble the analysis into one report model, including plain-English conclusions."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timezone

from . import __version__, describe
from .analyze import OS_ECOSYSTEMS, TYPE_LABELS, as_dict
from .sources import human_size
from .vulns import FIX_STATUSES, SEVERITIES

SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _pct(a: int, b: int) -> str:
    return f"{round(100 * a / b)}%" if b else "0%"


def _be(n: int, past: bool = False) -> str:
    return ("was" if n == 1 else "were") if past else ("is" if n == 1 else "are")


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n:,} {word if n == 1 else (plural or word + 's')}"


def build(image, walker, analyzer, origins, per_layer, notes, vulns, vuln_tool, app_name, vuln_scan=None) -> dict:
    history, aligned = image.layer_history()
    comps = [as_dict(c) for c in analyzer.components]
    origin_by_key = {o.key: o for o in origins}
    if not aligned:
        notes = notes + [
            "This image's build history does not line up with its layers (it may have been squashed "
            "or assembled by a tool). Build-step descriptions may be missing or shifted."
        ]

    # ---- layers
    layers = []
    comp_per_layer = Counter(c["layer"] for c in comps)
    vuln_per_layer = Counter(v.layer for v in vulns or [] if v.layer is not None)
    for layer, h, ls in zip(image.layers, history, walker.layers):
        d = describe.describe(h.get("created_by", ""), h.get("comment", ""))
        if d["instruction"] in describe.METADATA_INSTRUCTIONS:
            d["summary"] = (
                "Several build steps were combined (squashed) into this layer, so the individual "
                "commands were not recorded"
            )
        okey = per_layer[layer.index]
        layers.append(
            {
                "index": layer.index,
                "number": layer.index + 1,
                "diff_id": layer.diff_id,
                "digest": layer.digest,
                "size": layer.size,
                "size_h": human_size(layer.size),
                "created": h.get("created", ""),
                "origin": okey,
                "origin_label": origin_by_key[okey].label if okey in origin_by_key else okey,
                "origin_kind": origin_by_key[okey].kind if okey in origin_by_key else "unknown",
                **d,
                "files_added": ls.added,
                "files_replaced": ls.replaced,
                "files_metadata_only": ls.metadata_only,
                "files_deleted": ls.deleted,
                "components": comp_per_layer.get(layer.index, 0),
                "vulns": vuln_per_layer.get(layer.index, 0),
                "content_summary": _content_summary([c for c in comps if c["layer"] == layer.index], ls),
                "config_steps": [
                    describe.clean_command(m.get("created_by", ""))[0] for m in h.get("metadata_steps", [])
                ],
                "error": ls.error,
            }
        )

    # ---- origins with stats
    vdicts = [v.to_dict() for v in vulns] if vulns is not None else None
    olist = []
    for o in origins:
        mine = [c for c in comps if c["origin"] == o.key]
        ov = [v for v in vdicts or [] if v["origin"] == o.key]
        olist.append(
            {
                "key": o.key,
                "label": o.label,
                "kind": o.kind,
                "reference": o.reference,
                "match": o.match,
                "note": o.note,
                "layers": [lyr + 1 for lyr in o.layers],
                "size": sum(image.layers[lyr].size for lyr in o.layers),
                "components": len(mine),
                "by_type": dict(Counter(c["ecosystem"] for c in mine)),
                "vulns": {s: sum(1 for v in ov if v["severity"] == s) for s in SEVERITIES},
                "vulns_total": len(ov),
                "vulns_fixable": sum(1 for v in ov if v["fix_status"] == "fixed"),
                "vulns_by_fix": dict(Counter(v["fix_status"] for v in ov)),
            }
        )
    if vdicts and any(v["origin"] == "unknown" for v in vdicts) and "unknown" not in origin_by_key:
        ov = [v for v in vdicts if v["origin"] == "unknown"]
        olist.append(
            {
                "key": "unknown",
                "label": "Could not be attributed",
                "kind": "unknown",
                "reference": "",
                "match": "",
                "note": "",
                "layers": [],
                "size": 0,
                "components": 0,
                "by_type": {},
                "vulns": {s: sum(1 for v in ov if v["severity"] == s) for s in SEVERITIES},
                "vulns_total": len(ov),
                "vulns_fixable": sum(1 for v in ov if v["fix_status"] == "fixed"),
                "vulns_by_fix": dict(Counter(v["fix_status"] for v in ov)),
            }
        )

    findings = _findings(comps, layers, vdicts, origin_by_key, notes)
    model = {
        "tool": {"name": "What's In My Image", "version": __version__},
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "image": {
            "name": image.name,
            "source": image.source,
            "digest": image.manifest_digest or "",
            "index_digest": image.index_digest or "",
            "platform": image.platform,
            "created": image.created,
            "os": analyzer.os_release.get("PRETTY_NAME", ""),
            "size": sum(lyr.size for lyr in image.layers),
            "size_h": human_size(sum(lyr.size for lyr in image.layers)),
            "layer_count": len(image.layers),
            "labels": image.labels,
        },
        "app_name": app_name,
        "origins": olist,
        "layers": layers,
        "components": comps,
        "vulns": vdicts,
        "vuln_tool": vuln_tool,
        "vuln_scan": _scan_details(vuln_scan),
        "findings": findings,
        "notes": notes + analyzer.notes,
        "removed_packages": analyzer.removed_packages,
        "type_labels": TYPE_LABELS,
        "fix_status_labels": FIX_STATUSES,
    }
    model["takeaways"] = _takeaways(model)
    return model


_NOUNS = {
    "rpm": ("OS package", "OS packages"),
    "deb": ("OS package", "OS packages"),
    "apk": ("OS package", "OS packages"),
    "python": ("Python library", "Python libraries"),
    "npm": ("JavaScript library", "JavaScript libraries"),
    "java": ("Java library", "Java libraries"),
    "go-binary": ("Go program", "Go programs"),
    "go-module": ("compiled-in Go library", "compiled-in Go libraries"),
    "binary": ("untraceable program file", "untraceable program files"),
}


def _content_summary(comps: list[dict], ls) -> str:
    """Describe a layer by what it actually contains, independent of the recorded build command."""
    added, changed = Counter(), Counter()
    for c in comps:
        noun = _NOUNS.get(c["ecosystem"], (c["ecosystem"], c["ecosystem"]))
        (changed if c["change"] in ("upgraded", "downgraded", "changed") else added)[noun] += 1
    parts = []
    for verb, counter in (("added", added), ("updated", changed)):
        items = [f"{n:,} {noun[0] if n == 1 else noun[1]}" for noun, n in counter.most_common()]
        if items:
            parts.append(f"{verb} " + (", ".join(items[:-1]) + " and " + items[-1] if len(items) > 1 else items[0]))
    if not parts and (ls.added or ls.replaced or ls.deleted or not ls.metadata_only):
        parts.append(f"no software components; {ls.added + ls.replaced:,} file(s) written, {ls.deleted:,} removed")
    if ls.metadata_only:
        parts.append(
            f"changed only the permissions, ownership or timestamps of {ls.metadata_only:,} existing file(s) "
            "(their contents are still credited to the layers that wrote them)"
        )
    text = "; ".join(parts)
    return text[0].upper() + text[1:]


def _is_base_warning(note: str) -> bool:
    return (
        "NOT built on" in note
        or "Only the first" in note
        or note.startswith(("Possible unidentified base", "Outdated base"))
    )


def _no_fix_reasons(vulns) -> str:
    """'the vendor has not released one yet for 40, has deferred 12 and will not fix 5'"""
    c = Counter(v["fix_status"] for v in vulns)
    phrases = [
        ("affected", "has not released one yet for {}"),
        ("fix_deferred", "has deferred {}"),
        ("will_not_fix", "will not fix {}"),
        ("end_of_life", "no longer supports {}"),
        ("under_investigation", "is still investigating {}"),
    ]
    parts = [text.format(f"{c[k]:,}") for k, text in phrases if c[k]]
    if not parts:
        return "the scanner lists no fixed version"
    sentence = ", ".join(parts[:-1]) + (" and " if len(parts) > 1 else "") + parts[-1]
    if c["unknown"]:
        sentence += f"; no reason is given for {c['unknown']:,}"
    return "the vendor " + sentence


def _findings(comps, layers, vulns, origin_by_key, notes) -> list[dict]:
    out = []

    def label(okey):
        return origin_by_key[okey].label if okey in origin_by_key else "Unattributed"

    for lyr in layers:
        for r in lyr["risks"]:
            out.append(
                {
                    "severity": r["severity"],
                    "origin": lyr["origin"],
                    "origin_label": lyr["origin_label"],
                    "title": r["message"],
                    "detail": f"Build step {lyr['number']}: {lyr['summary']}",
                    "items": lyr["urls"] or [lyr["command"][:300]],
                }
            )

    groups: dict = defaultdict(list)
    for c in comps:
        for f in c["flags"]:
            groups[(f["severity"], _flag_family(f["message"]), c["origin"])].append((c, f["message"]))
    for (sev, family, okey), items in groups.items():
        titles = {
            "unmanaged": "program files with no package record (origin traceable only to a build step)",
            "unsigned": "OS packages not signed by any vendor key",
            "unknown-key": "OS packages signed by an unrecognised key",
            "third-party": "packages from third-party suppliers rather than the OS vendor",
            "replaced": "vendor packages whose program files were later replaced",
            "local": "packages installed from local files or direct URLs instead of a repository",
            "copied": "compiled programs copied in directly (not via a package manager)",
        }
        n = len(items)
        out.append(
            {
                "severity": sev,
                "origin": okey,
                "origin_label": label(okey),
                "title": f"{n:,} {titles.get(family, family)}",
                "detail": items[0][1] if family in ("replaced",) else "",
                "items": [
                    f"{c['paths'][0] if c['ecosystem'] == 'binary' and c['paths'] else c['name'] + ' ' + c['version']}"
                    f"  (layer {c['layer'] + 1})"
                    for c, _ in items[:200]
                ],
            }
        )

    if vulns:
        for okey in {v["origin"] for v in vulns}:
            serious = [v for v in vulns if v["origin"] == okey and v["severity"] in ("CRITICAL", "HIGH")]
            fixable = [v for v in serious if v["fix_status"] == "fixed"]
            if fixable:
                kind = origin_by_key[okey].kind if okey in origin_by_key else "unknown"
                how = (
                    "Updating to a newer release of this base image, or running the OS package update in "
                    "your build, may resolve them."
                    if kind == "base"
                    else "These were introduced by this build and can be fixed by updating the affected components."
                )
                out.append(
                    {
                        "severity": "high",
                        "origin": okey,
                        "origin_label": label(okey),
                        "title": f"{len(fixable)} critical/high vulnerabilities with fixes already available",
                        "detail": how,
                        "items": [
                            f"{v['id']}  {v['package']} {v['version']} -> {v['fixed_version']}" for v in fixable[:200]
                        ],
                    }
                )
        sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
        vendor_findings = {
            "end_of_life": (
                "high",
                "in software the vendor no longer supports",
                "No fix will ever be released for these. Replace or upgrade the component; for a base image, move to "
                "a release the vendor still supports.",
            ),
            "will_not_fix": (
                "medium",
                "the vendor has decided not to fix",
                "The vendor has assessed these and will not ship a fix, usually because the risk is low in typical "
                "use. Updating will not remove them. Record a risk decision (for example a VEX statement or POA&M "
                "entry, citing the vendor's assessment) or replace the component.",
            ),
            "fix_deferred": (
                "low",
                "whose fix the vendor has deferred",
                "The vendor plans to fix these in a later release. Track them and pick up the fix when it ships.",
            ),
        }
        for status, (sev, what, detail) in vendor_findings.items():
            for okey in sorted({v["origin"] for v in vulns if v["fix_status"] == status}):
                hits = sorted(
                    (v for v in vulns if v["origin"] == okey and v["fix_status"] == status),
                    key=lambda v: (sev_rank.get(v["severity"], 9), v["id"]),
                )
                out.append(
                    {
                        "severity": sev,
                        "origin": okey,
                        "origin_label": label(okey),
                        "title": f"{_plural(len(hits), 'vulnerability', 'vulnerabilities')} {what}",
                        "detail": detail,
                        "items": [
                            f"{v['id']}  {v['severity'].title()}  {v['package']} {v['version']}" for v in hits[:200]
                        ],
                    }
                )
    for n in notes:
        if _is_base_warning(n):
            out.append(
                {
                    "severity": "medium",
                    "origin": "",
                    "origin_label": "Base image",
                    "title": (
                        "Part of the application build may come from an unidentified base image"
                        if n.startswith("Possible unidentified base")
                        else "The base image is out of date"
                        if n.startswith("Outdated base")
                        else "Image does not match the base image specified"
                    ),
                    "detail": n,
                    "items": [],
                }
            )
    upgraded = [c for c in comps if c["change"] in ("upgraded", "downgraded") and c["ecosystem"] in OS_ECOSYSTEMS]
    by_o = defaultdict(list)
    for c in upgraded:
        by_o[(c["origin"], c["change"])].append(c)
    for (okey, change), items in by_o.items():
        out.append(
            {
                "severity": "info" if change == "upgraded" else "medium",
                "origin": okey,
                "origin_label": label(okey),
                "title": f"{_plural(len(items), 'OS package')} {change} after "
                f"{'it was' if len(items) == 1 else 'they were'} first installed",
                "detail": "The current version came from this layer, so responsibility for it moved here.",
                "items": [
                    f"{c['name']}: {c['previous_version']} -> {c['version']} (layer {c['layer'] + 1})"
                    for c in items[:200]
                ],
            }
        )
    out.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["origin_label"]))
    return out


def _flag_family(msg: str) -> str:
    m = msg.lower()
    if m.startswith("no package record"):
        return "unmanaged"
    if "not signed" in m:
        return "unsigned"
    if "not a known vendor key" in m:
        return "unknown-key"
    if m.startswith("third-party"):
        return "third-party"
    if "replaced after installation" in m:
        return "replaced"
    if "local" in m or "straight from a url" in m or "loose rpm" in m:
        return "local"
    if "copied in directly" in m:
        return "copied"
    return msg


# Older vulnerability data than this is called out in the bottom line: anything published since is not reported.
DB_AGE_WARN_DAYS = 30


def _scan_details(scan: dict | None) -> dict:
    """How the vulnerability scan ran (binary or container, scanner version, database date), with the database age."""
    if not scan:
        return {}
    out = dict(scan)
    try:
        built = date.fromisoformat(str(scan.get("db_built", ""))[:10])
    except ValueError:
        return out
    out["db_date"] = built.isoformat()
    out["db_age_days"] = max(0, (datetime.now(timezone.utc).date() - built).days)
    return out


def scan_source(m: dict) -> str:
    """One sentence on where the vulnerability data came from, e.g. for the report's vulnerability section."""
    scan = m.get("vuln_scan") or {}
    tool = m.get("vuln_tool") or "imported report"
    if not scan:
        return tool
    how = "installed binary" if scan.get("mode") == "binary" else f"container image {scan.get('image', '')}"
    if scan.get("image_digest"):
        how += f" ({scan['image_digest'].rsplit('@', 1)[-1][:19]})"
    text = f"{tool}, run from the {how}"
    if "db_date" in scan:
        age = scan["db_age_days"]
        text += f"; vulnerability data built {scan['db_date']} ({_plural(age, 'day', 'days')} old)"
    else:
        text += "; the vulnerability data date could not be determined"
    return text


def _takeaways(m: dict) -> list[dict]:
    """The 'bottom line' for executives: short sentences, each backed by numbers in the report."""
    out = []
    comps = m["components"]
    origins = m["origins"]
    base = [o for o in origins if o["kind"] == "base"]
    app = [o for o in origins if o["kind"] == "app"]
    if any(o["label"].lower().startswith("iron bank") for o in base):
        base_name = "Iron Bank"
    elif len(base) == 1 and not base[0]["match"].startswith("estimated"):
        base_name = base[0]["label"]
    else:
        base_name = "the base image"
    estimated = any(o["match"].startswith("estimated") for o in base)
    total = len(comps)
    nb = sum(o["components"] for o in base)
    na = sum(o["components"] for o in app)

    for n in m["notes"]:
        if _is_base_warning(n):
            out.append({"tone": "warn", "text": n})
    if not base:
        out.append(
            {
                "tone": "warn",
                "text": "The base image could not be identified, so components could not be "
                "split between the base and your build. Re-run with --base <the image you build FROM>.",
            }
        )
    else:
        out.append(
            {
                "tone": "neutral",
                "text": f"{base_name[0].upper() + base_name[1:]} supplied "
                f"{_plural(nb, 'component')} ({_pct(nb, total)}) and the application build added "
                f"{_plural(na, 'component')} ({_pct(na, total)}) of the {total:,} found in this image."
                + (" (Base boundary is estimated.)" if estimated else ""),
            }
        )

    vulns = m["vulns"]
    if vulns is not None and base:
        serious = [v for v in vulns if v["severity"] in ("CRITICAL", "HIGH")]
        bkeys = {o["key"] for o in base}
        akeys = {o["key"] for o in app}
        sb = sum(1 for v in serious if v["origin"] in bkeys)
        sa = sum(1 for v in serious if v["origin"] in akeys)
        vb = sum(1 for v in vulns if v["origin"] in bkeys)
        va = sum(1 for v in vulns if v["origin"] in akeys)
        if not vulns:
            out.append({"tone": "good", "text": f"{m['vuln_tool'] or 'The scanner'} found no known vulnerabilities."})
        else:
            out.append(
                {
                    "tone": "neutral",
                    "text": f"Of {_plural(len(vulns), 'known vulnerability', 'known vulnerabilities')}, {vb:,} "
                    f"({_pct(vb, len(vulns))}) {_be(vb)} inherited from {base_name} and "
                    f"{va:,} ({_pct(va, len(vulns))}) "
                    f"{_be(va, past=True)} introduced by the application build.",
                }
            )
            if serious:
                if sa > sb:
                    out.append(
                        {
                            "tone": "bad",
                            "text": f"Most critical/high-severity vulnerabilities ({sa} of {len(serious)}) "
                            "were introduced "
                            f"after the {base_name} base, by the application build. Changing or blaming the base "
                            "image would not resolve them; the application team owns these fixes"
                            + (
                                f" ({fa} already {'has' if fa == 1 else 'have'} a fix available)."
                                if (
                                    fa := sum(1 for v in serious if v["origin"] in akeys and v["fix_status"] == "fixed")
                                )
                                else "."
                            ),
                        }
                    )
                elif sb > sa:
                    bf = sum(1 for v in serious if v["origin"] in bkeys and v["fix_status"] == "fixed")
                    if bf:
                        tail = (
                            f"{bf} of them already {'has' if bf == 1 else 'have'} a fix available: "
                            f"rebuilding on the latest {base_name} "
                            "release, or applying OS updates during the build, should resolve those."
                        )
                    else:
                        why = _no_fix_reasons(v for v in serious if v["origin"] in bkeys)
                        tail = (
                            f"None of them has a fix available ({why}), so no rebuild can remove them today. "
                            "They need a documented risk decision or tracking until the vendor ships fixes."
                        )
                    out.append(
                        {
                            "tone": "bad",
                            "text": f"Most critical/high-severity vulnerabilities ({sb} of {len(serious)}) "
                            "are inherited "
                            f"from {base_name}. {tail}",
                        }
                    )
                else:
                    out.append(
                        {
                            "tone": "neutral",
                            "text": f"Critical/high-severity vulnerabilities are split evenly ({sb} from {base_name}, "
                            f"{sa} from the application build). Both teams have fixes to make.",
                        }
                    )
    if vulns:
        never = Counter(v["fix_status"] for v in vulns if v["fix_status"] in ("will_not_fix", "end_of_life"))
        if never:
            parts = []
            if never["will_not_fix"]:
                parts.append(f"the vendor will not fix {never['will_not_fix']:,}")
            if never["end_of_life"]:
                parts.append(f"{never['end_of_life']:,} are in software the vendor no longer supports")
            n_never = sum(never.values())
            out.append(
                {
                    "tone": "warn",
                    "text": f"{_plural(n_never, 'vulnerability', 'vulnerabilities')} will never be removed by "
                    f"updating: {' and '.join(parts)}. Each needs a documented risk decision (for example a VEX "
                    "statement or POA&M entry) or a different component.",
                }
            )
    scan = m.get("vuln_scan") or {}
    if vulns is not None and scan.get("db_age_days", 0) > DB_AGE_WARN_DAYS:
        out.append(
            {
                "tone": "warn",
                "text": f"The vulnerability data used for this scan is {scan['db_age_days']} days old (built "
                f"{scan['db_date']}). Vulnerabilities published since then are not reported; refresh the "
                "database and scan again.",
            }
        )
    if vulns is None:
        out.append(
            {
                "tone": "neutral",
                "text": "No vulnerability scan was included. Add --scan (needs Trivy or Grype), "
                "--vuln-report <file>, or --harbor-vulns to attribute vulnerabilities as well.",
            }
        )

    unmanaged = [c for c in comps if c["ecosystem"] == "binary"]
    if unmanaged:
        app_un = sum(1 for c in unmanaged if c["origin"] in {o["key"] for o in app})
        out.append(
            {
                "tone": "warn",
                "text": f"{_plural(len(unmanaged), 'program file')} ({app_un:,} in the application build) "
                f"{_be(len(unmanaged), past=True)} not installed "
                "by any package manager. Nobody can patch or verify them automatically; each one must be "
                "tracked back to the team that copied it in.",
            }
        )
    risky = [f for f in m["findings"] if f["severity"] == "high" and "vulnerabilities" not in f["title"]]
    if risky:
        out.append(
            {
                "tone": "bad",
                "text": f"{_plural(len(risky), 'high-risk build practice')} {_be(len(risky), past=True)} "
                "found (for example: "
                f"{risky[0]['title'].lower()}). See Findings.",
            }
        )
    upgraded = sum(1 for c in comps if c["change"] == "upgraded" and c["origin"] in {o["key"] for o in app})
    if upgraded:
        out.append(
            {
                "tone": "good",
                "text": f"The application build updated {_plural(upgraded, 'OS package')} beyond "
                f"the versions shipped in {base_name}.",
            }
        )
    return out
