"""Render the report model as a single self-contained HTML file (no external resources)."""

from __future__ import annotations

import math
from collections import Counter
from html import escape

from .report import scan_source
from .vulns import FIX_STATUSES, SEVERITIES

ORIGIN_SLOTS = ["var(--series-1)", "var(--series-3)", "var(--series-7)", "var(--series-5)"]
SEV_COLOR = {
    "CRITICAL": "var(--st-critical)",
    "HIGH": "var(--st-serious)",
    "MEDIUM": "var(--st-warning)",
    "LOW": "var(--muted)",
    "UNKNOWN": "var(--gridline-strong)",
}
# Vendor fix status: semantic colours, always shown beside their text label.
FIX_COLOR = {
    "fixed": "var(--st-good)",
    "affected": "var(--muted)",
    "fix_deferred": "var(--st-warning)",
    "will_not_fix": "var(--st-serious)",
    "end_of_life": "var(--st-critical)",
    "under_investigation": "var(--gridline-strong)",
    "not_affected": "var(--st-good)",
    "unknown": "var(--gridline-strong)",
}
FLAG_SEV = {
    "high": ("High", "var(--st-critical)", "!"),
    "medium": ("Medium", "var(--st-serious)", "!"),
    "low": ("Low", "var(--st-warning)", "i"),
    "info": ("Info", "var(--muted)", "i"),
}
TONE = {
    "good": ("var(--st-good)", "✓", "Good"),
    "bad": ("var(--st-critical)", "!", "Attention"),
    "warn": ("var(--st-warning)", "!", "Caution"),
    "neutral": ("var(--series-1)", "•", "Fact"),
}


def e(x) -> str:
    return escape(str(x if x is not None else ""))


def origin_colors(origins: list[dict]) -> dict[str, str]:
    colors, i = {}, 0
    for o in origins:
        if o["kind"] == "app":
            colors[o["key"]] = "var(--series-2)"
        elif o["kind"] == "unknown":
            colors[o["key"]] = "var(--muted)"
        else:
            colors[o["key"]] = ORIGIN_SLOTS[min(i, len(ORIGIN_SLOTS) - 1)]
            i += 1
    colors.setdefault("unknown", "var(--muted)")
    return colors


def _badge(label: str, color: str) -> str:
    return f'<span class="badge"><span class="sw" style="background:{color}"></span>{e(label)}</span>'


def _stacked(segments: list[tuple[str, int, str]], total: int, unit: str) -> str:
    """Horizontal 100% stacked bar. segments: (label, value, color)."""
    if not total:
        return '<div class="bar empty">None</div>'
    parts = []
    for label, val, color in segments:
        if val <= 0:
            continue
        pct = 100 * val / total
        tip = f"{label}: {val:,} {unit} ({pct:.0f}%)"
        parts.append(
            f'<div class="seg" style="flex:{val} 1 0;background:{color}" data-tip="{e(tip)}" '
            f'aria-label="{e(tip)}"></div>'
        )
    return f'<div class="bar" role="img">{"".join(parts)}</div>'


def _layer_cake(m: dict, colors: dict[str, str], olabel: dict[str, str]) -> str:
    """Draw the image as a cake: first layer at the bottom, each slice coloured by who added it."""
    layers = m["layers"]
    if not layers:
        return ""
    vulns = m["vulns"]
    total_v, serious_v = Counter(), Counter()
    for v in vulns or []:
        if v["layer"] is not None:
            total_v[v["layer"]] += 1
            if v["severity"] in ("CRITICAL", "HIGH"):
                serious_v[v["layer"]] += 1
    biggest = max(lyr["size"] for lyr in layers) or 1
    origins = {o["key"]: o for o in m["origins"]}
    proof = {
        "exact layer-digest match": "proven by digest",
        "partial layer-digest match": "partly proven by digest",
        "estimated from build timestamps": "estimated",
    }

    groups: list[tuple[str, list[dict]]] = []  # runs of consecutive layers with the same origin, bottom-up
    for lyr in layers:
        if groups and groups[-1][0] == lyr["origin"]:
            groups[-1][1].append(lyr)
        else:
            groups.append((lyr["origin"], [lyr]))

    parts = []
    for gi in range(len(groups) - 1, -1, -1):  # top tier first
        okey, group = groups[gi]
        color = colors.get(okey, "var(--muted)")
        nums = [lyr["number"] for lyr in group]
        span = f"Layer {nums[0]}" if len(nums) == 1 else f"Layers {nums[0]}–{nums[-1]}"
        how = proof.get(origins.get(okey, {}).get("match", ""), "")
        slices = []
        for lyr in reversed(group):
            # Thickness grows with the log of the layer size so a 249-byte layer and a 300 MB layer both read.
            height = 2.6 + 2.4 * math.log1p(lyr["size"]) / math.log1p(biggest)
            meta = [lyr["size_h"], f"{lyr['components']:,} component{'' if lyr['components'] == 1 else 's'}"]
            if vulns is not None:
                n, sv = total_v[lyr["index"]], serious_v[lyr["index"]]
                meta.append(
                    f"{n:,} vulnerabilit{'y' if n == 1 else 'ies'}" + (f" ({sv:,} critical/high)" if sv else "")
                )
            tip = f"Step {lyr['number']}: {lyr['summary']}"
            label = f"Layer {lyr['number']}, {olabel.get(okey, okey)}: {lyr['content_summary']}. {', '.join(meta)}"
            slices.append(
                f'<a class="slice" href="#step-{lyr["number"]}" style="--oc:{color};min-height:{height:.2f}rem" '
                f'data-tip="{e(tip)}" aria-label="{e(label)}"><span class="slice-n">{lyr["number"]}</span>'
                f'<span class="slice-body"><span class="slice-sum">{e(lyr["content_summary"])}</span>'
                f'<span class="slice-meta">{e(" · ".join(meta))}</span></span></a>'
            )
        parts.append(
            f'<div class="tier"><div class="tier-label">{_badge(olabel.get(okey, okey), color)}'
            f'<span class="small muted">{e(span)}{" · " + e(how) if how else ""}</span></div>'
            f'<div class="slices">{"".join(slices)}</div></div>'
        )
        if gi > 0:
            below = olabel.get(groups[gi - 1][0], groups[gi - 1][0])
            parts.append(
                f'<div class="seam"><span>{e(below)} ends here. Everything above was added on top of it.</span></div>'
            )
    parts.append('<div class="stand"><span>Empty filesystem: the build starts here</span></div>')
    return (
        '<div class="card"><h3>The image as a layer cake</h3>'
        '<p class="sub">Read it from the bottom up, in the order it was built. Each slice is one layer, coloured by who '
        "added it; thicker slices are larger layers. Select a slice to see that build step.</p>"
        f'<div class="cake">{"".join(parts)}</div></div>'
    )


def render(m: dict) -> str:
    origins = m["origins"]
    colors = origin_colors(origins)
    olabel = {o["key"]: o["label"] for o in origins}
    olabel.setdefault("unknown", "Unattributed")
    comps = m["components"]
    vulns = m["vulns"]
    img = m["image"]
    total = len(comps)

    # ---------------------------------------------------------------- header
    title = f"Provenance report: {img['name']}"
    meta_rows = [
        ("Image", img["name"]),
        ("Digest", img["digest"] or "n/a"),
        ("Operating system", img["os"] or "unknown"),
        ("Platform", img["platform"] or "n/a"),
        ("Size (compressed)", img["size_h"]),
        ("Layers", img["layer_count"]),
        ("Image built", (img["created"] or "unknown")[:19].replace("T", " ")),
        ("Report generated", m["generated"]),
    ]
    meta_html = "".join(f"<div><dt>{e(k)}</dt><dd>{e(v)}</dd></div>" for k, v in meta_rows)

    # ---------------------------------------------------------------- bottom line
    takeaways = "".join(
        f'<li class="tk"><span class="tk-ic" style="background:{TONE[t["tone"]][0]}" '
        f'aria-label="{TONE[t["tone"]][2]}">{TONE[t["tone"]][1]}</span><span>{e(t["text"])}</span></li>'
        for t in m["takeaways"]
    )

    # ---------------------------------------------------------------- KPI tiles
    tiles = [("Components found", f"{total:,}", "", "")]
    for o in origins:
        if o["kind"] != "unknown" or o["components"]:
            tiles.append(
                (
                    o["label"],
                    f"{o['components']:,}",
                    colors[o["key"]],
                    f"{round(100 * o['components'] / total) if total else 0}% of components",
                )
            )
    n_unmanaged = sum(1 for c in comps if c["ecosystem"] == "binary")
    tiles.append(("Untraceable program files", f"{n_unmanaged:,}", "", "no package record"))
    if vulns is not None:
        serious = sum(1 for v in vulns if v["severity"] in ("CRITICAL", "HIGH"))
        tiles.append(("Known vulnerabilities", f"{len(vulns):,}", "", f"{serious:,} critical or high"))
    tiles_html = "".join(
        f'<div class="tile">{f"<span class=sw style=background:{c}></span>" if c else ""}'
        f'<div class="tile-label">{e(lbl)}</div><div class="tile-val">{e(val)}</div>'
        f'<div class="tile-sub">{e(sub)}</div></div>'
        for lbl, val, c, sub in tiles
    )

    # ---------------------------------------------------------------- composition charts
    legend = "".join(
        f'<span class="lg"><span class="sw" style="background:{colors[o["key"]]}"></span>{e(o["label"])}</span>'
        for o in origins
    )
    comp_bar = _stacked([(o["label"], o["components"], colors[o["key"]]) for o in origins], total, "components")
    size_total = sum(o["size"] for o in origins)
    size_bar = _stacked([(o["label"], o["size"], colors[o["key"]]) for o in origins], size_total, "bytes")
    type_counts = Counter(c["ecosystem"] for c in comps)
    type_rows = []
    for eco, n in type_counts.most_common():
        segs = [(o["label"], o["by_type"].get(eco, 0), colors[o["key"]]) for o in origins]
        cells = "".join(f'<td class="num">{o["by_type"].get(eco, 0):,}</td>' for o in origins)
        type_rows.append(
            f'<tr><th scope="row">{e(m["type_labels"].get(eco, eco))}</th>{cells}'
            f'<td class="num"><b>{n:,}</b></td><td class="barcell">{_stacked(segs, n, "components")}</td></tr>'
        )
    type_head = "".join(f'<th class="num">{e(o["label"])}</th>' for o in origins)

    vuln_chart = ""
    if vulns is not None:
        vorigins = [o for o in origins if o["vulns_total"]]
        vlegend = "".join(
            f'<span class="lg"><span class="sw" style="background:{colors.get(o["key"], "var(--muted)")}">'
            f"</span>{e(o['label'])}</span>"
            for o in vorigins
        )
        sev_rows = [
            (s.title(), SEV_COLOR[s], {o["key"]: o["vulns"][s] for o in vorigins})
            for s in SEVERITIES
            if s != "UNKNOWN" or any(o["vulns"][s] for o in vorigins)
        ]
        fix_rows = [
            (lbl, FIX_COLOR[k], {o["key"]: o["vulns_by_fix"].get(k, 0) for o in vorigins})
            for k, lbl in FIX_STATUSES.items()
            if any(o["vulns_by_fix"].get(k, 0) for o in vorigins)
        ]
        rows = _origin_bars(sev_rows, vorigins, colors, label_width="90px")
        fix_bars = _origin_bars(fix_rows, vorigins, colors, label_width="200px")
        vtable_rows = "".join(
            f'<tr><th scope="row"><span class="sw" style="background:{colors.get(o["key"], "var(--muted)")}"></span>'
            f"{e(o['label'])}</th>"
            + "".join(f'<td class="num">{o["vulns"][s]:,}</td>' for s in SEVERITIES)
            + f'<td class="num"><b>{o["vulns_total"]:,}</b></td><td class="num">{o["vulns_fixable"]:,}</td></tr>'
            for o in vorigins
        )
        vuln_chart = f"""
<div class="card">
  <h3>Known vulnerabilities by severity and origin</h3>
  <p class="sub">Source: {e(scan_source(m))}. Each vulnerability is attributed to the layer that
  installed the affected version of the component.</p>
  <div class="legend">{vlegend}</div>
  <div class="vchart">{rows if vulns else "<p>No known vulnerabilities reported.</p>"}</div>
  {f'<h3 class="mt">What the software vendors say about fixing them</h3><div class="vchart">{fix_bars}</div>' if vulns else ""}
  <details class="tableview"><summary>Show as table</summary>
  <table class="data"><thead><tr><th>Origin</th>{"".join(f'<th class="num">{s.title()}</th>' for s in SEVERITIES)}
  <th class="num">Total</th><th class="num">Fix available</th></tr></thead><tbody>{vtable_rows}</tbody></table>
  <table class="data mt"><thead><tr><th>Vendor fix status</th>{"".join(f'<th class="num">{e(o["label"])}</th>' for o in vorigins)}</tr></thead>
  <tbody>{"".join(f'<tr><th scope="row">{e(lbl)}</th>' + "".join(f'<td class="num">{c[o["key"]]:,}</td>' for o in vorigins) + "</tr>" for lbl, _, c in fix_rows)}</tbody></table>
  </details>
</div>"""

    # ---------------------------------------------------------------- origins explained
    origin_cards = []
    for o in origins:
        how = {
            "exact layer-digest match": "Proven: the layers are byte-for-byte identical (same SHA-256 digests) to the base image.",
            "partial layer-digest match": "Proven for the shared layers only. The image was built from a different version of this base.",
            "estimated from build timestamps": "Estimated from the gap in build timestamps. Not proof; supply --base for certainty.",
            "layers added on top of the base": "Everything added after the base: the application Dockerfile / build pipeline.",
            "none": "No base image was supplied, so these layers cannot be attributed.",
        }.get(o["match"], o["match"])
        layers_txt = (
            f"Layers {o['layers'][0]}–{o['layers'][-1]}"
            if len(o["layers"]) > 1
            else f"Layer {o['layers'][0]}"
            if o["layers"]
            else ""
        )
        origin_cards.append(
            f'<div class="ocard" style="border-color:{colors[o["key"]]}"><div class="ocard-h">{_badge(o["label"], colors[o["key"]])}'
            f'<span class="muted">{e(layers_txt)}</span></div>'
            + (f'<div class="mono small">{e(o["reference"])}</div>' if o["reference"] else "")
            + f"<p>{e(how)}</p>"
            + (f'<p class="note">{e(o["note"])}</p>' if o["note"] else "")
            + "</div>"
        )

    cake = _layer_cake(m, colors, olabel)

    # ---------------------------------------------------------------- build timeline
    steps = []
    for lyr in m["layers"]:
        risk = "".join(
            f'<span class="flag" style="--fc:{FLAG_SEV[r["severity"]][1]}">'
            f"<b>{FLAG_SEV[r['severity']][0]}</b> {e(r['message'])}</span>"
            for r in lyr["risks"]
        )
        urls = "".join(f"<li class='mono'>{e(u)}</li>" for u in lyr["urls"])
        steps.append(f"""
<li class="step" id="step-{lyr["number"]}" style="--oc:{colors.get(lyr["origin"], "var(--muted)")}">
  <div class="step-n">{lyr["number"]}</div>
  <div class="step-body">
    <div class="step-top">{_badge(lyr["origin_label"], colors.get(lyr["origin"], "var(--muted)"))}
      <span class="muted">{e(lyr["size_h"])} · {lyr["components"]:,} components{f" · {lyr['vulns']:,} vulnerabilities" if vulns is not None else ""}
      {(" · " + e(lyr["created"][:10])) if lyr["created"] else ""}</span></div>
    <div class="step-sum">{e(lyr["content_summary"])}</div>
    <div class="step-rec"><span class="muted">Build record:</span> {e(lyr["summary"])}</div>
    {f'<div class="flags">{risk}</div>' if risk else ""}
    <details><summary>Technical detail</summary>
      <dl class="kv"><dt>Instruction</dt><dd class="mono">{e(lyr["instruction"] or "(none recorded)")}</dd>
      <dt>Command</dt><dd><pre>{e(lyr["command"] or "(none recorded)")}</pre></dd>
      {f"<dt>URLs contacted</dt><dd><ul>{urls}</ul></dd>" if urls else ""}
      <dt>Layer digest</dt><dd class="mono">{e(lyr["diff_id"])}</dd>
      <dt>Files</dt><dd>{lyr["files_added"]:,} added, {lyr["files_replaced"]:,} replaced, {lyr["files_deleted"]:,} deleted{f", {lyr['files_metadata_only']:,} with only permissions or ownership changed" if lyr["files_metadata_only"] else ""}</dd>
      {f"<dt>Warning</dt><dd>{e(lyr['error'])}</dd>" if lyr["error"] else ""}</dl>
    </details>
  </div>
</li>""")

    # ---------------------------------------------------------------- findings
    fcards = []
    for f in m["findings"]:
        lbl, col, ic = FLAG_SEV.get(f["severity"], FLAG_SEV["info"])
        items = "".join(f"<li class='mono'>{e(i)}</li>" for i in f["items"])
        oc = colors.get(f["origin"], "var(--muted)")
        detail = f'<p class="f-detail">{e(f["detail"])}</p>' if f["detail"] else ""
        more = (
            f'<details><summary>Show {len(f["items"]):,} item(s)</summary><ul class="items">{items}</ul></details>'
            if items
            else ""
        )
        fcards.append(f"""
<div class="finding" data-origin="{e(f["origin"])}">
  <div class="f-head"><span class="sev" style="--fc:{col}"><span class="sev-ic">{ic}</span>{lbl}</span>
  {_badge(f["origin_label"], oc)}</div>
  <div class="f-title">{e(f["title"])}</div>
  {detail}
  {more}
</div>""")
    findings_html = "".join(fcards) or "<p>No findings that need attention.</p>"

    # ---------------------------------------------------------------- vulnerability table
    vuln_section = ""
    if vulns is not None:
        sev_order = {s: i for i, s in enumerate(SEVERITIES)}
        vrows = []
        for v in sorted(vulns, key=lambda v: (sev_order.get(v["severity"], 9), v["id"])):
            vrows.append(
                f'<tr data-origin="{e(v["origin"])}" data-sev="{e(v["severity"])}" data-fix="{e(v["fix_status"])}">'
                f'<td class="nw"><span class="sevdot" style="background:{SEV_COLOR.get(v["severity"])}"></span>{e(v["severity"].title())}</td>'
                f'<td class="mono nw">{e(v["id"])}</td><td>{e(v["package"])}</td><td class="mono">{e(v["version"])}</td>'
                + f'<td><span class="nw"><span class="sevdot" style="background:{FIX_COLOR.get(v["fix_status"])}"></span>'
                f"{e(FIX_STATUSES.get(v['fix_status'], v['fix_status']))}</span>"
                + (f'<div class="mono small">{e(v["fixed_version"])}</div>' if v["fixed_version"] else "")
                + "</td>"
                + f"<td>{_badge(olabel.get(v['origin'], v['origin']), colors.get(v['origin'], 'var(--muted)'))}"
                f'<div class="muted small">{("layer " + str(v["layer"] + 1)) if v["layer"] is not None else ""}'
                f" · {e(v['attribution'])}</div></td>"
                f'<td class="small">{e(v["title"])}</td></tr>'
            )
        vfilters = _filter_chips(
            "vt",
            [(o["key"], o["label"], colors.get(o["key"], "var(--muted)")) for o in origins if o["vulns_total"]],
            "origin",
        )
        vfilters += _filter_chips("vt", [(s, s.title(), SEV_COLOR[s]) for s in SEVERITIES], "sev")
        present = {v["fix_status"] for v in vulns}
        vfilters += _filter_chips(
            "vt", [(k, lbl, FIX_COLOR[k]) for k, lbl in FIX_STATUSES.items() if k in present], "fix"
        )
        vuln_section = f"""
<section id="vulns"><h2><span class="num-h">5</span>Vulnerabilities and who introduced them</h2>
<p class="lead">Every known vulnerability, traced to the build step that installed the affected component.</p>
<div class="controls" data-table="vt">{vfilters}<input type="search" placeholder="Search CVE or package..." data-search="vt"></div>
<div class="tablewrap"><table class="data" id="vt"><thead><tr><th>Severity</th><th>ID</th><th>Package</th><th>Installed</th>
<th>Vendor fix status</th><th>Introduced by</th><th>Summary</th></tr></thead><tbody>{"".join(vrows)}</tbody></table></div>
<p class="muted small" data-count="vt"></p></section>"""

    # ---------------------------------------------------------------- inventory
    crow = []
    for c in comps:
        flags = "".join(
            f'<span class="flag sm" style="--fc:{FLAG_SEV[f["severity"]][1]}">{e(f["message"])}</span>'
            for f in c["flags"]
        )
        change = ""
        if c["change"] in ("upgraded", "downgraded", "changed"):
            change = f'<div class="small muted">{e(c["change"])} from {e(c["previous_version"])}</div>'
        ev = "".join(
            f"<li>{e(x)}</li>"
            for x in c["evidence"]
            + ([f"Location: {p}" for p in c["paths"][:3]])
            + ([f"Package URL: {c['purl']}"] if c["purl"] else [])
            + ([f"License: {c['license']}"] if c["license"] else [])
        )
        via = (
            f'<div class="small muted">via {e(c["source"])}</div>'
            if c["source"] and not c["source"].startswith("http")
            else ""
        )
        crow.append(
            f'<tr data-origin="{e(c["origin"])}" data-type="{e(c["ecosystem"])}" data-flag="{"1" if c["flags"] else "0"}">'
            f'<td><b>{e(c["name"])}</b>{change}</td><td class="mono">{e(c["version"] or "—")}</td>'
            f"<td>{e(c['type_label'])}</td>"
            f"<td>{e(c['supplier'])}{via}</td>"
            f"<td>{_badge(olabel.get(c['origin'], c['origin']), colors.get(c['origin'], 'var(--muted)'))}"
            f'<div class="small muted">layer {c["layer"] + 1}</div></td>'
            f'<td>{flags}<details><summary>Evidence</summary><ul class="ev">{ev}</ul></details></td></tr>'
        )
    cfilters = _filter_chips(
        "ct", [(o["key"], o["label"], colors[o["key"]]) for o in origins if o["components"]], "origin"
    )
    cfilters += _filter_chips(
        "ct", [(eco, m["type_labels"].get(eco, eco), "") for eco, _ in type_counts.most_common()], "type"
    )
    cfilters += _filter_chips("ct", [("1", "Only items with concerns", "var(--st-serious)")], "flag")

    # ---------------------------------------------------------------- notes
    notes = "".join(f"<li>{e(n)}</li>" for n in m["notes"])
    removed = m["removed_packages"]
    removed_html = ""
    if removed:
        removed_html = (
            "<details><summary>"
            + f"{len(removed):,} packages were removed during the build</summary><ul class='items'>"
            + "".join(
                f"<li class='mono'>{e(r['name'])} {e(r['version'])} (removed in layer {r['layer'] + 1})</li>"
                for r in removed[:500]
            )
            + "</ul></details>"
        )
    vuln_toc = '<a href="#vulns">Vulnerabilities</a>' if vulns is not None else ""
    inv_n, meth_n = ("6", "7") if vulns is not None else ("5", "6")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<style>{CSS}</style></head>
<body>
<div id="tip" role="tooltip"></div>
<header class="hero">
  <div class="wrap">
    <div class="eyebrow">{e(m.get("subtitle") or "Container image provenance report")}</div>
    <h1>Where did everything in this image come from?</h1>
    <div class="imgname mono">{e(img["name"])}</div>
    <dl class="meta">{meta_html}</dl>
    <nav class="toc"><a href="#bottom-line">Bottom line</a><a href="#composition">Composition</a>
    <a href="#build">How it was built</a><a href="#findings">Findings</a>{vuln_toc}
    <a href="#inventory">Full inventory</a><a href="#method">Method</a>
    <button type="button" id="theme" aria-label="Toggle dark mode">◐</button></nav>
  </div>
</header>
<main class="wrap">
<section id="bottom-line"><h2><span class="num-h">1</span>Bottom line</h2>
  <ul class="takeaways">{takeaways}</ul>
  <div class="tiles">{tiles_html}</div>
</section>

<section id="composition"><h2><span class="num-h">2</span>Where the contents came from</h2>
  <p class="lead">An image is built in layers, like a cake. The bottom tiers come from the base image, and the tiers on
  top are added by the application team's build. Each layer is attributed to whoever produced it.</p>
  {cake}
  <div class="ocards">{"".join(origin_cards)}</div>
  <div class="grid2">
  <div class="card"><h3>Share of components</h3><div class="legend">{legend}</div>{comp_bar}
  <h3 class="mt">Share of image size</h3>{size_bar}</div>
  {vuln_chart}
  </div>
  <div class="card"><h3>Components by type and origin</h3>
  <div class="tablewrap"><table class="data"><thead><tr><th>Type</th>{type_head}<th class="num">Total</th><th>Split</th></tr></thead>
  <tbody>{"".join(type_rows)}</tbody></table></div></div>
</section>

<section id="build"><h2><span class="num-h">3</span>How the image was built, step by step</h2>
  <p class="lead">Each step created one layer. The colour shows who is responsible for that step.</p>
  <ol class="timeline">{"".join(steps)}</ol>
  {removed_html}
</section>

<section id="findings"><h2><span class="num-h">4</span>Findings that need attention</h2>
  <p class="lead">Issues are grouped by who introduced them, so each one can be routed to the right owner.</p>
  <div class="findings">{findings_html}</div>
</section>
{vuln_section}
<section id="inventory"><h2><span class="num-h">{inv_n}</span>Complete component inventory</h2>
  <p class="lead">Every package, library and program file found, with its supplier and the evidence behind that answer.</p>
  <div class="controls" data-table="ct">{cfilters}<input type="search" placeholder="Search components..." data-search="ct"></div>
  <div class="tablewrap"><table class="data" id="ct"><thead><tr><th>Component</th><th>Version</th><th>Type</th>
  <th>Supplied by</th><th>Added by</th><th>Concerns &amp; evidence</th></tr></thead><tbody>{"".join(crow)}</tbody></table></div>
  <p class="muted small" data-count="ct"></p>
</section>

<section id="method"><h2><span class="num-h">{meth_n}</span>How this report was produced</h2>
<div class="grid2">
<div class="card"><h3>Method</h3>
<ol class="method">
<li><b>Every layer was unpacked and replayed in order</b>, including deletions, so the report reflects exactly what ships in the final image.</li>
<li><b>Layers were matched to the base image by cryptographic digest.</b> A layer with the same SHA-256 digest as a base-image
layer is byte-for-byte identical to it, so that is proof of where it came from rather than an opinion.</li>
<li><b>Package databases were read at every layer</b> (RPM, Debian, Alpine), so each package is credited to the layer that
installed its <i>current</i> version. If the application build upgrades a base package, that version belongs to the application build.</li>
<li><b>Language libraries</b> (Python, JavaScript, Java, Go) were identified from their own metadata and credited to the layer that wrote them.</li>
<li><b>Program files with no package record</b> were found by checking every executable against all package file lists.</li>
<li><b>Supplier evidence</b> comes from package signatures (signing key IDs), vendor fields, the repository each package was installed
from (dnf history), and registry URLs.</li>
</ol></div>
<div class="card"><h3>Glossary</h3>
<dl class="gloss">
<dt>Base image</dt><dd>The starting image a team builds on, such as an Iron Bank hardened image.</dd>
<dt>Layer</dt><dd>One set of file changes produced by one build step. Images are stacks of layers.</dd>
<dt>Component</dt><dd>A piece of software in the image: an OS package, a library, or a program.</dd>
<dt>Digest</dt><dd>A cryptographic fingerprint (SHA-256). Identical digest means identical content.</dd>
<dt>Untraceable program file</dt><dd>An executable that no package manager installed. Its origin is known only as far as the build step that added it.</dd>
<dt>CVE</dt><dd>A publicly catalogued security vulnerability.</dd>
</dl></div>
</div>
{f'<div class="card notes"><h3>Notes and limitations</h3><ul>{notes}</ul></div>' if notes else ""}
</section>
</main>
<footer class="wrap muted small">{e(m["tool"]["name"])} v{e(m["tool"]["version"])} · generated {e(m["generated"])}</footer>
<script>{JS}</script>
</body></html>"""


def _origin_bars(rows: list[tuple[str, str, dict]], vorigins: list[dict], colors: dict, label_width: str) -> str:
    """Horizontal bars, one per category, each split into segments by origin. rows: (label, dot colour, counts)."""
    vmax = max([sum(c.values()) for _, _, c in rows] + [1])
    out = []
    for label, dot, counts in rows:
        n = sum(counts.values())
        segs = "".join(
            f'<div class="seg" style="flex:{counts[o["key"]]} 1 0;background:{colors.get(o["key"], "var(--muted)")}" '
            f'data-tip="{e(o["label"])}: {counts[o["key"]]:,} ({e(label.lower())})"></div>'
            for o in vorigins
            if counts.get(o["key"])
        )
        width = max(100 * n / vmax, 0.5) if n else 0
        out.append(
            f'<div class="vrow" style="grid-template-columns:{label_width} 1fr"><div class="vlab">'
            f'<span class="sevdot" style="background:{dot}"></span>{e(label)}</div><div class="vtrack">'
            f'<div class="bar" style="width:{width}%">{segs}</div><span class="vnum">{n:,}</span></div></div>'
        )
    return "".join(out)


def _filter_chips(table: str, items: list[tuple[str, str, str]], attr: str) -> str:
    chips = "".join(
        f'<button type="button" class="chip" data-attr="{attr}" data-val="{e(k)}" aria-pressed="false">'
        + (f'<span class="sw" style="background:{c}"></span>' if c else "")
        + f"{e(lbl)}</button>"
        for k, lbl, c in items
    )
    return f'<div class="chips">{chips}</div>' if chips else ""


CSS = """
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--surface-2:#f3f2ee;--ink:#0b0b0b;--ink-2:#52514e;--muted:#898781;
--gridline:#e1e0d9;--gridline-strong:#c3c2b7;--border:rgba(11,11,11,.10);
--series-1:#2a78d6;--series-2:#eb6834;--series-3:#1baf7a;--series-5:#e87ba4;--series-7:#4a3aa7;
--st-good:#0ca30c;--st-warning:#fab219;--st-serious:#ec835a;--st-critical:#d03b3b;--hero:#0f1b2d;--hero-ink:#fff}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--surface-2:#232321;
--ink:#fff;--ink-2:#c3c2b7;--gridline:#2c2c2a;--gridline-strong:#383835;--border:rgba(255,255,255,.10);
--series-1:#3987e5;--series-2:#d95926;--series-3:#199e70;--series-5:#d55181;--series-7:#9085e9;--hero:#111a28}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--surface-2:#232321;--ink:#fff;--ink-2:#c3c2b7;
--gridline:#2c2c2a;--gridline-strong:#383835;--border:rgba(255,255,255,.10);--series-1:#3987e5;--series-2:#d95926;
--series-3:#199e70;--series-5:#d55181;--series-7:#9085e9;--hero:#111a28}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:0 16px}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.86em;overflow-wrap:break-word}
.nw{white-space:nowrap}.meta dd,.kv dd{overflow-wrap:anywhere}
.muted{color:var(--muted)}.small{font-size:.82em}.mt{margin-top:20px}
.hero{background:var(--hero);color:var(--hero-ink);padding:32px 0 0;margin-bottom:24px}
.eyebrow{text-transform:uppercase;letter-spacing:.08em;font-size:.75rem;opacity:.75}
.hero h1{margin:6px 0 4px;font-size:clamp(1.5rem,3vw,2.1rem);line-height:1.2}
.imgname{font-size:1rem;opacity:.9;margin-bottom:16px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px 24px;margin:0 0 20px}
.meta dt{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;opacity:.65}.meta dd{margin:0;font-size:.9rem;word-break:break-all}
.toc{display:flex;flex-wrap:wrap;gap:4px;border-top:1px solid rgba(255,255,255,.15);padding:8px 0}
.toc a{color:var(--hero-ink);opacity:.85;text-decoration:none;padding:6px 10px;border-radius:6px;font-size:.88rem}
.toc a:hover{background:rgba(255,255,255,.1);opacity:1}
#theme{margin-left:auto;background:none;border:1px solid rgba(255,255,255,.3);color:var(--hero-ink);border-radius:6px;cursor:pointer;padding:4px 10px}
section{margin:0 0 48px}
h2{font-size:1.35rem;margin:0 0 6px;display:flex;align-items:center;gap:10px}
.num-h{display:inline-grid;place-items:center;width:28px;height:28px;border-radius:50%;background:var(--ink);color:var(--page);font-size:.85rem}
h3{font-size:1rem;margin:0 0 10px}
.lead{color:var(--ink-2);max-width:75ch;margin:0 0 16px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px;margin-bottom:16px;min-width:0}
.sub{color:var(--ink-2);font-size:.85rem;margin:-4px 0 10px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,440px),1fr));gap:16px}
.takeaways{list-style:none;padding:0;margin:0 0 20px;display:grid;gap:10px}
.tk{display:flex;gap:12px;align-items:flex-start;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px;font-size:1.02rem}
.tk-ic{flex:none;width:24px;height:24px;border-radius:50%;color:#fff;display:grid;place-items:center;font-weight:700;font-size:.85rem;margin-top:1px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px;position:relative}
.tile .sw{position:absolute;top:16px;right:16px}
.tile-label{font-size:.8rem;color:var(--ink-2);padding-right:18px}.tile-val{font-size:1.9rem;font-weight:650;line-height:1.2}
.tile-sub{font-size:.78rem;color:var(--muted)}
.sw{display:inline-block;width:10px;height:10px;border-radius:3px;flex:none}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:.8rem;padding:2px 8px;border-radius:999px;background:var(--surface-2);border:1px solid var(--border);white-space:nowrap}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;margin-bottom:10px;font-size:.85rem;color:var(--ink-2)}
.lg{display:inline-flex;align-items:center;gap:6px}
.bar{display:flex;gap:2px;height:22px;width:100%}
.bar .seg{min-width:3px;height:100%}
.bar .seg:first-child{border-radius:4px 0 0 4px}.bar .seg:last-child{border-radius:0 4px 4px 0}.bar .seg:only-child{border-radius:4px}
.bar.empty{color:var(--muted);font-size:.85rem}
.barcell{min-width:140px;width:30%}.barcell .bar{height:12px}
.vchart{display:grid;gap:10px}.vrow{display:grid;grid-template-columns:90px 1fr;align-items:center;gap:10px}
.vlab{display:flex;align-items:center;gap:6px;font-size:.88rem}.vtrack{display:flex;align-items:center;gap:8px}
.vtrack .bar{height:18px}.vnum{font-variant-numeric:tabular-nums;font-size:.85rem;color:var(--ink-2)}
.sevdot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:middle}
.tableview{margin-top:12px}
.ocards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:12px;margin-bottom:16px}
.ocard{background:var(--surface);border:1px solid var(--border);border-left:4px solid;border-radius:10px;padding:14px 16px}
.ocard p{margin:8px 0 0;color:var(--ink-2);font-size:.9rem}.ocard .note{color:var(--ink)}
.ocard-h{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center}
.timeline{list-style:none;padding:0;margin:0}
.cake{display:grid;max-width:900px;margin:4px auto 0}
.tier{display:grid;grid-template-columns:minmax(120px,200px) minmax(0,1fr);gap:16px;align-items:center;padding:4px 0}
.tier-label{display:flex;flex-direction:column;align-items:flex-start;gap:4px}
.slices{display:flex;flex-direction:column;gap:3px;min-width:0}
.slice{display:flex;align-items:center;gap:12px;padding:6px 14px;border-radius:6px;text-decoration:none;color:var(--ink);
background:var(--surface-2);background:color-mix(in srgb,var(--oc) 15%,var(--surface));border-top:4px solid var(--oc);
-webkit-print-color-adjust:exact;print-color-adjust:exact}
.slice:hover{background:color-mix(in srgb,var(--oc) 26%,var(--surface))}
.slice:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
.slice-n{flex:none;width:26px;height:26px;border-radius:50%;background:var(--oc);color:#fff;display:grid;place-items:center;font-weight:650;font-size:.8rem}
.slice-body{display:flex;flex-direction:column;min-width:0}
.slice-sum{font-weight:600;font-size:.9rem}
.slice-meta{font-size:.78rem;color:var(--ink-2);font-variant-numeric:tabular-nums}
.seam{display:flex;align-items:center;gap:10px;margin:10px 0;color:var(--ink-2);font-size:.8rem;text-align:center}
.seam:before,.seam:after{content:"";flex:1;min-width:16px;border-top:2px dashed var(--gridline-strong)}
.stand{margin:6px -10px 0;border-top:6px solid var(--gridline-strong);border-radius:3px;text-align:center;padding-top:6px;font-size:.78rem;color:var(--muted)}
.step{scroll-margin-top:16px}
.step{display:grid;grid-template-columns:40px 1fr;gap:12px;position:relative;padding-bottom:12px}
.step:before{content:"";position:absolute;left:19px;top:34px;bottom:0;width:2px;background:var(--gridline)}
.step:last-child:before{display:none}
.step-n{width:36px;height:36px;border-radius:50%;background:var(--oc);color:#fff;display:grid;place-items:center;font-weight:650;z-index:1}
.step-body{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 14px;min-width:0}
.step-top{display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:.84rem}
.step-sum{font-weight:550;margin:6px 0 2px}.step-rec{font-size:.88rem;color:var(--ink-2)}
.flags{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.flag{display:inline-block;font-size:.8rem;padding:2px 8px;border-radius:6px;border-left:3px solid var(--fc);background:var(--surface-2)}
.flag.sm{font-size:.75rem;margin:0 4px 4px 0}
details summary{cursor:pointer;color:var(--ink-2);font-size:.85rem;margin-top:6px}
pre{white-space:pre-wrap;word-break:break-all;background:var(--surface-2);padding:8px;border-radius:6px;font-size:.8rem;margin:0;max-height:300px;overflow:auto}
.kv{display:grid;grid-template-columns:130px 1fr;gap:6px 12px;font-size:.85rem;margin:8px 0 0}.kv dt{color:var(--muted)}.kv dd{margin:0;min-width:0}
.kv ul{margin:0;padding-left:18px}
.findings{display:grid;gap:10px}
.finding{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.f-head{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.sev{display:inline-flex;align-items:center;gap:6px;font-size:.78rem;font-weight:650;text-transform:uppercase;letter-spacing:.04em}
.sev-ic{width:18px;height:18px;border-radius:50%;background:var(--fc);color:#fff;display:grid;place-items:center;font-size:.72rem}
.f-title{font-weight:600;margin-top:6px}.f-detail{margin:4px 0 0;color:var(--ink-2);font-size:.9rem}
.items{max-height:280px;overflow:auto;font-size:.82rem;margin:6px 0 0;padding-left:18px}
.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{display:inline-flex;align-items:center;gap:6px;font:inherit;font-size:.8rem;padding:4px 10px;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--ink);cursor:pointer}
.chip[aria-pressed="true"]{background:var(--ink);color:var(--page)}
input[type=search]{font:inherit;padding:6px 10px;border-radius:8px;border:1px solid var(--gridline-strong);background:var(--surface);color:var(--ink);min-width:min(260px,100%);flex:1}
.tablewrap{overflow-x:auto;background:var(--surface);border:1px solid var(--border);border-radius:10px}
table.data{border-collapse:collapse;width:100%;font-size:.85rem}
table.data th,table.data td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--gridline);vertical-align:top}
table.data thead th{position:sticky;top:0;background:var(--surface-2);font-weight:600;font-size:.78rem;color:var(--ink-2)}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.ev{margin:4px 0 0;padding-left:16px;font-size:.78rem;color:var(--ink-2);word-break:break-all}
.method li,.gloss dd{color:var(--ink-2)}.method li{margin-bottom:8px}.gloss dt{font-weight:600}.gloss dd{margin:0 0 10px}
.notes li{margin-bottom:6px}
footer{padding:24px 16px 40px}
#tip{position:fixed;pointer-events:none;background:var(--ink);color:var(--page);font-size:.8rem;padding:4px 8px;border-radius:6px;opacity:0;transition:opacity .1s;z-index:10;max-width:280px}
[hidden]{display:none!important}
@media (max-width:640px){.tier{grid-template-columns:minmax(0,1fr);gap:6px}.stand{margin-inline:0}.kv{grid-template-columns:1fr}.vrow{grid-template-columns:1fr!important;gap:4px}}
@media print{body{background:#fff;font-size:11px}.hero{background:#fff;color:#000;--hero-ink:#000}.toc,.controls,#tip{display:none}
details{display:block}details>*{display:block}section{break-inside:auto}.finding,.step,.tk,.card{break-inside:avoid}
.tablewrap{overflow:visible}table.data thead th{position:static}}
"""

JS = """
(function(){
  var tip=document.getElementById('tip');
  document.addEventListener('mousemove',function(ev){
    var t=ev.target.closest&&ev.target.closest('[data-tip]');
    if(!t){tip.style.opacity=0;return;}
    tip.textContent=t.getAttribute('data-tip');tip.style.opacity=1;
    var x=Math.min(ev.clientX+12,window.innerWidth-tip.offsetWidth-8);tip.style.left=x+'px';tip.style.top=(ev.clientY+14)+'px';
  });
  var tb=document.getElementById('theme');
  try{var saved=localStorage.getItem('wimi-theme');if(saved)document.documentElement.setAttribute('data-theme',saved);}catch(e){}
  tb.addEventListener('click',function(){
    var cur=document.documentElement.getAttribute('data-theme')||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');
    var nxt=cur==='dark'?'light':'dark';document.documentElement.setAttribute('data-theme',nxt);
    try{localStorage.setItem('wimi-theme',nxt);}catch(e){}
  });
  function apply(id){
    var table=document.getElementById(id);if(!table)return;
    var ctl=document.querySelector('.controls[data-table="'+id+'"]');
    var sel={};ctl.querySelectorAll('.chip[aria-pressed="true"]').forEach(function(c){(sel[c.dataset.attr]=sel[c.dataset.attr]||[]).push(c.dataset.val);});
    var q=(ctl.querySelector('input[type=search]').value||'').toLowerCase().trim();
    var shown=0,rows=table.tBodies[0].rows;
    for(var i=0;i<rows.length;i++){var r=rows[i],ok=true;
      for(var a in sel){if(sel[a].indexOf(r.getAttribute('data-'+a))<0){ok=false;break;}}
      if(ok&&q&&r.textContent.toLowerCase().indexOf(q)<0)ok=false;
      r.hidden=!ok;if(ok)shown++;}
    var c=document.querySelector('[data-count="'+id+'"]');if(c)c.textContent='Showing '+shown.toLocaleString()+' of '+rows.length.toLocaleString();
  }
  document.querySelectorAll('.controls').forEach(function(ctl){
    var id=ctl.dataset.table;
    ctl.addEventListener('click',function(ev){var c=ev.target.closest('.chip');if(!c)return;
      c.setAttribute('aria-pressed',c.getAttribute('aria-pressed')==='true'?'false':'true');apply(id);});
    var t;ctl.querySelector('input[type=search]').addEventListener('input',function(){clearTimeout(t);t=setTimeout(function(){apply(id);},120);});
    apply(id);
  });
  window.addEventListener('beforeprint',function(){document.querySelectorAll('details').forEach(function(d){d.open=true;});});
})();
"""
