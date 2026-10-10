"""Command-line entry point: ``wimi <image> --base <base image>``."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import textwrap
from pathlib import Path

from . import __version__, html_report, report
from . import vulns as vulnmod
from .analyze import Analyzer, base_label, compute_origins
from .catalog import Catalog, default_path, pick_tags
from .registry import RegistryClient, RegistryError, parse_ref
from .sources import SourceError, load_image
from .walker import Walker

EPILOG = textwrap.dedent("""\
    image sources:
      registry.example.mil/project/app:1.2       pull from any OCI registry (Iron Bank, Artifactory, GitLab ...)
      docker-archive:app.tar  /  app.tar       a `docker save` / `podman save` archive
      oci:./layout-dir  /  oci-archive:x.tar   an OCI image layout
      docker:app:1.2  /  podman:app:1.2        export from the local container engine

    examples:
      wimi registry.example.mil/team/api:2.4 \\
           --base registry1.dso.mil/ironbank/redhat/ubi/ubi9:9.4
      wimi registry.example.mil/team/api:2.4 \\
           --base "Iron Bank Python=registry1.dso.mil/ironbank/opensource/python:3.11" \\
           --base registry1.dso.mil/ironbank/redhat/ubi/ubi9:9.4 --scan
      wimi api.tar --base ubi9.tar --vuln-report trivy.json --app-name "Payments team build"

    identify bases automatically (no --base needed once the catalog knows them):
      wimi catalog crawl registry1.dso.mil/ironbank/redhat/ubi/ubi9 --limit 20
      wimi catalog add "Iron Bank Python 3.11=registry1.dso.mil/ironbank/opensource/python:3.11"
      wimi registry.example.mil/team/api:2.4
      run `wimi catalog --help` for more.

    credentials are read from `docker login` / `podman login`, or WIMI_USERNAME / WIMI_PASSWORD.

    scanners (--scan):
      An installed trivy / grype binary is used first. Otherwise, if a container engine socket is reachable
      (/var/run/docker.sock, a Podman socket, or DOCKER_HOST=unix://...) and the scanner image is present locally,
      the scanner runs as a sidecar container. Otherwise that scanner is skipped.
      WIMI_TRIVY_IMAGE / WIMI_GRYPE_IMAGE    scanner image(s), comma separated, e.g. registry.local/mirror/trivy:0.75.0
                                             (default aquasec/trivy and anchore/grype, newest local tag)
      WIMI_SCANNER_MODE                      auto (default) | binary | container | off
      WIMI_SCANNER_PULL                      true to pull a missing scanner image (default: never pull)
      TRIVY_* / GRYPE_*                      passed to the sidecar, e.g. TRIVY_CACHE_DIR, GRYPE_DB_CACHE_DIR; the volume
                                             holding a path they name is shared at the same path, read-only
                                             (only the scanner's database directory is writable)
      WIMI_SCANNER_ENV                       more variable names to pass through, comma separated; everything passed
                                             is visible to the scanner image
      WIMI_VULNDB_MOUNT                      SOURCE:/path[:ro|rw] to share instead of the detected volumes
      WIMI_SCANNER_TIMEOUT / _MEMORY / _USER sidecar limits (default 1800 seconds, no memory limit, image's user);
                                             memory as 512m, 4g, 4GiB ...
""")


FORMATS = ("html", "json", "csv")


def _formats(value: str) -> list[str]:
    fmts = [f.strip().lower() for f in value.split(",") if f.strip()]
    bad = [f for f in fmts if f not in FORMATS]
    if bad or not fmts:
        raise argparse.ArgumentTypeError(f"choose from {', '.join(FORMATS)}, comma separated (got {value!r})")
    return fmts


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wimi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
        description="What's In My Image: trace every package, library and program in a container image back to "
        "the base image or build step that put it there, and produce an executive-ready report.",
    )
    p.add_argument("image", help="image to analyse (see image sources below)")
    p.add_argument(
        "--base",
        action="append",
        default=[],
        metavar="[NAME=]IMAGE",
        help="base image the target was built FROM (repeat for a chain, e.g. Iron Bank Python and UBI)",
    )
    p.add_argument(
        "--app-name",
        default="Application build (your team)",
        help="label for the layers added on top of the base (default: %(default)s)",
    )
    p.add_argument(
        "--no-auto-base", action="store_true", help="do not try the base image recorded in the image's own annotations"
    )
    p.add_argument(
        "--catalog",
        type=Path,
        default=None,
        help=f"base image catalog used to identify bases automatically (default: {default_path()})",
    )
    p.add_argument("--no-catalog", action="store_true", help="do not consult the base image catalog")
    g = p.add_argument_group("vulnerabilities (optional)")
    g.add_argument(
        "--scan",
        nargs="?",
        const="auto",
        choices=["auto", "trivy", "grype"],
        help="run Trivy or Grype and attribute every finding: the installed binary if there is one, otherwise the "
        "scanner's container image if a container engine is reachable (see 'scanners' below)",
    )
    g.add_argument(
        "--vuln-report",
        action="append",
        default=[],
        type=Path,
        metavar="FILE",
        help="import an existing Trivy / Grype / Harbor JSON report",
    )
    g.add_argument(
        "--harbor-vulns",
        action="store_true",
        help="download the scan Harbor already ran for this image (Harbor registries only)",
    )
    g = p.add_argument_group("output")
    g.add_argument("-o", "--output-dir", type=Path, default=Path("wimi-reports"))
    g.add_argument(
        "--formats",
        type=_formats,
        action="extend",
        metavar="FORMAT[,FORMAT...]",
        help="report formats to write: html, json, csv, comma separated or repeated (default: all three)",
    )
    g.add_argument(
        "--subtitle",
        default="Container image provenance report",
        help="line shown above the report heading, e.g. 'Prepared for CISO review'",
    )
    g.add_argument("-q", "--quiet", action="store_true", help="only print the final summary")
    _add_registry_args(p)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _add_registry_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("registry access")
    g.add_argument("--platform", default="linux/amd64", help="platform for multi-arch images (default: %(default)s)")
    g.add_argument("--username", default=os.environ.get("WIMI_USERNAME"))
    g.add_argument("--password-stdin", action="store_true", help="read the registry password from stdin")
    g.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed registry certificates)")
    g.add_argument("--ca-cert", help="CA bundle for registries using an internal certificate authority (e.g. DoD PKI)")
    g.add_argument("--plain-http", action="store_true", help="use http:// instead of https://")
    g.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(os.environ.get("WIMI_CACHE", Path.home() / ".cache" / "whats-in-my-image")),
    )


def _registry_opts(args) -> dict:
    password = os.environ.get("WIMI_PASSWORD")
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    return dict(
        username=args.username,
        password=password,
        insecure=args.insecure,
        ca_cert=args.ca_cert,
        plain_http=args.plain_http,
    )


def _split_spec(spec: str) -> tuple[str, str]:
    """``NAME=IMAGE`` or ``IMAGE`` -> (name, image). Image references never contain '='."""
    name, sep, ref = spec.partition("=")
    return (name.strip(), ref.strip()) if sep and ref else ("", spec.strip())


def _safe_name(name: str) -> str:
    tail = name.rsplit("/", 1)[-1]
    return re.sub(r"[^A-Za-z0-9._-]+", "_", tail).strip("_")[:80] or "image"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "catalog":
        return catalog_main(argv[1:])
    if argv and argv[0] == "scan":
        argv = argv[1:]
    args = _parser().parse_args(argv)
    log = (lambda *a, **k: None) if args.quiet else (lambda msg: print(msg, file=sys.stderr, flush=True))

    target_opts = _registry_opts(args)
    common = dict(platform=args.platform, cache_dir=args.cache_dir, log=log)

    try:
        image = load_image(args.image, **common, **target_opts)
    except SourceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    target_registry = image.registry_client.ref.registry if image.registry_client else None

    # ---- base images: only their configs (layer digests) are needed, not their content
    base_specs = [_split_spec(spec) for spec in args.base]
    auto = image.annotations.get("org.opencontainers.image.base.name") or image.labels.get(
        "org.opencontainers.image.base.name"
    )
    if not base_specs and auto and not args.no_auto_base:
        log(f"Image records its base as {auto}; checking it")
        base_specs.append(("", auto))
    bases = []
    for name, ref in base_specs:
        try:
            opts = dict(target_opts)
            if target_registry and not ref.startswith(target_registry + "/"):
                opts.update(username=None, password=None)  # never send one registry's password to another
            b = load_image(ref, **common, fetch_layers=False, **opts)
            bases.append({"ref": ref, "label": name or base_label(ref), "diff_ids": b.diff_ids})
        except SourceError as e:
            print(f"warning: could not load base image {ref}: {e}", file=sys.stderr)

    # The catalog finds every known base in the image's ancestry, including ones the user did not
    # name, so an incomplete --base chain cannot silently credit a base's layers to the application.
    stale_notes: list[str] = []
    if not args.no_catalog:
        try:
            cat = Catalog.load(args.catalog)
        except ValueError as e:
            print(f"warning: {e}", file=sys.stderr)
            cat = None
        if cat and cat.entries:
            chain, near = cat.match(image.diff_ids)
            for e in chain + near:
                bases.append(
                    {
                        "ref": e["ref"],
                        "label": e.get("label") or base_label(e["ref"]),
                        "diff_ids": e["diff_ids"],
                        "source": "catalog",
                        "also": e.get("also", []),
                    }
                )
            log(f"Base image catalog: {len(cat.entries)} images, {len(chain)} matched this image")
            # A base that has had newer releases is a common, fixable cause of "base image" vulnerabilities.
            for e in chain:
                newer = cat.newer_releases(e)
                if newer:
                    latest = newer[0]
                    stale_notes.append(
                        f"Outdated base image: built on {e['ref']} (released {e['created'][:10]}). The catalog "
                        f"knows {len(newer)} newer release{'s' if len(newer) != 1 else ''} of this base; the latest "
                        f"is {latest['ref']} (released {latest['created'][:10]}). Rebuilding on it picks up the "
                        "vendor's fixes."
                    )
        elif not base_specs:
            log(
                "Tip: catalogue your base images (`wimi catalog crawl` / `wimi catalog add`) "
                "to identify them automatically"
            )
    seen: set = set()
    bases = [b for b in bases if not (tuple(b["diff_ids"]) in seen or seen.add(tuple(b["diff_ids"])))]

    # ---- walk layers, attribute, analyse
    log(f"Analysing {image.name} ({len(image.layers)} layers)")
    walker = Walker()
    walker.scan(image, log)
    history, _ = image.layer_history()
    origins, per_layer, notes = compute_origins(image.diff_ids, bases, history, image.labels, args.app_name)
    notes += stale_notes
    analyzer = Analyzer(image, walker, origins, per_layer)
    analyzer.run()

    # ---- vulnerabilities
    found_vulns = None
    tool = ""
    diff_index = {d: i for i, d in enumerate(image.diff_ids)}
    for path in args.vuln_report:
        try:
            found_vulns = (found_vulns or []) + vulnmod.load_report(path, diff_index)
            tool = tool or f"imported report ({path.name})"
        except (OSError, ValueError) as e:
            print(f"warning: could not read {path}: {e}", file=sys.stderr)
    if args.harbor_vulns:
        hv = vulnmod.fetch_harbor(image, log)
        if hv is not None:
            found_vulns, tool = (found_vulns or []) + hv, tool or "Harbor scan"
    scan_info = None
    if args.scan:
        res = vulnmod.run_scanner(args.scan, image, log)
        if res:
            _, sv, scan_info = res
            found_vulns = (found_vulns or []) + sv
            tool = " ".join(filter(None, (scan_info.get("tool"), scan_info.get("version"))))
    if found_vulns is not None:
        found_vulns = _dedupe(found_vulns)
        vulnmod.attribute(found_vulns, [vars(c) for c in analyzer.components], per_layer)

    model = report.build(
        image, walker, analyzer, origins, per_layer, notes, found_vulns, tool, args.app_name, vuln_scan=scan_info
    )
    model["subtitle"] = args.subtitle

    # ---- write outputs
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stem = args.output_dir / f"provenance-{_safe_name(image.name)}"
    formats = set(args.formats or FORMATS)
    written = []
    if "html" in formats:
        p = stem.with_name(stem.name + ".html")
        p.write_text(html_report.render(model), encoding="utf-8")
        written.append(p)
    if "json" in formats:
        p = stem.with_name(stem.name + ".json")
        p.write_text(json.dumps(model, indent=2, default=str), encoding="utf-8")
        written.append(p)
    if "csv" in formats:
        written.append(_write_csv(stem.with_name(stem.name + "-components.csv"), model))
        if model["vulns"] is not None:
            written.append(_write_vuln_csv(stem.with_name(stem.name + "-vulnerabilities.csv"), model))

    _print_summary(model, written)
    return 0


def catalog_main(argv: list[str]) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--catalog", type=Path, default=None, help=f"catalog file (default: {default_path()}, or set WIMI_CATALOG)"
    )
    p = argparse.ArgumentParser(
        prog="wimi catalog",
        description="Manage the catalog of known base images. Once a base is catalogued, `wimi` recognises it in "
        "any image by exact layer digests, without --base. The catalog stores only layer digests, so it "
        "is small and safe to share across a team.",
    )
    sub = p.add_subparsers(dest="cmd", required=True, metavar="{add,crawl,list,remove}")
    a = sub.add_parser("add", parents=[common], help="add one or more base images")
    a.add_argument("images", nargs="+", metavar="[NAME=]IMAGE", help="registry reference, archive or OCI layout")
    _add_registry_args(a)
    c = sub.add_parser(
        "crawl", parents=[common], help="add many tags of one repository, e.g. every Iron Bank UBI 9 release"
    )
    c.add_argument("repository", help="e.g. registry1.dso.mil/ironbank/redhat/ubi/ubi9")
    c.add_argument("--match", metavar="REGEX", help="only tags matching this regular expression")
    c.add_argument("--limit", type=int, default=25, help="newest N tags to add, 0 for all (default: %(default)s)")
    c.add_argument("--name", default="", help="label for these entries (default: derived from the repository)")
    _add_registry_args(c)
    sub.add_parser("list", parents=[common], help="show the catalogued images")
    r = sub.add_parser("remove", parents=[common], help="remove entries whose reference matches")
    r.add_argument("pattern", help="exact reference or regular expression")
    args = p.parse_args(argv)

    try:
        cat = Catalog.load(args.catalog)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.cmd == "list":
        if not cat.entries:
            print(f"The catalog at {cat.path} is empty. Add bases with `wimi catalog add` or `wimi catalog crawl`.")
            return 0
        for e in sorted(cat.entries, key=lambda e: e["ref"]):
            n = len(e["diff_ids"])
            layers = f"{n:>2} layer{'s' if n != 1 else ' '}"
            print(f"{e['ref']:<70} {layers}  {(e.get('created') or '')[:10]}  {e.get('label', '')}")
        print(f"\n{len(cat.entries)} images in {cat.path}")
        return 0
    if args.cmd == "remove":
        n = cat.remove(args.pattern)
        cat.save()
        print(f"Removed {n} entr{'y' if n == 1 else 'ies'} from {cat.path}")
        return 0

    opts = _registry_opts(args)
    common_opts = dict(platform=args.platform, cache_dir=args.cache_dir, log=lambda m: None)
    if args.cmd == "add":
        targets = [_split_spec(s) for s in args.images]
    else:
        try:
            ref = parse_ref(args.repository)
            tags = RegistryClient(ref, **opts).list_tags()
        except RegistryError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        chosen = pick_tags(tags, args.match, args.limit)
        print(f"{ref.registry}/{ref.repository}: {len(tags)} tags, adding {len(chosen)}", file=sys.stderr)
        targets = [(args.name, f"{ref.registry}/{ref.repository}:{t}") for t in chosen]

    failed = 0
    for i, (name, image_ref) in enumerate(targets, 1):
        try:
            img = load_image(image_ref, fetch_layers=False, **common_opts, **opts)
        except SourceError as e:
            print(f"  skipped {image_ref}: {e}", file=sys.stderr)
            failed += 1
            continue
        changed = cat.add(image_ref, img.diff_ids, label=name, digest=img.manifest_digest or "", created=img.created)
        n = len(img.diff_ids)
        print(
            f"  {'added  ' if changed else 'current'}  {image_ref}  ({n} layer{'s' if n != 1 else ''})", file=sys.stderr
        )
        if i % 10 == 0:
            cat.save()
    cat.save()
    print(f"Catalog now holds {len(cat.entries)} images: {cat.path}")
    return 1 if failed and failed == len(targets) else 0


def _dedupe(vs):
    seen, out = set(), []
    for v in vs:
        key = (v.id, v.package, v.version, v.path)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


def _write_csv(path: Path, m: dict) -> Path:
    labels = {o["key"]: o["label"] for o in m["origins"]}
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "component",
                "version",
                "type",
                "supplier",
                "added_by",
                "layer",
                "change",
                "previous_version",
                "managed_by",
                "location",
                "license",
                "concerns",
                "evidence",
                "purl",
            ]
        )
        for c in m["components"]:
            w.writerow(
                [
                    c["name"],
                    c["version"],
                    c["type_label"],
                    c["supplier"],
                    labels.get(c["origin"], c["origin"]),
                    c["layer"] + 1,
                    c["change"],
                    c["previous_version"],
                    c["managed_by"],
                    "; ".join(c["paths"]),
                    c["license"],
                    "; ".join(f["message"] for f in c["flags"]),
                    "; ".join(c["evidence"]),
                    c["purl"],
                ]
            )
    return path


def _write_vuln_csv(path: Path, m: dict) -> Path:
    labels = {o["key"]: o["label"] for o in m["origins"]}
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "id",
                "severity",
                "package",
                "installed_version",
                "fixed_version",
                "vendor_fix_status",
                "introduced_by",
                "layer",
                "attribution",
                "title",
            ]
        )
        for v in m["vulns"]:
            w.writerow(
                [
                    v["id"],
                    v["severity"],
                    v["package"],
                    v["version"],
                    v["fixed_version"],
                    m["fix_status_labels"].get(v["fix_status"], v["fix_status"]),
                    labels.get(v["origin"], v["origin"]),
                    "" if v["layer"] is None else v["layer"] + 1,
                    v["attribution"],
                    v["title"],
                ]
            )
    return path


def _print_summary(m: dict, written: list[Path]) -> None:
    out = sys.stdout
    width = 78
    print("\n" + "=" * width, file=out)
    print(f" {m['image']['name']}", file=out)
    print("=" * width, file=out)
    for o in m["origins"]:
        layers = (
            f"layers {o['layers'][0]}-{o['layers'][-1]}"
            if len(o["layers"]) > 1
            else (f"layer {o['layers'][0]}" if o["layers"] else "")
        )
        vul = f"  {o['vulns_total']:>5} vulns" if m["vulns"] is not None else ""
        print(f" {o['label'][:44]:<44} {layers:<13} {o['components']:>6} comps{vul}", file=out)
    print("-" * width, file=out)
    for t in m["takeaways"]:
        mark = {"good": "+", "bad": "!", "warn": "!", "neutral": "*"}[t["tone"]]
        print(textwrap.fill(t["text"], width, initial_indent=f" {mark} ", subsequent_indent="   "), file=out)
    print("-" * width, file=out)
    for p in written:
        print(f" wrote {p}", file=out)
    print(file=out)
