"""Offline tests: synthetic images exercise the full pipeline without network access.

Run with:  python -m unittest discover -s tests
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import json
import os
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path

from whats_in_my_image import cli
from whats_in_my_image.analyze import compute_origins
from whats_in_my_image.catalog import Catalog, pick_tags
from whats_in_my_image.describe import describe
from whats_in_my_image.parsers import gobuild, rpm
from whats_in_my_image.suppliers import compare_versions
from whats_in_my_image.vulns import fix_status, parse_grype, parse_harbor

ELF = b"\x7fELF" + b"\0" * 124
WH = None  # marker for a whiteout


def make_layer(files: dict) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for path, content in files.items():
            if content is WH:
                d, _, b = path.rpartition("/")
                ti = tarfile.TarInfo(f"{d}/.wh.{b}" if d else f".wh.{b}")
                tf.addfile(ti, io.BytesIO(b""))
            elif isinstance(content, tuple) and content[0] == "symlink":
                ti = tarfile.TarInfo(path)
                ti.type, ti.linkname = tarfile.SYMTYPE, content[1]
                tf.addfile(ti)
            else:
                ti = tarfile.TarInfo(path)
                ti.size, ti.mode = len(content), 0o755
                tf.addfile(ti, io.BytesIO(content))
    return gzip.compress(raw.getvalue())


def write_oci(root: Path, layers: list[bytes], history: list[str]) -> Path:
    blobs = root / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    def put(data: bytes) -> str:
        h = hashlib.sha256(data).hexdigest()
        (blobs / h).write_bytes(data)
        return "sha256:" + h

    descs, diff_ids = [], []
    for lyr in layers:
        descs.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": put(lyr), "size": len(lyr)})
        diff_ids.append("sha256:" + hashlib.sha256(gzip.decompress(lyr)).hexdigest())
    config = {
        "architecture": "amd64",
        "os": "linux",
        "created": "2026-09-01T00:00:00Z",
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
        "history": [{"created": "2026-09-01T00:00:00Z", "created_by": h} for h in history],
    }
    cfg = json.dumps(config).encode()
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": put(cfg), "size": len(cfg)},
            "layers": descs,
        }
    ).encode()
    md = put(manifest)
    (root / "index.json").write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": md, "size": len(manifest)}
                ],
            }
        )
    )
    (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    return root


DPKG_BASE = b"""Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.36-9
Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>

Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.11-1
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@lists.debian.org>
"""
DPKG_APP = (
    DPKG_BASE.replace(b"3.0.11-1", b"3.0.15-1")
    + b"""
Package: curl
Status: install ok installed
Architecture: amd64
Version: 7.88.1-10
Maintainer: Alessandro Ghedini <ghedo@debian.org>
"""
)
PY_META = b"Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nLicense: Apache-2.0\n"
SITE = "usr/local/lib/python3.12/site-packages"


def build_fixture(tmp: Path) -> tuple[Path, Path]:
    base_layer = make_layer(
        {
            "etc/os-release": b'ID=debian\nPRETTY_NAME="Debian GNU/Linux 12"\n',
            "bin": ("symlink", "usr/bin"),
            "var/lib/dpkg/status": DPKG_BASE,
            "var/lib/dpkg/info/libc6:amd64.list": b"/.\n/bin/ls\n",
            "var/lib/dpkg/info/openssl.list": b"/usr/bin/openssl\n",
            "usr/bin/ls": ELF,
            "usr/bin/openssl": ELF,
            "usr/bin/legacy": ELF,
        }
    )
    os_layer = make_layer(
        {
            "var/lib/dpkg/status": DPKG_APP,
            "var/lib/dpkg/info/curl.list": b"/usr/bin/curl\n",
            "usr/bin/curl": ELF,
            "usr/bin/openssl": ELF,
        }
    )
    app_layer = make_layer(
        {
            f"{SITE}/requests-2.31.0.dist-info/METADATA": PY_META,
            f"{SITE}/requests-2.31.0.dist-info/INSTALLER": b"pip\n",
            f"{SITE}/requests-2.31.0.dist-info/RECORD": b"requests/_native.so,,\n",
            f"{SITE}/requests/_native.so": ELF,
            "opt/app/node_modules/left-pad/package.json": b'{"name":"left-pad","version":"1.3.0","license":"WTFPL"}',
            "opt/app/node_modules/left-pad/native.node": ELF,
            "usr/local/bin/mystery-tool": ELF,
            "usr/bin/legacy": WH,
        }
    )
    base_dir = write_oci(tmp / "base", [base_layer], ["/bin/sh -c #(nop) ADD file:abc in / "])
    # A second-level base built on the first one, like Iron Bank Python on top of UBI.
    write_oci(tmp / "middle", [base_layer, os_layer], ["/bin/sh -c #(nop) ADD file:abc in / ", "RUN apt-get install"])
    target = write_oci(
        tmp / "app",
        [base_layer, os_layer, app_layer],
        [
            "/bin/sh -c #(nop) ADD file:abc in / ",
            "RUN /bin/sh -c apt-get update && apt-get install -y curl && apt-get upgrade -y # buildkit",
            "RUN /bin/sh -c curl -k https://example.com/install.sh | sh && pip install requests # buildkit",
        ],
    )
    return target, base_dir


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.target, self.base = build_fixture(self.tmp)
        self.middle = self.tmp / "middle"
        self.catalog = self.tmp / "catalog.json"
        self._env = os.environ.get("WIMI_CATALOG")
        os.environ["WIMI_CATALOG"] = str(self.catalog)  # never read the developer's real catalog
        self._scans = 0

    def tearDown(self):
        if self._env is None:
            os.environ.pop("WIMI_CATALOG", None)
        else:
            os.environ["WIMI_CATALOG"] = self._env
        self._tmp.cleanup()

    def catalog_add(self, *specs: str) -> None:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(["catalog", "add", *specs, "--cache-dir", str(self.tmp / "cache")])
        self.assertEqual(rc, 0)

    def scan(self, *extra) -> dict:
        """Scan the target with no --base unless one is given in ``extra``."""
        self._scans += 1
        out = self.tmp / f"scan{self._scans}"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main([f"oci:{self.target}", "-o", str(out), "-q", "--cache-dir", str(self.tmp / "cache"), *extra])
        self.assertEqual(rc, 0)
        return json.loads(next(out.glob("*.json")).read_text())

    def test_catalog_identifies_full_base_chain_without_base_flag(self):
        self.catalog_add(f"Debian base=oci:{self.base}", f"Python base=oci:{self.middle}")
        m = self.scan()
        self.assertEqual([lyr["origin"] for lyr in m["layers"]], ["base0", "base1", "app"])
        labels = {o["key"]: o for o in m["origins"]}
        self.assertEqual(labels["base0"]["label"], "Debian base")
        self.assertEqual(labels["base1"]["label"], "Python base")
        self.assertIn("catalog", labels["base1"]["note"])
        self.assertEqual(labels["base1"]["match"], "exact layer-digest match")

    def test_catalog_completes_an_incomplete_base_flag(self):
        # The user names only the lowest base; the catalog knows the one in between.
        self.catalog_add(f"Python base=oci:{self.middle}")
        m = self.scan("--base", f"Debian base=oci:{self.base}")
        self.assertEqual([lyr["origin"] for lyr in m["layers"]], ["base0", "base1", "app"])
        curl = next(c for c in m["components"] if c["name"] == "curl")
        self.assertEqual(curl["origin"], "base1")  # not wrongly credited to the application build

    def test_outdated_base_is_reported(self):
        base_layer = self.scan("--no-catalog")["layers"][0]["diff_id"]
        cat = Catalog(self.catalog)
        cat.add("reg.example/debian:12-old", [base_layer], label="Debian 12", created="2026-01-01T00:00:00Z")
        cat.add("reg.example/debian:12-new", ["sha256:" + "f" * 64], created="2026-05-01T00:00:00Z")
        cat.save()
        m = self.scan()
        self.assertEqual(m["layers"][0]["origin"], "base0")
        self.assertTrue(
            any(n.startswith("Outdated base image: built on reg.example/debian:12-old") for n in m["notes"])
        )
        self.assertTrue(any(f["title"] == "The base image is out of date" for f in m["findings"]))

    def test_no_catalog_flag_ignores_catalog(self):
        self.catalog_add(f"oci:{self.base}")
        m = self.scan("--no-catalog")
        self.assertNotIn("base0", {lyr["origin"] for lyr in m["layers"]} - {"unknown"})

    def run_cli(self, *extra) -> dict:
        out = self.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(
                [
                    f"oci:{self.target}",
                    "--base",
                    f"Iron Bank Debian=oci:{self.base}",
                    "-o",
                    str(out),
                    "-q",
                    "--cache-dir",
                    str(self.tmp / "cache"),
                    *extra,
                ]
            )
        self.assertEqual(rc, 0)
        return json.loads(next(out.glob("*.json")).read_text())

    def test_layers_attributed_to_base_by_digest(self):
        m = self.run_cli()
        self.assertEqual([lyr["origin"] for lyr in m["layers"]], ["base0", "app", "app"])
        self.assertEqual(m["origins"][0]["label"], "Iron Bank Debian")
        self.assertEqual(m["origins"][0]["match"], "exact layer-digest match")

    def test_package_upgrade_moves_responsibility(self):
        m = self.run_cli()
        comps = {c["name"]: c for c in m["components"]}
        self.assertEqual(comps["libc6"]["origin"], "base0")
        self.assertEqual(comps["openssl"]["origin"], "app")
        self.assertEqual(comps["openssl"]["change"], "upgraded")
        self.assertEqual(comps["openssl"]["previous_version"], "3.0.11-1")
        self.assertEqual(comps["curl"]["origin"], "app")
        self.assertEqual(comps["requests"]["supplier"], "PyPI (Python Package Index)")
        self.assertEqual(comps["left-pad"]["ecosystem"], "npm")

    def test_unmanaged_binaries_and_ownership(self):
        m = self.run_cli()
        loose = sorted(c["paths"][0] for c in m["components"] if c["ecosystem"] == "binary")
        # ls is owned through the /bin -> usr/bin symlink; the .so via RECORD; native.node via npm;
        # legacy was deleted by a whiteout; only mystery-tool is truly untraceable.
        self.assertEqual(loose, ["usr/local/bin/mystery-tool"])
        openssl = next(c for c in m["components"] if c["name"] == "openssl")
        self.assertFalse(any("replaced" in f["message"] for f in openssl["flags"]))

    def test_risky_build_steps_flagged(self):
        m = self.run_cli()
        msgs = [r["message"] for r in m["layers"][2]["risks"]]
        self.assertTrue(any("runs it immediately" in x for x in msgs))
        self.assertTrue(any("TLS certificate" in x for x in msgs))

    def test_vulnerabilities_attributed(self):
        diff_ids = [lyr["diff_id"] for lyr in self.run_cli()["layers"]]
        trivy = {
            "Results": [
                {
                    "Target": "debian",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "libc6",
                            "InstalledVersion": "2.36-9",
                            "Severity": "HIGH",
                            "Status": "will_not_fix",
                            "Layer": {"DiffID": diff_ids[0]},
                        },
                        {
                            "VulnerabilityID": "CVE-2",
                            "PkgName": "curl",
                            "InstalledVersion": "7.88.1-10",
                            "Severity": "CRITICAL",
                            "FixedVersion": "7.88.1-11",
                            "Status": "fixed",
                            "Layer": {"DiffID": diff_ids[1]},
                        },
                        {
                            "VulnerabilityID": "CVE-3",
                            "PkgName": "requests",
                            "InstalledVersion": "2.31.0",
                            "Severity": "HIGH",
                            "Status": "end_of_life",
                            "PkgPath": f"{SITE}/requests-2.31.0.dist-info/METADATA",
                        },
                    ],
                }
            ]
        }
        rp = self.tmp / "trivy.json"
        rp.write_text(json.dumps(trivy))
        m = self.run_cli("--vuln-report", str(rp))
        by_id = {v["id"]: v for v in m["vulns"]}
        self.assertEqual(by_id["CVE-1"]["origin"], "base0")
        self.assertEqual(by_id["CVE-2"]["origin"], "app")
        self.assertEqual(by_id["CVE-3"]["origin"], "app")
        self.assertTrue(any("introduced after" in t["text"] for t in m["takeaways"]))
        # vendor fix status
        self.assertEqual(
            [by_id[c]["fix_status"] for c in ("CVE-1", "CVE-2", "CVE-3")], ["will_not_fix", "fixed", "end_of_life"]
        )
        titles = {(f["origin"], f["title"]) for f in m["findings"]}
        self.assertIn(("base0", "1 vulnerability the vendor has decided not to fix"), titles)
        self.assertIn(("app", "1 vulnerability in software the vendor no longer supports"), titles)
        self.assertTrue(any("will never be removed by updating" in t["text"] for t in m["takeaways"]))
        self.assertEqual(m["origins"][0]["vulns_by_fix"], {"will_not_fix": 1})
        html = next((self.tmp / "out").glob("*.html")).read_text()
        self.assertIn("CVE-2", html)
        self.assertIn("Vendor will not fix", html)
        self.assertIn('data-fix="end_of_life"', html)
        vcsv = next((self.tmp / "out").glob("*-vulnerabilities.csv")).read_text()
        self.assertIn("vendor_fix_status", vcsv.splitlines()[0])
        self.assertIn("No longer supported by vendor", vcsv)
        # layer cake: one slice per layer, each linked to its build step, with the base seam marked
        self.assertEqual(html.count('class="slice"'), 3)
        for n in (1, 2, 3):
            self.assertIn(f'href="#step-{n}"', html)
            self.assertIn(f'id="step-{n}"', html)
        self.assertIn("Iron Bank Debian ends here", html)

    def test_mismatched_base_is_reported(self):
        other = write_oci(self.tmp / "other", [make_layer({"x": b"y"})], ["ADD x /"])
        out = self.tmp / "out2"
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(
                [
                    f"oci:{self.target}",
                    "--base",
                    f"oci:{other}",
                    "-o",
                    str(out),
                    "-q",
                    "--cache-dir",
                    str(self.tmp / "cache"),
                ]
            )
        m = json.loads(next(out.glob("*.json")).read_text())
        self.assertTrue(any("NOT built on" in n for n in m["notes"]))

    def test_formats_flag_before_image_writes_only_that_format(self):
        out = self.tmp / "out-json"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(
                [
                    "--formats",
                    "json",
                    f"oci:{self.target}",
                    "-o",
                    str(out),
                    "-q",
                    "--cache-dir",
                    str(self.tmp / "cache"),
                ]
            )
        self.assertEqual(rc, 0)
        self.assertEqual([p.suffix for p in out.iterdir()], [".json"])


class FormatsFlag(unittest.TestCase):
    def parse(self, *argv: str):
        with contextlib.redirect_stderr(io.StringIO()):
            return cli._parser().parse_args(list(argv))

    def formats(self, *argv: str) -> list[str]:
        args = self.parse(*argv)
        self.assertEqual(args.image, "IMG")
        return sorted(set(args.formats or cli.FORMATS))

    def test_default_is_all_formats(self):
        self.assertEqual(self.formats("IMG"), ["csv", "html", "json"])

    def test_comma_list(self):
        self.assertEqual(self.formats("IMG", "--formats", "html,json"), ["html", "json"])

    def test_repeated_flag(self):
        self.assertEqual(self.formats("IMG", "--formats", "html", "--formats", "json"), ["html", "json"])

    def test_flag_before_image_does_not_swallow_it(self):
        self.assertEqual(self.formats("--formats", "json", "IMG"), ["json"])

    def test_case_and_spaces_ignored(self):
        self.assertEqual(self.formats("IMG", "--formats", " HTML , Json "), ["html", "json"])

    def test_invalid_values_are_rejected(self):
        for bad in ("pdf", "html,pdf", ",", ""):
            with self.subTest(bad=bad), self.assertRaises(SystemExit) as cm:
                self.parse("IMG", "--formats", bad)
            self.assertEqual(cm.exception.code, 2)

    def test_missing_value_is_rejected(self):
        with self.assertRaises(SystemExit) as cm:
            self.parse("IMG", "--formats")
        self.assertEqual(cm.exception.code, 2)


class CatalogLogic(unittest.TestCase):
    def test_match_returns_chain_and_nearest_other_tag(self):
        cat = Catalog(Path("unused.json"))
        cat.add("ubi9:9.4", ["a", "b"])
        cat.add("ubi9:9.4-again", ["a", "b"])  # same release under another tag
        cat.add("python:3.12-newer", ["a", "b", "c", "z"])  # shares 3 layers, then diverges
        cat.add("ubi8:8.10", ["a", "q"])  # shares less than the full match: irrelevant
        chain, near = cat.match(["a", "b", "c", "d"])
        self.assertEqual([e["ref"] for e in chain], ["ubi9:9.4"])
        self.assertEqual(chain[0]["also"], ["ubi9:9.4-again"])
        self.assertEqual([(e["ref"], e["prefix"]) for e in near], [("python:3.12-newer", 3)])

    def test_newer_releases_of_the_same_base(self):
        cat = Catalog(Path("unused.json"))
        cat.add("reg/ubi9:9.4-1", ["a"], created="2026-01-01T00:00:00Z")
        cat.add("reg/ubi9:9.4-2", ["b"], created="2026-03-01T00:00:00Z")
        cat.add("reg/ubi9:9.4", ["b"], created="2026-03-01T00:00:00Z")  # same release, second tag
        cat.add("reg/other:1", ["c"], created="2026-06-01T00:00:00Z")
        newer = cat.newer_releases(cat.entries[0])
        self.assertEqual([e["diff_ids"] for e in newer], [["b"]])

    def test_pick_tags_newest_first(self):
        tags = ["9.2", "9.10", "latest", "9.4", "sha256-abc.sig"]
        self.assertEqual(pick_tags(tags, None, 2), ["9.10", "9.4"])
        self.assertEqual(pick_tags(tags, r"^9\.[0-9]$", 0), ["9.4", "9.2"])

    def test_warns_when_application_layers_hide_another_base(self):
        history = [
            {"created": "2025-12-01T00:00:00Z"},
            {"created": "2026-01-01T00:00:00Z"},  # built a month before the rest: probably another base
            {"created": "2026-03-01T00:00:00Z"},
            {"created": "2026-03-01T00:05:00Z"},
        ]
        bases = [{"ref": "ubi9", "label": "UBI 9", "diff_ids": ["a"]}]
        _, per_layer, notes = compute_origins(["a", "b", "c", "d"], bases, history, {}, "App")
        self.assertEqual(per_layer, ["base0", "app", "app", "app"])
        self.assertTrue(any(n.startswith("Possible unidentified base image: Layer 2 was") for n in notes))


class VendorFixStatus(unittest.TestCase):
    def test_normalisation(self):
        self.assertEqual(fix_status("will_not_fix", ""), "will_not_fix")  # Trivy
        self.assertEqual(fix_status("wont-fix", ""), "will_not_fix")  # Grype
        self.assertEqual(fix_status("not-fixed", ""), "affected")  # Grype
        self.assertEqual(fix_status("affected", "1.2.3"), "fixed")  # a fixed version always wins
        self.assertEqual(fix_status(None, ""), "unknown")  # e.g. Harbor: no reason given
        self.assertEqual(fix_status("something-new", ""), "unknown")

    def test_grype_and_harbor(self):
        grype = {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-9", "severity": "High", "fix": {"state": "wont-fix", "versions": []}},
                    "artifact": {"name": "zlib", "version": "1.2"},
                },
                {
                    "vulnerability": {"id": "CVE-8", "severity": "Low", "fix": {"state": "fixed", "versions": ["1.3"]}},
                    "artifact": {"name": "zlib", "version": "1.2"},
                },
            ]
        }
        self.assertEqual([v.fix_status for v in parse_grype(grype, {})], ["will_not_fix", "fixed"])
        harbor = {
            "vulnerabilities": [{"id": "CVE-7", "severity": "High", "package": "x", "version": "1", "fix_version": ""}]
        }
        self.assertEqual(parse_harbor(harbor, {})[0].fix_status, "unknown")


class Parsers(unittest.TestCase):
    def test_rpm_header_and_signature(self):
        sig = (
            bytes([0x89])
            + struct.pack(">H", 0)
            + bytes([4, 0, 1, 8])
            + struct.pack(">H", 0)
            + struct.pack(">H", 10)
            + bytes([9, 16])
            + bytes.fromhex("199e2f91fd431d51")
        )
        sig = bytes([0x89]) + struct.pack(">H", len(sig) - 3) + sig[3:]
        entries, store = [], b""

        def add(tag, typ, data, count=1):
            nonlocal store
            entries.append(struct.pack(">iiii", tag, typ, len(store), count))
            store += data

        add(1000, 6, b"openssl\0")
        add(1001, 6, b"3.0.7\0")
        add(1002, 6, b"27.el9\0")
        add(1022, 6, b"x86_64\0")
        add(1011, 6, b"Red Hat, Inc.\0")
        add(268, 7, sig, len(sig))
        blob = struct.pack(">ii", len(entries), len(store)) + b"".join(entries) + store
        p = rpm.parse_header(blob)
        self.assertEqual((p.name, p.evr, p.vendor), ("openssl", "3.0.7-27.el9", "Red Hat, Inc."))
        self.assertEqual(p.sig_key_id, "199e2f91fd431d51")

    def test_go_buildinfo(self):
        mod = "path\texample.com/cmd/x\nmod\texample.com\tv1.2.3\th1:abc\ndep\tgithub.com/a/b\tv0.1.0\th1:x\n"
        modb = b"0" * 16 + mod.encode()[:-1] + b"\n" + b"1" * 16

        def varstr(b):
            return bytes([len(b)]) if len(b) < 128 else bytes([len(b) & 0x7F | 0x80, len(b) >> 7])

        ver = b"go1.22.1"
        data = b"junk" + gobuild.MAGIC + bytes([8, 2]) + b"\0" * 16 + varstr(ver) + ver + varstr(modb) + modb
        info = gobuild.parse(data)
        self.assertEqual(info["go_version"], "go1.22.1")
        self.assertEqual(info["main"], ("example.com", "v1.2.3"))
        self.assertEqual(info["deps"], [("github.com/a/b", "v0.1.0")])

    def test_describe(self):
        d = describe("/bin/sh -c #(nop) COPY --from=builder /out/app /usr/local/bin/app")
        self.assertIn("earlier build stage", d["summary"])
        d = describe("RUN /bin/sh -c dnf install -y --nogpgcheck foo # buildkit")
        self.assertIn("Installed operating-system packages (dnf/yum)", d["summary"])
        self.assertEqual(d["risks"][0]["severity"], "high")

    def test_version_compare(self):
        self.assertEqual(compare_versions("3.0.15-1", "3.0.11-1"), 1)
        self.assertEqual(compare_versions("1:1.0", "2.0"), 1)
        self.assertEqual(compare_versions("1.0~rc1", "1.0"), -1)


if __name__ == "__main__":
    unittest.main()
