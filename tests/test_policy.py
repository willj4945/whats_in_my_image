"""--fail-on: rule parsing, each rule, and exit codes 0 pass, 1 policy failed, 2 usage or load error, 3 unexpected."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_wimi import build_fixture

from whats_in_my_image import cli, policy

BASE, APP = {"key": "base0", "kind": "base"}, {"key": "app", "kind": "app"}


def vuln(id_, severity, origin, fix_status="affected"):
    return {"id": id_, "severity": severity, "origin": origin, "fix_status": fix_status, "package": "p", "version": "1"}


def rpm(name, *messages, ecosystem="rpm"):
    return {
        "name": name,
        "version": "1",
        "layer": 0,
        "ecosystem": ecosystem,
        "flags": [{"message": m} for m in messages],
    }


def layer(number, kind="app", risks=()):
    return {"number": number, "origin_kind": kind, "risks": [{"severity": s, "message": m} for s, m in risks]}


def model(vulns=None, origins=(BASE, APP), components=(), layers=(), notes=()):
    return {
        "origins": list(origins),
        "vulns": vulns,
        "components": list(components),
        "layers": list(layers),
        "notes": list(notes),
    }


def check(m, rule, **kw) -> dict:
    return policy.evaluate(m, [rule], **kw)["rules"][0]


class ParseRules(unittest.TestCase):
    def test_valid_rules_are_normalized(self):
        self.assertEqual(policy.parse_rule(" App:HIGH+Fixable "), "app:high+fixable")
        for rule in ("base:critical", "any:low", *policy.CHECKS):
            self.assertEqual(policy.parse_rule(rule), rule)

    def test_fixable_is_a_modifier_not_a_rule(self):
        with self.assertRaisesRegex(ValueError, "modifier"):
            policy.parse_rule("fixable")

    def test_unknown_rules_are_rejected(self):
        for bad in ("app:hgh", "app", "high", "team:high", "app:high+fix", "risky"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                policy.parse_rule(bad)

    def test_cli_accepts_a_comma_list_or_repeated_flag(self):
        args = cli._parser().parse_args(["IMG", "--fail-on", "app:high, risky-step", "--fail-on", "OUTDATED-BASE"])
        self.assertEqual(args.fail_on, ["app:high", "risky-step", "outdated-base"])
        self.assertEqual(cli._parser().parse_args(["IMG"]).fail_on, [])

    def test_duplicate_rules_are_evaluated_once(self):
        self.assertEqual(len(policy.evaluate(model(), ["risky-step", "risky-step"])["rules"]), 1)


class VulnerabilityRules(unittest.TestCase):
    VULNS = [
        vuln("CVE-A1", "CRITICAL", "app", "fixed"),
        vuln("CVE-A2", "HIGH", "app"),
        vuln("CVE-A3", "MEDIUM", "app", "fixed"),
        vuln("CVE-B1", "HIGH", "base0", "fixed"),
        vuln("CVE-B2", "LOW", "base0"),
        vuln("CVE-U1", "CRITICAL", "unknown"),
        vuln("CVE-X1", "UNKNOWN", "app"),
    ]

    def ids(self, rule):
        r = check(model(self.VULNS), rule)
        self.assertIsNone(r["missing"])
        return sorted(i.split()[0] for i in r["items"])

    def test_severity_threshold_counts_that_severity_and_above(self):
        self.assertEqual(self.ids("app:critical"), ["CVE-A1"])
        self.assertEqual(self.ids("app:high"), ["CVE-A1", "CVE-A2"])
        self.assertEqual(self.ids("app:medium"), ["CVE-A1", "CVE-A2", "CVE-A3"])

    def test_scope(self):
        self.assertEqual(self.ids("base:high"), ["CVE-B1"])
        self.assertEqual(self.ids("base:low"), ["CVE-B1", "CVE-B2"])
        self.assertEqual(self.ids("any:critical"), ["CVE-A1", "CVE-U1"])  # includes unattributed findings

    def test_fixable_modifier(self):
        self.assertEqual(self.ids("app:high+fixable"), ["CVE-A1"])
        self.assertEqual(self.ids("app:medium+fixable"), ["CVE-A1", "CVE-A3"])
        self.assertEqual(self.ids("any:low+fixable"), ["CVE-A1", "CVE-A3", "CVE-B1"])

    def test_pass_and_fail(self):
        self.assertFalse(check(model(self.VULNS), "app:high")["passed"])
        self.assertEqual(check(model(self.VULNS), "app:high")["count"], 2)
        self.assertTrue(check(model(self.VULNS), "base:critical")["passed"])
        self.assertTrue(check(model([]), "any:low")["passed"])  # a scan that found nothing passes

    def test_no_scan_data_fails(self):
        for rule in ("app:high", "base:critical+fixable", "any:low"):
            r = check(model(None), rule)
            self.assertFalse(r["passed"], rule)
            self.assertIn("no vulnerability data", r["missing"])
        r = check(model(None), "app:high", scan_requested=True)
        self.assertIn("--scan did not produce vulnerability data", r["missing"])

    def test_no_attribution_fails_app_and_base_rules(self):
        m = model([], origins=[{"key": "unknown", "kind": "unknown"}])
        for rule in ("app:high", "base:high"):
            r = check(m, rule)
            self.assertFalse(r["passed"], rule)
            self.assertIn("could not be identified", r["missing"])
        self.assertTrue(check(m, "any:high")["passed"])  # needs no attribution


class OtherRules(unittest.TestCase):
    COMPONENTS = [
        rpm("unsigned", "Package is not signed by any vendor key"),
        rpm("oddkey", "Signed by a key that is not a known vendor key"),
        rpm(
            "loose",
            "Package is not signed by any vendor key",
            "Installed from a loose RPM file instead of a vendor repository",
        ),
        rpm("signed"),
        rpm("debpkg", "Package is not signed by any vendor key", ecosystem="deb"),  # rules are about RPMs only
    ]

    def names(self, rule):
        r = check(model(components=self.COMPONENTS), rule)
        return sorted(i.split()[0] for i in r["items"]), r["passed"]

    def test_unsigned_rpm(self):
        self.assertEqual(self.names("unsigned-rpm"), (["loose", "unsigned"], False))

    def test_unknown_key(self):
        self.assertEqual(self.names("unknown-key"), (["oddkey"], False))

    def test_commandline_rpm(self):
        self.assertEqual(self.names("commandline-rpm"), (["loose"], False))

    def test_rpm_rules_pass_without_rpms(self):
        for rule in ("unsigned-rpm", "unknown-key", "commandline-rpm"):
            self.assertTrue(check(model(components=[rpm("signed")]), rule)["passed"], rule)

    def test_risky_step_counts_high_risks_only(self):
        layers = [
            layer(2, risks=[("high", "Downloads a script from the internet and runs it immediately")]),
            layer(3, risks=[("medium", "Files were made writable by every user (chmod 777)")]),
        ]
        r = check(model(layers=layers), "risky-step")
        self.assertEqual((r["passed"], r["count"]), (False, 1))
        self.assertTrue(r["items"][0].startswith("layer 2:"))
        self.assertTrue(check(model(layers=layers[1:]), "risky-step")["passed"])

    def test_outdated_base(self):
        note = "Outdated base image: built on reg/debian:12-old (released 2026-01-01)."
        r = check(model(notes=[note]), "outdated-base", catalog_matches=1)
        self.assertEqual((r["passed"], r["count"]), (False, 1))
        self.assertTrue(check(model(), "outdated-base", catalog_matches=1)["passed"])

    def test_outdated_base_fails_when_the_base_is_not_in_the_catalog(self):
        r = check(model(), "outdated-base", catalog_matches=0)
        self.assertFalse(r["passed"])
        self.assertIn("not in the catalog", r["missing"])

    def test_unattributed(self):
        layers = [layer(1, "base"), layer(2, "unknown")]
        r = check(model([vuln("CVE-U", "LOW", "unknown"), vuln("CVE-A", "LOW", "app")], layers=layers), "unattributed")
        self.assertEqual((r["passed"], r["count"]), (False, 2))
        self.assertEqual(r["items"], ["layer 2", "CVE-U p 1"])
        self.assertTrue(check(model([], layers=layers[:1]), "unattributed")["passed"])

    def test_items_are_capped_but_counts_are_not(self):
        layers = [layer(i, "unknown") for i in range(1, 51)]
        r = check(model(layers=layers), "unattributed")
        self.assertEqual((r["count"], len(r["items"])), (50, 20))


class ExitCodes(unittest.TestCase):
    """End to end against the test image: its application build runs `curl -k ... | sh` (risky-step)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.target, self.base = build_fixture(self.tmp)
        self._env = os.environ.get("WIMI_CATALOG")
        os.environ["WIMI_CATALOG"] = str(self.tmp / "catalog.json")
        self.out = self.tmp / "out"

    def tearDown(self):
        if self._env is None:
            os.environ.pop("WIMI_CATALOG", None)
        else:
            os.environ["WIMI_CATALOG"] = self._env
        self._tmp.cleanup()

    def run_wimi(self, *extra, image=None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        argv = [image or f"oci:{self.target}", "--base", f"oci:{self.base}", "-o", str(self.out), "-q"]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = cli.main([*argv, "--cache-dir", str(self.tmp / "cache"), *extra])
            except SystemExit as e:  # argparse
                rc = e.code
        return rc, out.getvalue(), err.getvalue()

    def report(self) -> dict:
        return json.loads(next(self.out.glob("*.json")).read_text())

    def html(self) -> str:
        return next(self.out.glob("*.html")).read_text()

    def trivy(self, severity: str, fixed: bool) -> str:
        diff_id = self.report()["layers"][1]["diff_id"]  # an application layer
        v = {"VulnerabilityID": "CVE-9", "PkgName": "curl", "InstalledVersion": "7.88.1-10", "Severity": severity}
        if fixed:
            v["FixedVersion"] = "7.88.1-11"
        v["Layer"] = {"DiffID": diff_id}
        p = self.tmp / "trivy.json"
        p.write_text(json.dumps({"Results": [{"Target": "debian", "Vulnerabilities": [v]}]}))
        return str(p)

    def test_0_without_fail_on_behaviour_is_unchanged(self):
        rc, _, _ = self.run_wimi()
        self.assertEqual(rc, 0)
        self.assertIsNone(self.report()["policy"])
        self.assertNotIn("Policy check", self.html())

    def test_0_when_every_rule_passes(self):
        rc, out, _ = self.run_wimi("--fail-on", "unsigned-rpm,unattributed")
        self.assertEqual(rc, 0)
        pol = self.report()["policy"]
        self.assertEqual((pol["passed"], pol["failed"]), (True, []))
        self.assertEqual([r["count"] for r in pol["rules"]], [0, 0])
        self.assertIn("Policy (--fail-on): passed", out)
        self.assertIn("Policy check passed", self.html())

    def test_1_when_a_rule_fails(self):
        rc, out, _ = self.run_wimi("--fail-on", "risky-step", "--fail-on", "unattributed")
        self.assertEqual(rc, 1)
        pol = self.report()["policy"]
        self.assertEqual(pol["failed"], ["risky-step"])
        risky = pol["rules"][0]
        self.assertEqual((risky["passed"], risky["count"]), (False, 2))
        self.assertIn("FAILED (1 of 2 rules)", out)
        self.assertIn("FAIL  risky-step", out)
        self.assertIn("pass  unattributed", out)
        self.assertIn("Policy check failed: risky-step (2 found)", self.html())
        self.assertTrue(list(self.out.glob("*.csv")))  # the report is still written

    def test_1_when_a_vulnerability_rule_has_no_scan_data(self):
        rc, out, _ = self.run_wimi("--fail-on", "app:critical")
        self.assertEqual(rc, 1)
        self.assertIn("no vulnerability data", self.report()["policy"]["rules"][0]["missing"])
        self.assertIn("not checked: no vulnerability data", out)

    def test_vulnerability_rules_with_scan_data(self):
        self.run_wimi()
        report = self.trivy("CRITICAL", fixed=False)
        self.assertEqual(self.run_wimi("--vuln-report", report, "--fail-on", "app:high")[0], 1)
        self.assertEqual(self.run_wimi("--vuln-report", report, "--fail-on", "app:high+fixable")[0], 0)
        self.assertEqual(self.run_wimi("--vuln-report", report, "--fail-on", "base:low")[0], 0)
        report = self.trivy("MEDIUM", fixed=True)
        self.assertEqual(self.run_wimi("--vuln-report", report, "--fail-on", "app:high+fixable")[0], 0)
        self.assertEqual(self.run_wimi("--vuln-report", report, "--fail-on", "any:medium+fixable")[0], 1)

    def test_2_for_a_bad_rule(self):
        rc, _, err = self.run_wimi("--fail-on", "app:hgh")
        self.assertEqual(rc, 2)
        self.assertIn("unknown rule 'app:hgh'", err)
        self.assertEqual(self.run_wimi("--fail-on")[0], 2)

    def test_2_when_the_image_cannot_be_loaded(self):
        rc, _, err = self.run_wimi("--fail-on", "risky-step", image=f"oci:{self.tmp / 'missing'}")
        self.assertEqual(rc, 2)
        self.assertIn("error:", err)

    def test_2_when_no_catalog_image_can_be_added(self):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = cli.main(["catalog", "add", f"oci:{self.tmp / 'missing'}", "--cache-dir", str(self.tmp / "cache")])
        self.assertEqual(rc, 2)

    def test_3_for_an_unexpected_error(self):
        with mock.patch.object(cli, "load_image", side_effect=PermissionError(13, "Permission denied", "app.tar")):
            rc, _, err = self.run_wimi("--fail-on", "risky-step")
            self.assertEqual(rc, 3)
            self.assertIn("error: unexpected PermissionError", err)
            self.assertNotIn("Traceback", err)
            self.assertIn("--debug", err)
            rc, _, err = self.run_wimi("--debug")
            self.assertEqual(rc, 3)
            self.assertIn("Traceback", err)


if __name__ == "__main__":
    unittest.main()
