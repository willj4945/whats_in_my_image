"""``--fail-on``: turn the report into a pass/fail decision a pipeline can gate on.

A policy is a list of rules. Each rule counts something in the report model; any count above zero fails the rule.
When the data a rule needs is missing (no vulnerability scan, no attribution, no catalog entry for the base), the
rule fails rather than passing on an absence of evidence.
"""

from __future__ import annotations

import re

SEVERITIES = ("critical", "high", "medium", "low")
SCOPES = {"app": "introduced by the application build", "base": "inherited from a base image", "any": "anywhere"}
CHECKS = {
    "unsigned-rpm": "OS packages not signed by any vendor key",
    "unknown-key": "OS packages signed by a key that is not a known vendor key",
    "commandline-rpm": "OS packages installed from a loose RPM file instead of a repository",
    "risky-step": "build steps that run downloaded scripts or turn off TLS or signature checks",
    "outdated-base": "a base image with newer releases in the catalog",
    "unattributed": "layers or vulnerabilities that could not be attributed",
}
_VULN_RULE = re.compile(r"^(?P<scope>app|base|any):(?P<sev>critical|high|medium|low)(?P<fixable>\+fixable)?$")
_ITEMS = 20  # examples kept per rule

RULES_HELP = (
    "SCOPE:SEVERITY[+fixable] (SCOPE app, base or any; SEVERITY critical, high, medium or low, counting that "
    "severity and above), " + ", ".join(CHECKS)
)


def parse_rule(text: str) -> str:
    """Normalize one rule, or raise ValueError saying what is accepted."""
    rule = text.strip().lower()
    if rule in CHECKS or _VULN_RULE.match(rule):
        return rule
    if "fixable" in rule:
        raise ValueError(f"{text!r}: fixable is a modifier, e.g. app:high+fixable")
    raise ValueError(f"unknown rule {text!r}; rules are {RULES_HELP}")


def describe(rule: str) -> str:
    """'app:high+fixable' -> 'fixable high or critical vulnerabilities introduced by the application build'"""
    m = _VULN_RULE.match(rule)
    if not m:
        return CHECKS[rule]
    sevs = SEVERITIES[: SEVERITIES.index(m["sev"]) + 1]
    sev = sevs[0] if len(sevs) == 1 else f"{sevs[-1]} or higher"
    return f"{'fixable ' if m['fixable'] else ''}{sev} vulnerabilities {SCOPES[m['scope']]}"


def evaluate(model: dict, rules: list[str], *, scan_requested: bool = False, catalog_matches: int = 0) -> dict:
    """Evaluate ``rules`` against a report model.

    ``scan_requested``: --scan was given (used to explain missing vulnerability data).
    ``catalog_matches``: how many catalog entries matched this image's layers; 0 means outdated-base cannot be checked.
    """
    results = []
    for rule in dict.fromkeys(rules):  # de-duplicate, keep order
        m = _VULN_RULE.match(rule)
        if m:
            r = _vuln_rule(model, m["scope"], m["sev"], bool(m["fixable"]), scan_requested)
        else:
            r = _CHECK_FUNCS[rule](model, catalog_matches)
        count, items, missing = r
        results.append(
            {
                "rule": rule,
                "description": describe(rule),
                "passed": missing is None and count == 0,
                "count": count,
                "missing": missing,  # why the rule could not be checked, or None
                "items": items[:_ITEMS],
            }
        )
    failed = [r["rule"] for r in results if not r["passed"]]
    return {"passed": not failed, "failed": failed, "rules": results}


def summary(policy: dict) -> str:
    """One sentence for the report's bottom line."""
    rules = policy["rules"]
    if policy["passed"]:
        return f"Policy check passed: nothing matched the --fail-on rules ({', '.join(r['rule'] for r in rules)})."
    parts = [f"{r['rule']} ({reason(r)})" for r in rules if not r["passed"]]
    return f"Policy check failed: {'; '.join(parts)}. wimi exits with code 1."


def reason(r: dict) -> str:
    if r["missing"]:
        return f"not checked: {r['missing']}"
    return f"{r['count']:,} found"


# --------------------------------------------------------------------------- rules


def _attributed(model: dict) -> bool:
    return any(o["kind"] in ("base", "app") for o in model["origins"])


def _vuln_rule(model, scope, sev, fixable, scan_requested):
    vulns = model.get("vulns")
    if vulns is None:
        why = (
            "--scan did not produce vulnerability data (see the warnings above)"
            if scan_requested
            else "no vulnerability data; add --scan, --vuln-report or --harbor-vulns"
        )
        return 0, [], why
    if scope != "any" and not _attributed(model):
        return 0, [], "the base image could not be identified, so vulnerabilities could not be attributed"
    keys = {o["key"] for o in model["origins"] if o["kind"] == scope} if scope != "any" else None
    wanted = {s.upper() for s in SEVERITIES[: SEVERITIES.index(sev) + 1]}
    hits = [
        v
        for v in vulns
        if v["severity"] in wanted
        and (keys is None or v["origin"] in keys)
        and (not fixable or v["fix_status"] == "fixed")
    ]
    order = {s.upper(): i for i, s in enumerate(SEVERITIES)}
    hits.sort(key=lambda v: (order.get(v["severity"], 9), v["id"]))
    return len(hits), [f"{v['id']} {v['severity'].title()} {v['package']} {v['version']}" for v in hits], None


def _flagged(model, test):
    hits = [c for c in model["components"] if c["ecosystem"] == "rpm" and any(test(f["message"]) for f in c["flags"])]
    return len(hits), [f"{c['name']} {c['version']} (layer {c['layer'] + 1})" for c in hits], None


def _unsigned(model, _):
    return _flagged(model, lambda m: m.startswith("Package is not signed by any vendor key"))


def _unknown_key(model, _):
    return _flagged(model, lambda m: m.startswith("Signed by a key that is not a known vendor key"))


def _commandline(model, _):
    return _flagged(model, lambda m: m.startswith("Installed from a loose RPM file"))


def _risky_step(model, _):
    hits = [(lyr, r) for lyr in model["layers"] for r in lyr["risks"] if r["severity"] == "high"]
    return len(hits), [f"layer {lyr['number']}: {r['message']}" for lyr, r in hits], None


def _outdated_base(model, catalog_matches):
    if not catalog_matches:
        return 0, [], "the base image is not in the catalog, so newer releases cannot be checked"
    hits = [n for n in model["notes"] if n.startswith("Outdated base")]
    return len(hits), hits, None


def _unattributed(model, _):
    layers = [lyr for lyr in model["layers"] if lyr["origin_kind"] == "unknown"]
    vulns = [v for v in model.get("vulns") or [] if v["origin"] == "unknown"]
    items = [f"layer {lyr['number']}" for lyr in layers] + [f"{v['id']} {v['package']} {v['version']}" for v in vulns]
    return len(layers) + len(vulns), items, None


_CHECK_FUNCS = {
    "unsigned-rpm": _unsigned,
    "unknown-key": _unknown_key,
    "commandline-rpm": _commandline,
    "risky-step": _risky_step,
    "outdated-base": _outdated_base,
    "unattributed": _unattributed,
}
