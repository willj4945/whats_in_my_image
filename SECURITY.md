# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's private vulnerability reporting:
<https://github.com/willj4945/whats_in_my_image/security/advisories/new>. Do not open a public issue for a security
problem.

Include what you found, how to reproduce it, and the version (`wimi --version`). A sample image or file that triggers
the problem helps most.

## What happens next

| Step                                          | Target                       |
|-----------------------------------------------|------------------------------|
| Acknowledgement of your report                | Within 5 working days        |
| Assessment (confirmed or not, and how severe) | Within 14 days               |
| Fix released for a confirmed issue            | Within 90 days of the report |
| Public advisory                               | When the fix is released     |

We coordinate disclosure with you: the advisory is published as a GitHub security advisory with a CVE where one
applies, and credits you unless you ask us not to. If a fix will take longer than 90 days, we agree a date with you
rather than disclosing early or late.

## Scope

`wimi` reads untrusted input: container images, image archives, package databases and scanner reports. In scope:

- A crafted image, archive or report that makes `wimi` write outside its output directory, run code, read files it
  was not asked to read, or exhaust memory or disk out of proportion to the input.
- Script injection in the HTML report from values taken from an image or a scan.
- Credentials (registry tokens, `~/.docker/config.json`) leaking into reports, logs or error messages.
- Scanner sidecars started with more access than documented (capabilities, writable mounts, privilege escalation).
- Problems with the release itself: signatures, provenance or SBOMs that don't match the published artifacts.

Out of scope:

- Vulnerabilities in the images you analyse. Reporting those is what `wimi` is for.
- Vulnerabilities in the base image of the `wimi` container that have no fix available. These are tracked in each
  release's own `wimi` report.
- Wrong attribution (a component credited to the wrong layer) with no security impact. Please open a normal issue.
- Problems that need an attacker who can already change your container engine, registry credentials or the `wimi`
  installation.

## Supported versions

Security fixes go into the latest release only.

## How this project is checked

Every push and pull request runs:

| Check | Tool |
| --- | --- |
| Static analysis (SAST) | CodeQL (`security-extended`), Bandit |
| Vulnerable dependencies, secrets, misconfiguration | Trivy, GitHub dependency review |
| Secrets in the full git history | Gitleaks |
| Workflow security (injection, permissions, unpinned actions) | zizmor, actionlint, CodeQL for Actions |
| Supply-chain practices | OpenSSF Scorecard |

Every third-party action is pinned to a full commit SHA, and every downloaded tool is verified against its published
SHA-256 checksum. Workflows run with read-only permissions by default. The tool itself has no third-party runtime
dependencies.
