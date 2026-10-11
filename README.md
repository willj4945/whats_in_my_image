<!-- markdownlint-disable MD033 MD041 -->
<p align="center">
  <img src="docs/assets/logo.svg" alt="What's In My Image logo" width="120">
</p>

<h1 align="center">What's In My Image (<code>wimi</code>)</h1>

<p align="center">
  <b>Prove where every piece of a container image came from.</b>
</p>

<p align="center">
  <a href="https://github.com/willj4945/whats_in_my_image/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/willj4945/whats_in_my_image/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/willj4945/whats_in_my_image/actions/workflows/security.yml"><img alt="Security" src="https://github.com/willj4945/whats_in_my_image/actions/workflows/security.yml/badge.svg"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/willj4945/whats_in_my_image"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/willj4945/whats_in_my_image/badge"></a>
  <a href="https://github.com/willj4945/whats_in_my_image/releases"><img alt="Release" src="https://img.shields.io/github/v/release/willj4945/whats_in_my_image"></a>
  <img alt="Python 3.9+" src="https://img.shields.io/badge/python-3.9%2B-blue">
  <img alt="Dependencies: none" src="https://img.shields.io/badge/dependencies-none-brightgreen">
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue"></a>
</p>

<p align="center">
  <a href="https://willj4945.github.io/whats_in_my_image/"><b>Documentation</b></a> ·
  <a href="https://willj4945.github.io/whats_in_my_image/sample-report.html">Sample report</a> ·
  <a href="https://willj4945.github.io/whats_in_my_image/getting-started/quickstart/">Quick start</a> ·
  <a href="https://github.com/willj4945/whats_in_my_image/releases">Releases</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

When a scan finds a problem in an image, people often blame "the base image" (often Iron Bank) by default. `wimi`
replaces that assumption with evidence. It unpacks the image layer by layer and traces every OS package, library
and program file to the **base image or the build step that put it there**. It then writes a report that an
executive (CISO/CIO) can read in two minutes and an engineer can act on.

```text
==============================================================================
 registry.example.mil/payments/api:2.4
==============================================================================
 Iron Bank base: redhat/ubi/ubi9              layers 1-2       182 comps     41 vulns
 Application build (your team)                layers 3-9       406 comps    212 vulns
------------------------------------------------------------------------------
 * Iron Bank supplied 182 components (31%) and the application build added
   406 components (69%) of the 588 found in this image.
 ! Most critical/high-severity vulnerabilities (38 of 44) were introduced
   after the Iron Bank base, by the application build. ...
```

## Features

* **Evidence, not guesses.** Base layers are matched by SHA-256 digest, so "this came from the base image" is
  cryptographic proof. Packages are credited to the layer that installed their current version.
* **Finds the base for you.** A [base image catalog](https://willj4945.github.io/whats_in_my_image/guide/catalog/)
  recognises the whole base chain in any image, names the exact release, and flags outdated bases.
* **Who introduced each CVE.** Import a Trivy, Grype or Harbor scan, and every finding is credited to the party that
  can fix it, with the vendor's fix status.
* **Executive-ready report.** One self-contained HTML file to email or print, plus JSON and CSV.
* **No dependencies.** Python standard library only. Works on air-gapped hosts, with no Docker required.
* **Signed releases.** SLSA build provenance, CycloneDX SBOMs and a cosign-signed container image.

## Quick start

```bash
# Install the wheel from the Releases page (or use the container image below)
pip install whats_in_my_image-0.3.0-py3-none-any.whl

# Scan any image in any registry
wimi registry.example.mil/team/api:2.4

# Name the base yourself, and attribute vulnerabilities
wimi registry.example.mil/team/api:2.4 \
     --base "Iron Bank UBI 9=registry1.dso.mil/ironbank/redhat/ubi/ubi9:9.4" \
     --scan
```

Or run the signed container image, with no install:

```bash
mkdir -p reports
docker run --rm -u "$(id -u):0" -v "$PWD/reports:/out" \
  ghcr.io/willj4945/whats_in_my_image:latest \
  registry.example.mil/team/api:2.4 -o /out
```

Open `provenance-<image>.html` from `./wimi-reports/` (or `./reports/` for the container) in a browser.

## Documentation

The full documentation is at **[willj4945.github.io/whats_in_my_image](https://willj4945.github.io/whats_in_my_image/)**.

| | |
| --- | --- |
| [Getting started](https://willj4945.github.io/whats_in_my_image/getting-started/) | Installation, quick start and verifying a release |
| [User guide](https://willj4945.github.io/whats_in_my_image/guide/) | Image sources, naming the base image, the base image catalog, vulnerabilities, registry access |
| [Reports](https://willj4945.github.io/whats_in_my_image/reports/) | The HTML report section by section, and the JSON and CSV formats |
| [CI/CD](https://willj4945.github.io/whats_in_my_image/ci/) | GitLab CI and GitHub Actions examples |
| [Concepts](https://willj4945.github.io/whats_in_my_image/concepts/) | How attribution works, what is supported, limitations |
| [Reference](https://willj4945.github.io/whats_in_my_image/reference/) | Every command and option, environment variables |
| [Developer guide](https://willj4945.github.io/whats_in_my_image/developer/) | Development, branch protection, releases |

## Contributing

```bash
python3 -m unittest discover -s tests     # offline tests with synthetic images
ruff check . && ruff format --check .     # lint and formatting
```

See the [developer guide](https://willj4945.github.io/whats_in_my_image/developer/) for the project layout, the
documentation site and the release process, and the [roadmap](ROADMAP.md) for what's planned and where help is
welcome. To report a security problem, see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
