---
title: Home
hide:
  - navigation
  - toc
---

<div class="wimi-hero" markdown>

![What's In My Image logo](assets/logo.svg)

# What's In My Image

**Prove where every piece of a container image came from.**

`wimi` traces every OS package, library and program file in a container image to the **base image or the build step
that put it there**, then writes a report a CISO can read in two minutes and an engineer can act on.

[Get started](getting-started/index.md){ .md-button .md-button--primary }
[See a sample report](sample-report.html){ .md-button }

</div>

When a scan finds a problem in an image, people often blame "the base image" (often Iron Bank) by default. `wimi`
replaces that assumption with evidence: layer digests, package databases, signing keys and build history.

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

<div class="grid cards" markdown>

-   :material-fingerprint:{ .lg .middle } **Evidence, not guesses**

    ---

    Base layers are matched by SHA-256 digest, so "this came from the base image" is cryptographic proof.

    [:octicons-arrow-right-24: How attribution works](concepts/how-it-works.md)

-   :material-layers-search:{ .lg .middle } **Finds the base for you**

    ---

    Catalogue the base images your organisation uses once, and `wimi` recognises the whole base chain in any image.

    [:octicons-arrow-right-24: Base image catalog](guide/catalog.md)

-   :material-shield-bug:{ .lg .middle } **Who introduced each CVE**

    ---

    Import a Trivy, Grype or Harbor scan, and every finding is credited to the party that can fix it.

    [:octicons-arrow-right-24: Vulnerabilities](guide/vulnerabilities.md)

-   :material-file-chart:{ .lg .middle } **Executive-ready report**

    ---

    One self-contained HTML file to email or print, plus JSON and CSV for dashboards and spreadsheets.

    [:octicons-arrow-right-24: Reports](reports/index.md)

-   :material-package-variant-closed-check:{ .lg .middle } **No dependencies**

    ---

    Python standard library only. Works on air-gapped and locked-down hosts, with no Docker required.

    [:octicons-arrow-right-24: Installation](getting-started/installation.md)

-   :material-source-branch-check:{ .lg .middle } **Built for pipelines**

    ---

    Runs from a signed container image in GitLab CI, GitHub Actions or any other runner.

    [:octicons-arrow-right-24: CI/CD](ci/index.md)

</div>

## Try it

=== "pip"

    ```bash
    pip install whats_in_my_image-0.3.0-py3-none-any.whl   # from the Releases page
    wimi registry.example.mil/team/api:2.4 --scan
    ```

=== "Container"

    ```bash
    mkdir -p reports
    docker run --rm -u "$(id -u):0" -v "$PWD/reports:/out" \
      ghcr.io/willj4945/whats_in_my_image:latest \
      registry.example.mil/team/api:2.4 -o /out
    ```

=== "From source"

    ```bash
    git clone https://github.com/willj4945/whats_in_my_image.git
    cd whats_in_my_image
    python3 -m whats_in_my_image registry.example.mil/team/api:2.4
    ```

Open the `provenance-*.html` file in `./wimi-reports/` (or `./reports/` for the container). The
[Quick start](getting-started/quickstart.md) walks through a first scan.
