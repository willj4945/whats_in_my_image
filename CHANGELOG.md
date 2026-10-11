# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- `SECURITY.md` links straight to private vulnerability reporting, and sets out a disclosure timeline and what is in
  and out of scope.
- The tools CI installs (Ruff, build, Bandit, zizmor) are hash-locked in `.github/requirements/` and kept current by
  Dependabot, so every tool a workflow downloads is verified by checksum.

## [0.3.0] - 2026-10-10

Runs Trivy and Grype as sidecar containers, fixes attribution for layers that only change permissions, adds a
documentation site, and makes the container image easy to run with the `wimi-docker` wrapper.

### Added

- Documentation site at https://willj4945.github.io/whats_in_my_image/, built with Material for MkDocs and published
  to GitHub Pages from `main`. The command line reference is generated from `wimi --help`.
- `--scan` runs Trivy or Grype from their container images when the binaries are not installed: if a container
  engine socket is reachable and the scanner image is present locally, the scanner runs as a sidecar container with
  no capabilities and `no-new-privileges`, and is removed afterwards. An installed binary is still used
  first, and a scanner with neither is skipped. The `wimi` image itself still contains no scanners.
- `WIMI_TRIVY_IMAGE` / `WIMI_GRYPE_IMAGE` name mirrored or retagged scanner images (exact tag, digest, or a repository
  whose newest local tag is used). Missing images are never pulled unless `WIMI_SCANNER_PULL=true`.
- `TRIVY_*` / `GRYPE_*` variables (and any named in `WIMI_SCANNER_ENV`) are passed to the sidecar, and the volume
  holding a path they name (for example the vulnerability database in `TRIVY_CACHE_DIR`) is mounted at the same path,
  so air-gapped database settings work the same for binaries and sidecars. Shared paths are read-only except the
  scanner's database directory (`TRIVY_CACHE_DIR` / `GRYPE_DB_CACHE_DIR`). `WIMI_VULNDB_MOUNT` overrides detection.
- `WIMI_SCANNER_MODE` (`auto`, `binary`, `container`, `off`), `WIMI_SCANNER_TIMEOUT`, `WIMI_SCANNER_MEMORY`,
  `WIMI_SCANNER_USER`. Sidecars run on the engine's default network.
- The report records how the scan ran (binary or container image and digest), the scanner version, and the date its
  vulnerability data was built, and warns in the bottom line when that data is more than 30 days old.
- CI job that runs a real Trivy sidecar against a mirrored image and a database volume.
- Local Docker testbed for development (`testbed/testbed.sh`): a local registry, images covering every supported
  ecosystem, demo application images that trigger findings, a base image catalog, and pinned scanners with their
  databases. `testbed/testbed.sh scan` runs the current checkout against every target.
- `contrib/wimi-docker`: runs the `wimi` container image like an installed command. It runs as your user in the
  current directory, shares your `docker login` credentials, catalog and caches (including scanner databases), shares
  the container engine socket for scanner sidecars when you can use it, and passes through `WIMI_*`, `TRIVY_*` and
  `GRYPE_*` settings.
- Documentation for scanner containers, the `wimi-docker` wrapper, and building the image yourself.

### Changed

- README is now a short landing page that links into the documentation site.
- The sample report moved from `docs/index.html` to `docs/sample-report.html`.
- `docker build .` now works from a clean checkout: the Dockerfile builds the wheel from source in a first stage, so
  no local `python -m build` is needed, and a leftover wheel in `dist/` can never end up in the image. The build
  backend is pinned by version and hash in `requirements-build.txt`. Build arguments `PIP_INDEX_URL` (and
  `PIP_EXTRA_INDEX_URL`, `PIP_TRUSTED_HOST`) point the build at a PyPI mirror on disconnected networks. The release
  workflow passes its signed wheel in with `--build-arg WHEEL=dist --build-context dist=dist/`, so released images
  contain exactly that wheel.
- The "Scanner sidecar (container engine)" CI job is a required check on `main`.
- `--formats` values are validated, so a typo such as `--formats htlm` is an error instead of writing nothing. A comma
  list (`--formats html,json`) or a repeated flag (`--formats html --formats json`) is accepted, case is ignored, and
  the flag can come before the image name.
- The container image is built on Red Hat UBI 9 Python 3.12 minimal `9.8-1791420498` (2026-10-08), the latest release.

### Fixed

- Grype scanner sidecars no longer fail when run as a non-root user (`WIMI_SCANNER_USER`): sidecars now write
  temporary files to the scan directory, which any user can write, instead of the image's `/tmp`.
- A layer that only changes permissions, ownership or timestamps (`chown -R`, `chmod -R`, `fix-permissions`, `COPY
  --chown` over existing files) no longer takes credit for files it didn't change. Every file's contents are now
  hashed, and a rewrite of the same bytes keeps the earlier layer, for loose programs and Python, npm, Java and Go
  components alike. Vendor packages re-owned this way are no longer flagged as "replaced after installation". The layer
  view reports these files separately (`files_metadata_only` in the JSON). (#10)

## [0.2.0] - 2026-10-02

Identifies base images automatically, explains why vulnerabilities have no fix, and adds a layer cake view.

### Added

- Vendor fix status for every vulnerability, read from the scanner (Trivy `Status`, Grype `fix.state`): fix
  available, no fix released yet, fix deferred, will not fix, no longer supported, under investigation. Shown as a
  chart, a filterable column and a CSV column. New findings for "will not fix", "end of life" and "deferred", and a
  bottom-line statement of how many vulnerabilities will never be removed by updating and need a risk decision.
- Base image catalog (`wimi catalog add | crawl | list | remove`): record the layer digests of the base images you
  use, then any scan identifies its base automatically and exactly, with no `--base` and no Dockerfile needed. The
  whole base chain is found even if `--base` names only part of it, so an unnamed base is never counted as the
  application team's work.
- "Outdated base image" finding when the catalog knows newer releases of the base an image was built on.
- Warning when the application layers look like they contain another, unidentified base image.
- "Layer cake" view in the HTML report: the image drawn as stacked slices, bottom-up in build order, coloured by
  who added each layer, sized by layer size, with the end of the base image marked. Each slice links to its build step.

### Changed

- README and help show the published container image and generic registry examples. Harbor is one optional integration,
  not a requirement.

## [0.1.0] - 2026-10-01

First public release.

### Added

- Trace every component of a container image to the base image or the build step that added it, using exact
  layer-digest matching against one or more base images (`--base`), with a timestamp-based estimate when no base is given.
- OS package attribution for RPM (sqlite and Berkeley DB), Debian/Ubuntu (including distroless) and Alpine/Wolfi,
  tracked layer by layer so upgrades are credited to the layer that made them.
- RPM supplier evidence: signing key ID, vendor, build host, and source repository from dnf history.
- Language packages: Python, npm, Java (including fat jars) and Go modules embedded in binaries.
- Detection of program files that no package manager installed, and of risky build steps such as `curl | sh`
  and disabled signature or TLS checks.
- Vulnerability attribution from Trivy, Grype or Harbor scan results (`--scan`, `--vuln-report`, `--harbor-vulns`).
- Executive HTML report with plain-English conclusions, plus JSON and CSV exports.
- Image sources: any OCI registry (Harbor, Iron Bank, Docker Hub, Red Hat, Quay ...), `docker save` archives,
  OCI layouts, and the local Docker or Podman engine.
- Standard library only, Python 3.9+.
- Licensed under the Apache License 2.0.
- Container image on GHCR, signed with cosign, with SLSA build provenance and CycloneDX SBOMs.

[Unreleased]: https://github.com/willj4945/whats_in_my_image/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/willj4945/whats_in_my_image/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/willj4945/whats_in_my_image/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/willj4945/whats_in_my_image/releases/tag/v0.1.0
