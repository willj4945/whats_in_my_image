---
name: release
description: Prepare a whats_in_my_image release (patch or minor) - decide whether one is due, bump the version everywhere, refresh the base image digest, move the CHANGELOG section, open the release PR, and hand the maintainer the tag commands. Use when asked to cut, prepare or plan a release, or when a base-image issue or security fix may need a patch release.
---

# Preparing a release

The policy is in `docs/developer/releasing.md` ("When to release"); the release workflow is
`.github/workflows/release.yml`. Release tags are **immutable**, so the maintainer pushes the tag, never Claude.

## 1. Decide the version

- **Patch (0.x.Y):** backwards-compatible fixes only: a vulnerability in `wimi`, a base image build that fixes a
  critical (or a high in Python, OpenSSL or glibc), wrong attribution, a crash or regression.
- **Minor (0.X.0):** anything that adds options or changes behaviour (new flags, exit codes, report fields).
- Nothing to release for CI-, test- or docs-only changes.
- Read `## [Unreleased]` in `CHANGELOG.md`: an `Added` entry or a behaviour change under `Changed` means minor.

## 2. Gather facts

```bash
git switch main && git pull
gh issue list --label base-image          # an open issue means a newer base build exists
grep -rn "$(python3 -c 'import tomllib;print(tomllib.load(open("pyproject.toml","rb"))["project"]["version"])')" \
  --include=*.md --include=*.toml --include=*.py --include=Dockerfile . | grep -v -E "CHANGELOG|ROADMAP|testbed/.state"
```

Latest base digest and its build (anonymous access works for the Red Hat registry):

```bash
curl -sI -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json' \
  https://registry.access.redhat.com/v2/ubi9/python-312-minimal/manifests/latest | grep -i docker-content-digest
```

Find the build's version and release labels from its config blob (`config.Labels.version` and `.release`, plus
`created`) so the CHANGELOG can name it, for example `9.8-1791925965 (2026-10-13)`.

## 3. Edit, on a `release/vX.Y.Z` branch

| File                                                                                                                                                                                    | Change                                                                                                                                                                                                                                                          |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `pyproject.toml`, `whats_in_my_image/__init__.py`                                                                                                                                       | `version` / `__version__`                                                                                                                                                                                                                                       |
| `README.md`, `docs/index.md`, `docs/getting-started/installation.md`, `docs/getting-started/verify.md`, `docs/ci/github-actions.md`, `docs/ci/gitlab.md`, `docs/developer/releasing.md` | Every old version string from the grep above                                                                                                                                                                                                                    |
| `Dockerfile`                                                                                                                                                                            | `ARG BASE_IMAGE=...@sha256:<new digest>` if there is a newer build                                                                                                                                                                                              |
| `CHANGELOG.md`                                                                                                                                                                          | New `## [X.Y.Z] - YYYY-MM-DD` under an empty `## [Unreleased]`, a one-sentence summary, a `### Security` entry for a base bump that fixes vulnerabilities, and the compare links at the bottom (`[Unreleased]` → `vX.Y.Z...HEAD`, new `[X.Y.Z]` → previous tag) |
| `ROADMAP.md`                                                                                                                                                                            | A line under `## Shipped`; tick shipped items                                                                                                                                                                                                                   |

Then confirm no old version string is left (re-run the grep).

## 4. Verify locally

```bash
.venv/bin/python -m unittest discover -s tests -q
.venv-docs/bin/mkdocs build --strict -d /tmp/wimi-site
docker build -q -t wimi-rc . && docker run --rm wimi-rc --version
trivy image --severity CRITICAL --ignore-unfixed --exit-code 1 wimi-rc     # the release gate
trivy image --severity CRITICAL,HIGH --ignore-unfixed wimi-rc              # for the PR description
docker rmi wimi-rc
```

## 5. PR, then hand over

Commit with `release: prepare vX.Y.Z` (and `Closes #N` for a `base-image` issue), and open the PR after the
maintainer agrees. Wait for all checks. Give the maintainer:

```bash
gh pr merge N --merge --admin
git switch main && git pull
git log -1 --oneline        # must be the merge of the release PR
git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
```

## 6. After the tag

```bash
gh run list --workflow release.yml --limit 1
gh release view vX.Y.Z --json assets --jq '.assets[].name'
docker run --rm ghcr.io/willj4945/whats_in_my_image:latest --version
gh api repos/willj4945/whats_in_my_image/attestations/sha256:<image digest> --jq '.attestations | length'
```

Expect the wheel, sdist, both CycloneDX SBOMs, the provenance HTML and JSON, and `SHA256SUMS`. `gh attestation
verify` needs GitHub CLI 2.49+; with an older `gh`, check attestations through the API as above.
