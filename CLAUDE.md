# CLAUDE.md

What's In My Image (`wimi`) traces every package, library and program in a container image to the base image or the
build step that added it, and writes an HTML/JSON/CSV report. Python, **standard library only**, Apache-2.0.

Start a session by reading `ROADMAP.md` and running `gh pr list` and `gh issue list`: the roadmap is the plan, and
items are ticked in the PR that completes them.

## Commands

```bash
python3 -m venv .venv && .venv/bin/pip install -e . \
  && .venv/bin/pip install --require-hashes -r .github/requirements/ruff.txt -r .github/requirements/bandit.txt
python3 -m venv .venv-docs && .venv-docs/bin/pip install --require-hashes -r docs/requirements.txt

.venv/bin/python -m unittest discover -s tests       # offline, ~10 s, synthetic images
.venv/bin/python -m unittest tests.test_wimi.EndToEnd # one class
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/bandit -q -c pyproject.toml -r whats_in_my_image
.venv-docs/bin/mkdocs build --strict -d /tmp/wimi-site # what CI runs; must exit 0
.venv/bin/wimi IMAGE                                  # or: python3 -m whats_in_my_image IMAGE
docker build -t wimi .                                # image from the checkout
testbed/testbed.sh scan [label]                       # real images; see docs/developer/testbed.md
```

## Code rules

- **No runtime dependencies.** Only the standard library in `whats_in_my_image/`. `pyproject.toml` has
  `dependencies = []`; the only extra is `zstd`. Tests use `unittest`, not pytest.
- **Python 3.9+.** Ruff targets `py39`; CI tests 3.9 to 3.14. Use `from __future__ import annotations`; no `match`,
  no 3.10+ only APIs without a fallback.
- Ruff rules `E F W B UP I`, line length **120**. Format with `ruff format`.
- Subprocess calls use a fixed argv with no shell, a comment saying why that is safe, and `# nosec B603`. Bandit runs
  in CI.
- **Attribution must be provable.** Base layers are matched by exact SHA-256 digest. Anything weaker (an estimated
  boundary, a partial match) is labelled as such in the report and must never be presented as proof. Policy rules
  fail when the data they need is missing, rather than passing.
- Tests build synthetic OCI images with `make_layer()` and `write_oci()` in `tests/test_wimi.py`. A bug fix gets a
  test that fails on `main`. Check real images too (testbed) when attribution changes.

## Layout

| Path                                                     | Contents                                                                                               |
|----------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `whats_in_my_image/cli.py`                               | Arguments, base resolution, output writing, exit codes, `--help` epilog                                |
| `whats_in_my_image/sources.py`, `registry.py`            | Registries, archives, OCI layouts, local engines                                                       |
| `whats_in_my_image/walker.py`                            | Layers in build order; hashes every file; captures package databases                                   |
| `whats_in_my_image/analyze.py`                           | Origins (`compute_origins`), component attribution, flags, findings                                    |
| `whats_in_my_image/parsers/`                             | RPM, dpkg/apk/language ecosystems (`ecosystems.py`), Go build info                                     |
| `whats_in_my_image/catalog.py`                           | Base image catalog (`wimi catalog ...`)                                                                |
| `whats_in_my_image/vulns.py`, `scanners.py`, `engine.py` | Scanner import, Trivy/Grype as binary or sidecar, Docker Engine API                                    |
| `whats_in_my_image/policy.py`                            | `--fail-on` rules                                                                                      |
| `whats_in_my_image/report.py`, `html_report.py`          | Report model (JSON) and the HTML renderer                                                              |
| `docs/`, `mkdocs.yml`, `docs/hooks.py`                   | Documentation site (Material for MkDocs); CLI page generated from `--help`                             |
| `testbed/`                                               | Local registry and real images for manual checks; state in `testbed/.state/` (git-ignored, several GB) |
| `contrib/`                                               | `wimi-docker` wrapper, `compose.yml`                                                                   |
| `.github/requirements/`                                  | Hash-locked tool versions CI installs (`*.in` → `pip-compile` → `*.txt`)                               |

## Keeping things in sync

A change is not done until these agree. The `docs-sync` skill has the full checklist.

- **CLI options or help text** → edit `cli.py` only; `docs/reference/cli.md` is generated. Also update the guide page
  that covers the option and `docs/reference/environment.md` for new environment variables.
- **Report fields** → `docs/reports/data-exports.md` (JSON fields, CSV columns) and `docs/reports/html-report.md`.
- **Supported formats or ecosystems** → `docs/concepts/supported.md` and `docs/concepts/limitations.md`.
- **Every user-visible change** → an entry under `## [Unreleased]` in `CHANGELOG.md` (Keep a Changelog headings:
  Added, Changed, Fixed, Security). Not needed for CI-, test- or docs-only changes.
- **Roadmap items** → tick them in `ROADMAP.md` in the same PR.
- **Version** lives in `pyproject.toml`, `whats_in_my_image/__init__.py` and the install/verify/CI examples in the
  docs. Only change it in a release PR (`release` skill).

## Style

- Markdown tables are **aligned**: padded cells and `|----|` separators, every row the same width. Contributors'
  editors enforce this; `python3 .claude/skills/docs-sync/align_tables.py FILE...` re-aligns.
- Prose is wrapped at about 120 characters, plain and specific. Docs use British spelling where it is already
  established ("catalogue" as a verb, "organisation"); keep the surrounding style.
- Commit subjects use the Conventional Commits prefixes already in the log: `fix:`, `feat:`, `docs:`, `ci:`,
  `docs(deps):`, `release:`. Close issues with `Closes #N` in the commit body or PR description.

## Workflow rules

- **Ask before anything outward-facing**: pushing, opening or merging PRs, commenting, filing issues, dismissing
  alerts, tagging. Commit only when asked.
- **Stage explicit paths.** Never `git add -A` or `git add .`. `testbed/.state/` holds gigabytes of images and
  databases; it is git-ignored, but an editor's "commit all" has pushed it before.
- **Never commit anything sensitive**: credentials, tokens, `.env` files, keys, registry auth files, or scan output.
  Reports (`wimi-reports/`, `testbed/.state/`) can contain build commands and image labels with secrets in them.
  Before every commit, read `git diff --cached` and check it for secrets. `.gitignore` covers the common file
  names, `.claude/settings.local.json` and `CLAUDE.local.md`; CI's Gitleaks job scans the full history.
- Branch from an up-to-date `main` (`fix/N-short-name`, `docs/...`, `ci/...`, `release/vX.Y.Z`).
- `main` is protected by `.github/rulesets/`: PRs only, 16 required checks on an **up-to-date** branch (this cannot
  be bypassed), one approval (admins may bypass with `gh pr merge N --merge --admin`). Release tags `v*` are
  immutable: never push a tag without explicit confirmation.
- Squash-merge contributor PRs whose history has duplicate or merge-noise commits.
- **Scanner findings stay visible.** No `.trivyignore` or similar suppressions. Decisions not to fix are recorded as
  dismissals with a written reason, by the maintainer.
- Check exit codes rather than filtering command output (`; echo "exit=$?"`).

## Gotchas

- `gh` 2.46 (Ubuntu's package): `gh pr checks --json` and `gh attestation` don't exist, and `gh pr edit` fails on
  Projects (classic). Use `gh api -X PATCH repos/willj4945/whats_in_my_image/pulls/N -f body=...` to edit a PR.
- A merge can silently move a `CHANGELOG.md` entry into an already-released section, when the branch was created
  before a release. After merging `main` into a branch, check every entry is still under `## [Unreleased]`.
- Dependabot sometimes closes a PR on `@dependabot rebase` and opens a replacement; review the new one.
- The base image is an `ARG BASE_IMAGE` default, which Dependabot can't update. The weekly *Base image check*
  workflow opens a `base-image` issue instead; `docs/developer/releasing.md` says when that warrants a patch release.
- `docs/sample-report.html` is a real report of `docker.io/library/python:3.12-slim-bookworm`; regenerate it when the
  HTML report changes visibly.

## References

- Roadmap and milestones: `ROADMAP.md`. Release policy and steps: `docs/developer/releasing.md`.
- Security policy and scope: `SECURITY.md`. Branch protection: `docs/developer/branch-protection.md`.
- Testbed: `docs/developer/testbed.md`. Docs site: <https://willj4945.github.io/whats_in_my_image/>
- Skills in `.claude/skills/`: `release`, `review-pr`, `docs-sync`.
