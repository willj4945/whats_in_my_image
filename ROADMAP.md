# Roadmap

Where What's In My Image (`wimi`) is heading: from a working tool to an open-source project that developers and
DevSecOps teams can install in one line, trust the answers of, and wire into their pipelines.

This is a living plan. Items link to issues where one exists. Tick items off in the same PR that completes them, and
open an issue before starting anything larger than a day's work. The order within each milestone is the suggested
order of work.

Last reviewed: 2026-10-10.

## Principles

- **Correct before broad.** A provenance tool that blames the wrong team does more harm than none. Attribution bugs
  come before new features.
- **Evidence, not assertion.** Every claim in a report, and every claim this project makes about its own security,
  should be checkable.
- **No dependencies at runtime.** The tool stays standard-library only, so it installs on air-gapped hosts.
- **Findings stay visible.** No scanner suppressions (`.trivyignore` and the like) until there is a recorded triage
  process ([VEX](#v060-interoperable-and-hardened)). Decisions not to fix are recorded, never hidden.

## Shipped

- **v0.3.0** (2026-10-10): scanner sidecars, the documentation site, the `wimi-docker` wrapper, the local testbed,
  attribution fix for layers that only change permissions ([#10](https://github.com/willj4945/whats_in_my_image/issues/10)),
  and validated `--formats` ([#14](https://github.com/willj4945/whats_in_my_image/pull/14)). See the
  [changelog](https://github.com/willj4945/whats_in_my_image/blob/main/CHANGELOG.md).

## Now: project basics

Small, mostly administrative items that make the project approachable. No release needed.

- [ ] Repository description and topics (`container-security`, `sbom`, `supply-chain`, `devsecops`, `provenance`,
      `iron-bank`, ...).
- [ ] Enable Dependabot security updates. Alerts are already on.
- [ ] Automatically delete branches after merge.
- [ ] Enable Discussions for questions that aren't bugs or feature requests.
- [ ] `CONTRIBUTING.md`: setup, the testbed, the checks CI runs, branch and PR conventions, resolving `CHANGELOG.md`
      conflicts.
- [ ] Code of Conduct (Contributor Covenant).
- [ ] Issue forms (bug report, feature request) and a pull request template.
- [ ] `CODEOWNERS`.
- [ ] Give a second maintainer the `triage` or `write` role, so reviews count toward the required approval instead of
      admins bypassing it. This also fixes the Scorecard Code-Review check.
- [ ] Label approachable issues `good first issue` ([#17](https://github.com/willj4945/whats_in_my_image/issues/17) and [#18](https://github.com/willj4945/whats_in_my_image/issues/18) are good candidates).
- [ ] Expand `SECURITY.md`: scope, what counts as a vulnerability in a tool that reads untrusted images, and the
      disclosure timeline. (Scorecard Security-Policy currently scores 4/10.)

## v0.4.0: correct and installable

Fix the attribution bugs, and make `pipx install whats-in-my-image` work.

**Correctness**

- [x] [#10](https://github.com/willj4945/whats_in_my_image/issues/10) Layers that only change permissions or ownership take over attribution of unchanged files (`priority: high`)
- [ ] [#11](https://github.com/willj4945/whats_in_my_image/issues/11) Vulnerability attribution: ties, ignored package type, loose version match
- [ ] [#15](https://github.com/willj4945/whats_in_my_image/issues/15) Distroless images: `status.d` file lists aren't read, so every file is reported as unowned
- [ ] [#16](https://github.com/willj4945/whats_in_my_image/issues/16) A partial catalog match is shown under the wrong base image's name
- [ ] [#17](https://github.com/willj4945/whats_in_my_image/issues/17) The scanner sidecar says the engine is "not responding" when the socket is permission denied
- [ ] [#18](https://github.com/willj4945/whats_in_my_image/issues/18) An unreadable input file crashes with a traceback instead of a clean error

**Distribution**

- [ ] Publish to PyPI from the release workflow with trusted publishing and attestations. Reserve the `wimi` name too.
- [ ] `pyproject.toml`: project URLs (docs, source, issues, changelog), classifiers and keywords.
- [ ] Update the install docs and README for PyPI and `pipx`.
- [ ] [#7](https://github.com/willj4945/whats_in_my_image/pull/7) Docker Compose example for Docker Desktop on Windows and macOS (in review)

**Supply chain**

- [ ] Attach the signed provenance bundle to each GitHub release, so the Scorecard Signed-Releases check can find it.
      (Releases are already attested, but the bundle isn't a release file.)
- [ ] Pin the remaining tool installs in workflows by hash, not just by version (Scorecard Pinned-Dependencies 6/10).

## v0.5.0: pipeline-ready

Make `wimi` a gate in CI, not only a report.

- [ ] [#12](https://github.com/willj4945/whats_in_my_image/issues/12) `--fail-on` policy with documented exit codes: 0 pass, 1 policy failed, 2 usage or load error, 3 unexpected
      error. Fail closed when a rule needs data that's missing (for example, no scan ran).
- [x] [#14](https://github.com/willj4945/whats_in_my_image/pull/14) Validate `--formats` without breaking the comma-list syntax (in review)
- [ ] SARIF output, so findings appear in GitHub code scanning and GitLab's security dashboard.
- [ ] A versioned JSON schema for the report, published with the docs, so automation can depend on it.
- [ ] A GitHub Action (`uses: willj4945/whats_in_my_image@v1`) and a GitLab CI/CD component.
- [ ] Known-answer regression tests: expected attribution for a set of reference images, run nightly from the
      testbed, so attribution changes are always deliberate.

## v0.6.0: interoperable and hardened

- [ ] CycloneDX SBOM output, with provenance (origin, layer, evidence) as component properties.
- [ ] Read VEX documents (OpenVEX, CycloneDX VEX) to record "not affected" and "will not fix" decisions. This is the
      triage process that findings stay visible until.
- [ ] Fuzz the parsers that read untrusted input (tar, RPM databases, ELF, jar/zip, Go build info) with
      ClusterFuzzLite and Atheris.
- [ ] Threat model in the docs: what `wimi` trusts, what it defends against (decompression bombs, path tricks,
      oversized members), and what sharing the container engine socket gives away.
- [ ] OpenSSF Best Practices badge.
- [ ] More package ecosystems: Rust, .NET and Ruby (currently listed as limitations).

## Before 1.0: stability promises

- [ ] Define the public API: CLI options, exit codes and the JSON schema. Document SemVer and a deprecation policy (an
      option is kept, with a warning, for at least one minor release before removal).
- [ ] Changelog fragments (one file per PR, assembled at release, e.g. towncrier), so entries can't be lost when a
      merge conflict in `CHANGELOG.md` is resolved by hand.
- [ ] A maintainers list and a short governance note (how decisions are made, how to become a maintainer).
- [ ] Release cadence written down.

## Later: outreach

After v0.3.0 and v0.4.0, so first impressions land on a tool that installs in one line and gives correct answers:

- [ ] Launch post and a walkthrough using the sample report.
- [ ] An honest comparison page: what `wimi` does that general SBOM and vulnerability scanners don't (layer-by-layer
      attribution to the base image or the build step), and what it doesn't try to do.
