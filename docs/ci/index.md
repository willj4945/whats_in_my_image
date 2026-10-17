# CI/CD

Run `wimi` after your image is built and pushed, so every build gets a provenance report alongside its scan.
The published container image works on any runner that can run containers, and the wheel works anywhere Python 3.9+
is available.

<div class="grid cards" markdown>

-   :simple-gitlab:{ .lg .middle } **[GitLab CI](gitlab.md)**

    ---

    A job that uses the `wimi` image directly, with GitLab registry credentials.

-   :simple-githubactions:{ .lg .middle } **[GitHub Actions](github-actions.md)**

    ---

    A workflow job that scans an image in GHCR and uploads the report.

</div>

## Recommendations for any pipeline

* **Commit a shared base catalog** (for example `ci/base-catalog.json`) and pass it with `--catalog`, so every pipeline
  identifies bases the same way. See [Base image catalog](../guide/catalog.md).
* **Reuse your scanner's output.** If the pipeline already runs Trivy or Grype, save its JSON and pass it with
  `--vuln-report` instead of scanning twice.
* **Pin the `wimi` image** to a version tag or digest, and [verify it](../getting-started/verify.md) when you upgrade.
* **Keep the reports** as pipeline artifacts. The HTML file is self-contained, so it can be opened straight from the
  artifact browser or attached to a change ticket.
* Use a **read-only registry token** for `WIMI_USERNAME` / `WIMI_PASSWORD`. `wimi` only ever pulls.

## Failing the pipeline

By default `wimi` exits 0 whenever it writes the report. Add `--fail-on` to make it exit 1 when the report finds
something your policy doesn't allow. The report is written either way, so keep it as an artifact of failed jobs too.

```shell
wimi "$IMAGE" --vuln-report trivy.json --fail-on app:high+fixable,risky-step,unattributed
```

Rules are comma separated, or the flag can be repeated. A rule fails when it finds anything:

| Rule              | Fails when the image has                                                                                                |
|-------------------|-------------------------------------------------------------------------------------------------------------------------|
| `app:SEVERITY`    | a vulnerability of that severity or above introduced by the application build, e.g. `app:high` counts critical and high |
| `base:SEVERITY`   | the same, inherited from a base image                                                                                   |
| `any:SEVERITY`    | the same, wherever it came from (including findings that could not be attributed)                                       |
| `…+fixable`       | only counting vulnerabilities with a fix available, e.g. `app:high+fixable`, `any:critical+fixable`                     |
| `unsigned-rpm`    | OS packages not signed by any vendor key                                                                                |
| `unknown-key`     | OS packages signed by a key that is not a known vendor key                                                              |
| `commandline-rpm` | OS packages installed from a loose RPM file instead of a repository                                                     |
| `risky-step`      | build steps that pipe a downloaded script into a shell or turn off TLS or signature checks                              |
| `outdated-base`   | a base image with newer releases in the [catalog](../guide/catalog.md)                                                  |
| `unattributed`    | layers or vulnerabilities that could not be attributed to a base image or the application build                         |

`SEVERITY` is `critical`, `high`, `medium` or `low`. Findings the scanner rates `UNKNOWN` are not counted.

**A rule fails when the data it needs is missing**, so a gap never passes silently:

* a vulnerability rule with no vulnerability data, for example because `--scan` was skipped when no scanner was
  available. Pass `--vuln-report`, `--scan` or `--harbor-vulns`;
* an `app:` or `base:` rule when the base image could not be identified, because findings cannot be split by origin;
* `outdated-base` when the base image is not in the catalog, because newer releases are unknown.

The terminal summary lists every rule with its count, the JSON report records the result under
[`policy`](../reports/data-exports.md#json), and the HTML report's bottom line opens with it.
Exit codes are 0 (pass), 1 (policy failed), 2 (bad option or the image could not be loaded) and 3 (unexpected error).

!!! tip "Gate on what the team can act on"
    `app:high+fixable` blocks a merge on high and critical vulnerabilities that the application build introduced
    and that already have a fix, without failing on base-image findings nobody can fix yet. Add `unattributed` so a
    finding that couldn't be attributed fails rather than escaping the `app:` count, and keep `--catalog` or `--base`
    accurate: `app:` and `base:` rules are only as good as the attribution.
