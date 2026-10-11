# GitHub Actions

This job scans an image in GitHub Container Registry with the published `wimi` image, then uploads the reports as a
workflow artifact.

```yaml title=".github/workflows/provenance.yml"
name: Provenance

on:
  workflow_dispatch:
  push:
    branches: [main]

permissions:
  contents: read
  packages: read # pull the image from GHCR

jobs:
  provenance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7 # pin to a full commit SHA in production
        with:
          persist-credentials: false

      - name: Trace image provenance
        env:
          IMAGE: ghcr.io/your-org/your-app:${{ github.sha }}
          WIMI_USERNAME: ${{ github.actor }}
          WIMI_PASSWORD: ${{ secrets.GITHUB_TOKEN }}
        run: |
          mkdir -p reports
          docker run --rm -u "$(id -u):0" -v "$PWD:/work" -w /work \
            -e WIMI_USERNAME -e WIMI_PASSWORD \
            ghcr.io/willj4945/whats_in_my_image:0.2.0 \
            "$IMAGE" --catalog ci/base-catalog.json -o reports \
            --fail-on risky-step,unattributed

      - uses: actions/upload-artifact@v7 # pin to a full commit SHA in production
        if: always()
        with:
          name: provenance-report
          path: reports/
```

* `GITHUB_TOKEN` with `packages: read` can pull images from the same organisation. For other registries, store a
  read-only token as a repository secret and use that.
* The image runs as your runner's user ID (`-u "$(id -u):0"`), so the reports it writes into the workspace are
  owned by the runner.
* `--fail-on` fails the step (exit 1) when a build step runs a downloaded script or turns off TLS or signature
  checks, or when something could not be attributed. `if: always()` still uploads the report of a failed run.
  See [Failing the pipeline](index.md#failing-the-pipeline) for the other rules.
* To attribute vulnerabilities, scan the image with Trivy or Grype earlier in the job, write JSON into the workspace,
  and add `--vuln-report trivy.json`. Then you can gate on them too, for example `--fail-on app:high+fixable`.

!!! tip "Pinning"
    Pin both the actions and the `wimi` image to full digests in production, and let Dependabot keep the action pins
    current.
