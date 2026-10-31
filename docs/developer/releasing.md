# Releasing

## When to release

Versions follow [Semantic Versioning](https://semver.org/). A patch release (for example 0.3.1) holds only
backwards-compatible fixes. New options, and changes in behaviour such as different exit codes, wait for the next minor
release (0.4.0).

Cut a patch release, without waiting for the next milestone, for:

| Trigger                                                                                                       | How soon                                                |
|---------------------------------------------------------------------------------------------------------------|---------------------------------------------------------|
| A vulnerability in `wimi` itself (see the scope in [Security](security.md))                                   | As soon as it is fixed, with a GitHub security advisory |
| A newer base image build that fixes a critical vulnerability, or a high one in Python, OpenSSL or glibc       | Within a few days                                       |
| Wrong attribution: a component, layer or vulnerability credited to the wrong base image or to the application | Once one or two such fixes are merged                   |
| A crash, or a regression in a feature of the latest release                                                   | Once one or two such fixes are merged                   |

Changes to CI, tests or documentation alone don't need a release; the documentation site deploys from `main`.

Release tags are immutable, so a rebuilt image always means a new version. The **Base image check** workflow compares
the pinned base image with its registry's `latest` tag every Monday. When a newer build is out, it opens an issue
labelled `base-image` listing the fixable critical and high vulnerabilities the new build removes. Use the table above
to decide whether that issue needs a patch release or can wait for the next one.

Keep `main` releasable, and release fixes before merging the next minor release's features, so a patch never needs a
maintenance branch.

## Cutting a release

1. Update the version in `pyproject.toml` and `whats_in_my_image/__init__.py`, and add a section to `CHANGELOG.md`.
2. Refresh the `ARG BASE_IMAGE` digest in the `Dockerfile` if the Base image check has an open `base-image` issue,
   and close the issue.
3. Commit, then tag and push:

    ```bash
    git tag -a v0.3.1 -m "v0.3.1" && git push origin v0.3.1
    ```

The Release workflow then:

1. builds and tests the Python package, and checks the tag matches the package version,
2. builds the container image from that exact wheel (`--build-arg WHEEL=dist --build-context dist=dist/`) and blocks
   on fixable critical CVEs,
3. pushes the image to GHCR and signs it with cosign (keyless, Sigstore),
4. generates CycloneDX SBOMs and signed SLSA build provenance for the wheel, sdist and image,
5. runs `wimi` on its own image and attaches the provenance report,
6. creates the GitHub Release with every artifact, the signed provenance bundle and a `SHA256SUMS` file,
7. publishes the wheel and source distribution to PyPI with trusted publishing, in the `pypi` environment. It runs
   last because PyPI never lets a version be replaced. If only this job fails, re-run it; don't tag a new version.

!!! warning
    The Release workflow refuses to publish if the tag does not match the package version, or if the image has a
    critical vulnerability with a fix available.
