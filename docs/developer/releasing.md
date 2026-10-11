# Cutting a release

1. Update the version in `pyproject.toml` and `whats_in_my_image/__init__.py`, and add a section to `CHANGELOG.md`.
2. Optionally refresh the base image digest in the `Dockerfile`.
3. Commit, then tag and push:

    ```bash
    git tag -a v0.3.0 -m "v0.3.0" && git push origin v0.3.0
    ```

The Release workflow then:

1. builds and tests the Python package, and checks the tag matches the package version,
2. builds the container image from that exact wheel (`--build-arg WHEEL=dist --build-context dist=dist/`) and blocks
   on fixable critical CVEs,
3. pushes the image to GHCR and signs it with cosign (keyless, Sigstore),
4. generates CycloneDX SBOMs and signed SLSA build provenance for the wheel, sdist and image,
5. runs `wimi` on its own image and attaches the provenance report,
6. creates the GitHub Release with every artifact and a `SHA256SUMS` file.

!!! warning
    The Release workflow refuses to publish if the tag does not match the package version, or if the image has a
    critical vulnerability with a fix available.
