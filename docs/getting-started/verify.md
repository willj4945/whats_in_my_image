# Verifying a release

Every release is built by GitHub Actions and ships with:

* signed **build provenance** (SLSA) for the wheel, the source distribution and the container image,
* **CycloneDX SBOMs** for the wheel and the image,
* a **cosign signature** on the image (keyless, Sigstore),
* the wheel and source distribution's signed provenance as a release file, `wimi-<version>.intoto.jsonl`,
* a `SHA256SUMS` file,
* a `wimi` provenance report of the release's own container image.

The exact commands, filled in for that release, are in each release's notes. In general:

```bash
gh attestation verify whats_in_my_image-0.4.0-py3-none-any.whl --repo willj4945/whats_in_my_image
gh attestation verify oci://ghcr.io/willj4945/whats_in_my_image:0.4.0 --repo willj4945/whats_in_my_image
sha256sum --check SHA256SUMS
```

To verify without asking GitHub for the attestation, for example on an air-gapped host, pass the bundle from the
release: add `--bundle wimi-0.4.0.intoto.jsonl` to the first command.

The packages on PyPI are the same files, built by the same workflow through trusted publishing, so the wheel you
download from PyPI verifies with the same command. PyPI also shows its own attestation for each file.

`gh attestation` needs GitHub CLI 2.49 or newer. Some Linux distributions package an older one; check with
`gh --version`.

!!! info "Release gate"
    The release workflow refuses to publish if the image has a critical vulnerability with a fix available, or if
    the tag does not match the package version.
