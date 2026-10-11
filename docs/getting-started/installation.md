# Installation

`wimi` uses **only the Python standard library**, so it has no dependencies to vet and works on air-gapped or
locked-down hosts.

=== "From a release (recommended)"

    Download the wheel from the [Releases](https://github.com/willj4945/whats_in_my_image/releases) page,
    [verify it](verify.md), then install it:

    ```bash
    pip install whats_in_my_image-0.3.0-py3-none-any.whl
    wimi --version
    ```

    This provides the `wimi` command.

=== "Container image"

    The image is published at
    [`ghcr.io/willj4945/whats_in_my_image`](https://github.com/willj4945/whats_in_my_image/pkgs/container/whats_in_my_image).
    It is built on Red Hat UBI 9, runs as a non-root user and is signed with cosign.

    ```bash
    mkdir -p reports
    docker run --rm -u "$(id -u):0" -v "$PWD/reports:/out" \
      ghcr.io/willj4945/whats_in_my_image:latest \
      registry.example.mil/team/app:1.2 -o /out
    ```

    The report lands in `./reports`. Pass registry credentials with `-e WIMI_USERNAME -e WIMI_PASSWORD`.

    **Run it like an installed command.** The `wimi-docker` wrapper adds the Docker options for you, so the container
    behaves like a local install:

    ```bash
    curl -fsSLo ~/.local/bin/wimi-docker \
      https://raw.githubusercontent.com/willj4945/whats_in_my_image/main/contrib/wimi-docker
    chmod +x ~/.local/bin/wimi-docker        # it's a short script: read it before you run it

    wimi-docker registry.example.mil/team/app:1.2 --scan
    ```

    See [The `wimi-docker` wrapper](#the-wimi-docker-wrapper) for what it sets up.

    !!! tip
        Pin a version tag (for example `:0.3.0`) or a digest rather than `:latest` in pipelines, so every run uses
        the release you verified.

=== "From source"

    ```bash
    git clone https://github.com/willj4945/whats_in_my_image.git
    cd whats_in_my_image
    pip install .                          # installs the `wimi` command
    python3 -m whats_in_my_image --help    # or run without installing
    ```

## The `wimi-docker` wrapper

[`contrib/wimi-docker`](https://github.com/willj4945/whats_in_my_image/blob/main/contrib/wimi-docker) runs the
container image with everything an installed `wimi` would have:

| It sets up                                                   | So that                                                                                                                                                                              |
|--------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Runs as your user and group                                  | Reports and other files it writes are owned by you.                                                                                                                                  |
| Mounts the current directory at the same path                | Reports go to `./wimi-reports/`, and relative paths (archives, `--vuln-report`, `--catalog`) just work.                                                                              |
| Mounts your `docker login` credentials, read-only            | Private registries work as they do for Docker. Credential helpers (such as Docker Desktop's) aren't available in the container, so use `WIMI_USERNAME` / `WIMI_PASSWORD` for those.  |
| Shares your catalog and layer cache with an installed `wimi` | `wimi-docker catalog add ...` persists, and repeat scans reuse downloaded layers.                                                                                                    |
| Shares the container engine socket, if there is one          | `--scan` can run Trivy or Grype as [sidecar containers](../guide/scanner-containers.md). The scanner databases are kept in your cache, so they aren't downloaded again on every run. |
| Passes through `WIMI_*`, `TRIVY_*` and `GRYPE_*` variables   | Settings such as `WIMI_SCANNER_PULL=true` work as they do for an installed `wimi`.                                                                                                   |

Set `WIMI_IMAGE` to run a different image (for example a pinned version, or one you built), and
`WIMI_DOCKER_SOCKET=0` to never share the engine socket.

!!! warning
    Sharing the engine socket gives the container root-equivalent access to the host. The wrapper only shares it if
    your own user can already use it.

## Building the container image yourself

From a checkout, no local Python build step is needed. The Dockerfile builds the wheel in a first stage, and the final
image holds only the base image and the installed wheel:

```bash
docker build -t wimi .                     # or: podman build -t wimi .
```

| Build argument                                                  | Use                                                                                                                                                                                                                                                                         |
|-----------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `PIP_INDEX_URL` (and `PIP_EXTRA_INDEX_URL`, `PIP_TRUSTED_HOST`) | Building from source downloads the build backend (setuptools) from a package index. On a disconnected network, point it at your mirror, for example `--build-arg PIP_INDEX_URL=https://nexus.example.mil/repository/pypi/simple`.                                           |
| `BASE_IMAGE`                                                    | Build on another base, for example an Iron Bank Python image. It needs Python 3.11 or newer with pip.                                                                                                                                                                       |
| `WHEEL=dist`                                                    | Install a prebuilt wheel instead of building from source: `docker build --build-arg WHEEL=dist --build-context dist=dist/ -t wimi .` Needs BuildKit/buildx or Podman 4+. The release workflow uses this, so the published image contains exactly the wheel that was signed. |

The image is always built from the checked-out source unless you pass `WHEEL=dist`. A leftover wheel in `dist/` is
never picked up by accident.

## Optional extras

| Extra                                            | When you need it                                                                                                                                                                                          |
|--------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `zstd` (`pip install "whats-in-my-image[zstd]"`) | Images with zstd-compressed layers, on Python older than 3.14. Python 3.14 reads zstd natively.                                                                                                           |
| Trivy or Grype                                   | To run a vulnerability scan with `--scan`: an installed binary, or the scanner's container image (see [Scanner containers](../guide/scanner-containers.md)). Not needed if you import an existing report. |

## Next steps

Head to the [Quick start](quickstart.md) to run your first scan.
