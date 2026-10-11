# Container image for wimi. `docker build -t wimi .` is all it takes: the first stage builds the wheel from the
# source in the build context, so the image always matches the checkout. dist/ is never part of the build context,
# so an old local build (which can share the version number with newer code) cannot end up in the image.
#
# The release workflow builds and signs the wheel first and hands it in through a separate, named build context:
#   docker build --build-arg WHEEL=dist --build-context dist=dist/ .
# so the published image contains exactly the wheel that was signed and attested.
#
# Base: Red Hat UBI 9 + Python 3.12 (minimal), pinned by digest so builds are reproducible.
# Dependabot does not update this pin; refresh it deliberately when cutting a release.
ARG BASE_IMAGE=registry.access.redhat.com/ubi9/python-312-minimal@sha256:f0f762a4babb280458627ab5cdaafbe86506aa60355c6fd4417074a5aa4727b8
# "source" (default): build the wheel from the checkout. "dist": use the prebuilt wheel from the `dist` build context.
ARG WHEEL=source

# ---- wheel built from source (default)
FROM ${BASE_IMAGE} AS wheel-source

# Building from source fetches the build backend (setuptools) from a package index, pinned by version and hash in
# requirements-build.txt. On a disconnected network, point it at your mirror:
#   docker build --build-arg PIP_INDEX_URL=https://nexus.example.mil/repository/pypi/simple .
ARG PIP_INDEX_URL
ARG PIP_EXTRA_INDEX_URL
ARG PIP_TRUSTED_HOST

USER 1001
WORKDIR /tmp/src
COPY --chown=1001:0 requirements-build.txt ./
RUN set -eu; \
    python3 -m venv /tmp/build-env; \
    /tmp/build-env/bin/python -m pip install --no-cache-dir --require-hashes --only-binary :all: \
        -r requirements-build.txt
COPY --chown=1001:0 . .
RUN set -eu; \
    mkdir -p /tmp/wheels; \
    /tmp/build-env/bin/python -m pip wheel --no-cache-dir --no-deps --no-build-isolation --wheel-dir /tmp/wheels .; \
    ls -l /tmp/wheels

# ---- placeholder for the `dist` build context. `--build-context dist=dist/` replaces this empty stage; without it,
# WHEEL=dist finds no wheel and says how to pass one, instead of trying to pull an image called "dist".
# Caveat: BuildKit can reuse the cached `COPY --from=dist` layer from an earlier WHEEL=dist build, so running
# WHEEL=dist without --build-context may silently reuse the old wheel instead of failing. Always pass the context
# (as the release workflow does on a fresh runner), or add --no-cache when switching between local wheel builds.
FROM scratch AS dist

# ---- prebuilt wheel from the `dist` build context (release workflow). Only built when WHEEL=dist.
FROM ${BASE_IMAGE} AS wheel-dist
USER 1001
WORKDIR /tmp/src
COPY --chown=1001:0 pyproject.toml ./
COPY --from=dist --chown=1001:0 . /tmp/dist/
RUN set -eu; \
    version="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"; \
    set -- /tmp/dist/whats_in_my_image-"${version}"-*.whl; \
    if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then \
        echo "WHEEL=dist: expected exactly one wheel for version ${version} in the dist build context;" \
             "pass it with: docker build --build-arg WHEEL=dist --build-context dist=dist/ ." >&2; \
        exit 1; \
    fi; \
    mkdir -p /tmp/wheels; \
    cp "$1" /tmp/wheels/; \
    ls -l /tmp/wheels

FROM wheel-${WHEEL} AS wheel

# ---- runtime image: the base plus the wheel, nothing else
FROM ${BASE_IMAGE}

ARG BASE_IMAGE
LABEL org.opencontainers.image.title="What's In My Image" \
      org.opencontainers.image.description="Trace every component of a container image to the base image or build step that put it there" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="${BASE_IMAGE}"

COPY LICENSE NOTICE /licenses/
COPY --from=wheel --chown=1001:0 /tmp/wheels/ /tmp/wheels/
RUN pip install --no-cache-dir --no-index /tmp/wheels/*.whl && rm -rf /tmp/wheels

USER 1001
ENV WIMI_CACHE=/tmp/wimi-cache
ENTRYPOINT ["wimi"]
CMD ["--help"]
