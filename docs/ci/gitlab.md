# GitLab CI

The `wimi` image's entrypoint is `wimi`, so clear it to let GitLab run the job script.

```yaml title=".gitlab-ci.yml"
provenance:
  stage: test
  image:
    name: ghcr.io/willj4945/whats_in_my_image:0.3.0
    entrypoint: [""]
  variables:
    WIMI_USERNAME: $CI_REGISTRY_USER
    WIMI_PASSWORD: $CI_REGISTRY_PASSWORD
  script:
    - wimi "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA"
        --catalog ci/base-catalog.json
        --vuln-report trivy.json
        -o reports
  artifacts:
    when: always
    paths: [reports/]
```

* `CI_REGISTRY_USER` and `CI_REGISTRY_PASSWORD` are GitLab's job token credentials for the project's registry.
  For images in another registry (for example Iron Bank), set `WIMI_USERNAME` and `WIMI_PASSWORD` from masked
  CI/CD variables instead.
* `trivy.json` comes from an earlier job that scanned the same image (pass it with `needs:` or `dependencies:`).
  Drop `--vuln-report` if you don't scan.
* Commit the team's base catalog (`ci/base-catalog.json` here) so every pipeline identifies bases the same way.

!!! tip "Internal certificate authorities"
    If your registry uses an internal CA, commit or mount the bundle and add `--ca-cert path/to/bundle.pem`.
