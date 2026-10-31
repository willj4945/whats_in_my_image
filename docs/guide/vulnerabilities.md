# Vulnerabilities

`wimi` doesn't scan for vulnerabilities itself. It takes findings from your scanner and matches each one to the traced
component, so every CVE is credited to the party that introduced it, and that can fix it.

## Getting findings in

=== "Run a scanner"

    ```bash
    wimi IMAGE --scan            # Trivy or Grype: the installed binary, or its container image
    wimi IMAGE --scan trivy      # or choose one
    ```

    No scanner installed? If a container engine is reachable and the scanner's image is present, `wimi` runs it as a
    sidecar container. See [Scanner containers](scanner-containers.md).

=== "Import a report"

    ```bash
    trivy image --format json -o trivy.json IMAGE
    wimi IMAGE --vuln-report trivy.json
    ```

    Trivy, Grype and Harbor JSON reports are accepted. Repeat `--vuln-report` to combine several.
    Use this in pipelines that already run a scanner.

=== "Reuse Harbor's scan"

    ```bash
    wimi harbor.example.com/project/app:1.2 --harbor-vulns
    ```

    Downloads the scan a Harbor registry already ran for this image. Harbor users only.

## What you get

* **Where the data came from:** the scanner and version, whether it ran as a binary or from which container image,
  and the date its vulnerability data was built. Data more than 30 days old is called out in the bottom line.
* **Who introduced it:** the base image or the application build. Each finding is matched to the traced component it
  affects, from the strongest evidence to the weakest (see [How a finding is matched](#how-a-finding-is-matched)). If
  no component matches, the layer reported by the scanner is used instead, and if there is none the finding is shown
  as *Unattributed* rather than guessed. The report states which method was used for every finding.
* **Severity**, with critical and high findings summarised in the bottom line.
* **Vendor fix status**, read from the scanner (Trivy `Status`, Grype `fix.state`):

| Fix status          | Meaning                                     |
|---------------------|---------------------------------------------|
| Fix available       | Updating the package removes the finding.   |
| No fix released yet | The vendor has not shipped a fix.           |
| Fix deferred        | The vendor plans to fix it later.           |
| Will not fix        | The vendor will not fix it in this release. |
| No longer supported | The package or release is end of life.      |
| Under investigation | The vendor has not decided yet.             |

"Will not fix", "end of life" and "deferred" findings are raised as their own findings, and the bottom line states
how many vulnerabilities will never be removed by updating and need a risk decision.

## How a finding is matched

The `match` value in the JSON, the vulnerabilities CSV and the HTML table says how each finding was tied to a component:

| `match`                  | Meaning                                                                                                                  |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `purl`                   | The scanner's package URL is the component's. Trivy and Grype report one; Harbor doesn't.                                |
| `name+ecosystem+version` | Same name, package type and exact version. A package of the same name from another ecosystem is never matched.           |
| `name+version`           | Same name and exact version, when the scanner gives no package type.                                                     |
| `prefix`                 | Same name, and one version is a shortened form of the other (`1.2` and `1.2.3`, not `1.24.0`). Weaker: check it by hand. |
| `layer`                  | No component matched, so the layer the scanner reported is used. A shortened version never overrides that layer.         |
| `none`                   | Nothing to go on. The finding is shown as *Unattributed*.                                                                |

The same package can be installed in more than one layer, for example in a system Python and a virtual environment.
`wimi` then picks the copy in the layer the scanner reported, then the one at the scanner's file path. If nothing
separates copies in different layers, the attribution says *matched to one of N copies in different layers*, because
the origin shown is then a choice between them, not proof.
