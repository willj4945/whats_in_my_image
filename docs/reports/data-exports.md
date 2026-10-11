# JSON and CSV

## JSON

`provenance-<image>.json` holds everything the HTML report is built from. The main top-level fields are:

| Field               | Contents                                                                                                                                                                                                                              |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `image`             | Reference, digests, platform, size, OS, labels and creation time of the image.                                                                                                                                                        |
| `origins`           | Each origin (base images and the application build), with its layers and the evidence for it.                                                                                                                                         |
| `layers`            | Every layer with its origin, size, build command and what it added.                                                                                                                                                                   |
| `components`        | Every traced component: name, version, type, supplier, layer, evidence, concerns, licence and purl.                                                                                                                                   |
| `vulns`             | Every finding with severity, fix status and attribution, or `null` if no vulnerability data was supplied.                                                                                                                             |
| `vuln_scan`         | When `wimi` ran the scanner: the tool and version, `mode` (`binary` or `container`), the container image and digest, and the vulnerability data's build date (`db_date`) and age in days (`db_age_days`). Empty for imported reports. |
| `findings`          | The findings that need attention, each with its severity and the origin responsible for it.                                                                                                                                           |
| `notes`             | Plain-English notes about the attribution, such as partial base matches or an outdated base.                                                                                                                                          |
| `policy`            | The `--fail-on` result, or `null` without `--fail-on`: `passed`, the `failed` rule names, and for each rule its `count`, a few example `items`, and `missing` (why the rule could not be checked, for example no vulnerability data). |
| `policy`            | The `--fail-on` result, or `null` without `--fail-on`: `passed`, the `failed` rule names, and for each rule its `count`, a few example `items`, and `missing` (why the rule could not be checked, for example no vulnerability data). |
| `removed_packages`  | Packages that an earlier layer installed and a later layer removed.                                                                                                                                                                   |
| `tool`, `generated` | The `wimi` version that wrote the report, and when.                                                                                                                                                                                   |

!!! note
    The JSON layout follows the report and may gain fields between releases. Read fields by name, and ignore ones
    you don't recognise.

## Components CSV

`provenance-<image>-components.csv`, one row per component:

| Column                       | Meaning                                                                          |
|------------------------------|----------------------------------------------------------------------------------|
| `component`, `version`       | Name and version.                                                                |
| `type`                       | OS package, language package or program file.                                    |
| `supplier`                   | Who built it, from the package metadata (for example the signing key's owner).   |
| `added_by`                   | The origin that put it there: a base image or the application build.             |
| `layer`                      | The layer that added the current version.                                        |
| `change`, `previous_version` | Whether the layer added, upgraded or downgraded it, and the version it replaced. |
| `managed_by`                 | The package manager that owns it, if any.                                        |
| `location`                   | Where it is in the image filesystem.                                             |
| `license`                    | Declared licence.                                                                |
| `concerns`                   | Anything that needs attention, such as an unsigned package or an unowned binary. |
| `evidence`                   | The evidence behind the attribution.                                             |
| `purl`                       | Package URL, for joining with SBOMs and other tools.                             |

## Vulnerabilities CSV

`provenance-<image>-vulnerabilities.csv`, one row per finding. Written only when vulnerability data was supplied.

| Column                                          | Meaning                                                                                                  |
|-------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| `id`, `severity`, `title`                       | The finding as reported by the scanner.                                                                  |
| `package`, `installed_version`, `fixed_version` | The affected package and the version that fixes it.                                                      |
| `vendor_fix_status`                             | Fix available, no fix released yet, deferred, will not fix, no longer supported, or under investigation. |
| `introduced_by`                                 | The origin that introduced it.                                                                           |
| `layer`                                         | The layer it was traced to.                                                                              |
| `attribution`                                   | How it was traced: matched to a traced component, or the layer reported by the scanner.                  |
