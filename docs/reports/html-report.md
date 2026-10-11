# The HTML report

The HTML report is a single self-contained file with no external resources, so it can be emailed, attached to a
ticket, opened offline or printed to PDF. It follows the system light or dark theme and has a toggle.
[Open the sample report](../sample-report.html) to follow along.

## Sections

1. **Bottom line.** Plain-English conclusions, each backed by numbers: who supplied what share of the software,
   where the critical and high vulnerabilities came from, and who can fix them. Written so a CISO or CIO can read
   it in two minutes. With `--fail-on`, the first line says whether the policy passed and which rules failed.
2. **Where the contents came from.** The proof behind each origin (exact or partial layer-digest match, catalog
   identification, or an estimate), with charts of components and vulnerabilities by origin.
3. **How the image was built.** Every layer, what it actually added, and the recorded build command. A "layer cake"
   draws the image as stacked slices in build order, coloured by who added each layer, with the end of the base
   marked. Risky build practices are called out, such as `curl | sh`, disabled signature or TLS checks, and `chmod 777`.
4. **Findings that need attention.** Each finding grouped by owner, so it can be routed to the right team. Examples:
   outdated base image, vulnerabilities the vendor will not fix, programs no package manager installed.
5. **Vulnerabilities.** Each CVE with severity, vendor fix status, and the party that introduced it. Filterable.
6. **Full inventory.** Every component with its supplier and the evidence behind that attribution. Searchable.
7. **Method and glossary.** How the conclusions were reached, written for non-specialists.

!!! tip "Sharing with leadership"
    Use `--subtitle` to label the report (for example "Prepared for CISO review") and `--app-name` to name the
    application team, so the bottom line reads naturally to its audience.
