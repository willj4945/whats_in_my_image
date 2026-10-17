# Command line

This page is generated from the installed version's `--help` output when the documentation is built.

## `wimi`

Analyse an image and write the reports. `wimi scan IMAGE` is accepted as an alias.

<!-- wimi-help -->

### Exit codes

| Code | Meaning                                                                         |
|------|---------------------------------------------------------------------------------|
| 0    | The report was written, and every `--fail-on` rule passed (or none was given). |
| 1    | The report was written, and at least one `--fail-on` rule failed.               |
| 2    | Bad option, or the image could not be loaded. No report is written.             |
| 3    | Unexpected error. Run again with `--debug` for the traceback.                   |

`wimi catalog` uses the same codes: 2 when the catalog file is unreadable or no image could be added.
See [Failing the pipeline](../ci/index.md#failing-the-pipeline) for the `--fail-on` rules.

## `wimi catalog`

<!-- wimi-help: catalog -->

### `wimi catalog add`

<!-- wimi-help: catalog add -->

### `wimi catalog crawl`

<!-- wimi-help: catalog crawl -->

### `wimi catalog list`

<!-- wimi-help: catalog list -->

### `wimi catalog remove`

<!-- wimi-help: catalog remove -->
