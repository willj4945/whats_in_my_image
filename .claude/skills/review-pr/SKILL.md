---
name: review-pr
description: Review a pull request on whats_in_my_image - a contributor's fork PR or a Dependabot update - by running it, not just reading it. Use when asked to review, check or merge a PR, or to look at Dependabot updates.
---

# Reviewing a pull request

Review by running the change. Draft the review in chat; post it, approve or merge only when the maintainer says so.

## Contributor PRs

```bash
git fetch origin pull/N/head:pr-N -f
gh pr view N --json title,body,author,commits,files,mergeable,mergeStateStatus,maintainerCanModify
git diff --stat origin/main...pr-N          # three dots: what the PR itself changes
```

GitHub's PR diff can include unrelated changes when the branch is stale; trust the three-dot diff. Then test the
result as it would be after merging:

```bash
git worktree add --detach /tmp/wt-N origin/main && cd /tmp/wt-N && git merge --no-edit pr-N
/path/to/repo/.venv/bin/python -m unittest discover -s tests -q
/path/to/repo/.venv/bin/ruff check . && /path/to/repo/.venv/bin/ruff format --check .
/path/to/repo/.venv-docs/bin/mkdocs build --strict -d /tmp/site-N
```

Then exercise the feature for real:

- CLI behaviour: run `python3 -m whats_in_my_image` against testbed images (`localhost:5000/testbed/...` with
  `--plain-http`, `docker:IMAGE`, catalog `testbed/.state/catalog.json`) and check exit codes.
- Containers and compose: run them with Docker, including the failure path (missing variable, no socket access).
- Attribution changes: compare components (name, version, ecosystem, layer) before and after on several images.

Check, beyond correctness:

- Every assumption in the code matches the data it reads (flag message strings, report keys, origin `match` values).
- New behaviour fails closed when data is missing, and is labelled as an estimate when it is one.
- A test exists that fails without the change.
- Docs follow the `docs-sync` map; tables are aligned; the CHANGELOG entry is under `## [Unreleased]` (merges can
  move it into a released section).
- Merge conflicts with `main`: `git merge-tree --write-tree origin/main pr-N` (non-zero exit means conflicts).

Write the review as: what was verified (with the commands' results), the blocking change if any (with the exact fix),
and minor points. Offer to make small doc fixes in a follow-up rather than sending a contributor another round.

**Merging:** the branch must be up to date with `main`. If `maintainerCanModify` is true, update it with
`gh api -X PUT repos/willj4945/whats_in_my_image/pulls/N/update-branch`, wait for checks, then merge. Squash-merge
(`gh pr merge N --squash --subject "type: summary (#N)"`) when the history has duplicate or noise commits; the
squash keeps the contributor as author. The maintainer's approval satisfies the review rule, so `--admin` is not
needed on approved contributor PRs.

Clean up: `git worktree remove --force /tmp/wt-N`, `git branch -D pr-N` once merged.

## Dependabot PRs

Verify that what is pinned is what was published:

- **pip** (`.github/requirements/*.txt`, `docs/requirements.txt`, `requirements-build.txt`): every `--hash` in the
  lock for the bumped package must be one of PyPI's file digests:

  ```bash
  curl -s https://pypi.org/pypi/PKG/VERSION/json | python3 -c 'import json,sys;[print(u["digests"]["sha256"]) for u in json.load(sys.stdin)["urls"]]'
  ```

- **Actions** (`uses: owner/repo@SHA # vX.Y.Z`): the SHA must be the commit behind the tag. Dereference annotated
  tags:

  ```bash
  gh api repos/OWNER/REPO/git/ref/tags/vX.Y.Z --jq '.object | "\(.type) \(.sha)"'
  gh api repos/OWNER/REPO/git/tags/TAG_SHA --jq .object.sha        # only when type is "tag"
  ```

- A minor bump of Ruff or zizmor can add rules: the PR's own CI runs the new version, so green CI means the code
  already complies. After merging a Ruff bump, update `.venv` from the lock file.

If the Security workflow fails on a Dependabot PR, read the Trivy log: a new advisory against anything pinned in the
repo fails every PR until that pin moves. Fix the pin in its own PR first, then rebase the Dependabot PRs.

Rebase with a `@dependabot rebase` comment, one PR at a time (merging one puts the others behind). Dependabot may
close the PR and open a replacement with newer versions; review the replacement.

## Reading CI

`gh pr checks N` (add `--watch` to wait). For a failure:
`gh api repos/willj4945/whats_in_my_image/actions/jobs/JOB_ID/logs` (the job ID is in the check's URL), since
`gh run view --log-failed` sometimes returns nothing.
