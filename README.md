# LeakGuard

[![CI](https://github.com/KageRyo/LeakGuard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/KageRyo/LeakGuard/actions/workflows/ci.yml) [![Latest release](https://img.shields.io/github/v/release/KageRyo/LeakGuard?display_name=tag&sort=semver)](https://github.com/KageRyo/LeakGuard/releases) [![License](https://img.shields.io/github/license/KageRyo/LeakGuard.svg)](LICENSE)

Lightweight secret & credential leakage guard for CI pipelines.

LeakGuard scans source code, configs, logs, fixtures, snapshots, notebooks and
artifacts for accidentally exposed credentials. It runs offline with no server,
database, LLM, provider API calls, or sibling-project dependencies.

**Version:** v0.1.0. The [GitHub release](https://github.com/KageRyo/LeakGuard/releases)
provides Linux x86_64, Windows x86_64 and macOS ARM64 archives with `SHA256SUMS`;
the composite Action downloads and verifies the matching Linux archive.

## Why LeakGuard?

Provider-oriented tools such as Gitleaks and GitHub Secret Scanning remain useful.
LeakGuard concentrates on contextual exposure: a password in a JSON dump,
a Bearer header in a debug log, or credentials in generated test artifacts.
A small curated pattern set, entropy evidence and credential context produce
explainable confidence scores. LeakGuard complements existing scanning; it does
not claim their rule breadth, validate live credentials, or replace rotation.

## Install from source

Rust 1.85+ and Git are required. Git is needed for repository modes only.

```sh
cargo install --path . --locked
leakguard --help
```

## Scan

```sh
leakguard scan                         # tracked working-tree files, including edits
leakguard scan --staged                # index blobs, not working-tree copies
leakguard scan --diff origin/main      # PR additions: merge-base(BASE, HEAD) -> HEAD
leakguard scan --history               # text blobs reachable from HEAD
leakguard scan ./logs ./artifacts       # includes ignored and untracked files
leakguard scan .env config.local
leakguard scan --fail-on medium
leakguard scan --format json --output leakguard.json
leakguard scan --format sarif --output leakguard.sarif
leakguard scan --format annotations
```

Git modes are mutually exclusive and cannot be combined with explicit paths.
Default scans require a repository; outside Git, pass paths explicitly. Deleted
tracked files are skipped. History covers HEAD-reachable commits, not every ref;
shallow clones only cover fetched history and produce a warning. Fetch the base
and shared history before a diff scan. `--diff BASE` compares the common ancestor
from `git merge-base BASE HEAD` with HEAD, so credentials removed upstream but
retained on a diverged PR branch are not mistaken for PR additions. No available
merge base (including insufficient shallow history) is an error with exit 2.
History findings carry their commit ID. Repeated unchanged
blobs at the same path are scanned once. Diff scans inspect added lines only,
retain destination line numbers, and exclude pure renames/deletions.

Explicit directory scans include dotfiles and ignored text. They exclude `.git`
internals and never follow symlinks. Overlapping paths are deduplicated. Files
larger than 10 MiB, binary files, invalid UTF-8 and symlinks are skipped and
accounted for; configure the limit with `--max-file-bytes`. JSON, YAML and notebooks
are scanned as text, without parsing or execution. Archives are not unpacked.

## Detection and scores

Rules cover AWS access-key IDs, GitHub token families, OpenAI-style keys, Google
API keys, structurally plausible JWTs, PEM private-key headers, credential-bearing
database URLs, and contextual credentials. These are syntax checks, not proof
that a credential is real or active. Context includes quoted JSON keys,
assignments, YAML mappings, Bearer and Basic headers, and keys such as `password`,
`secret`, `api_key`, `token`, `authorization` and `private_key`.
Environment prefixes such as `DB_PASSWORD`, `client_secret` and
`AWS_SECRET_ACCESS_KEY` are recognized. Generic multiline YAML scalar extraction
is outside v0.1; scalar markers alone are not credentials. Strong provider and PEM
patterns are still detected on their own lines.

| Evidence | Score |
| --- | ---: |
| Provider pattern, PEM header or database password | 70 |
| JWT or generic contextual candidate | 30 |
| Credential assignment or authorization context | +25 |
| At least 20 characters and entropy >= 3.5 bits/character | +15 |
| Artifact/config path | +5 |

Scores are capped at 100. HIGH is >=70; MEDIUM is 40–69; LOW is below 40.
Generic candidates below 40 are discarded. Obvious placeholders and template
references are suppressed; real-looking credentials in fixtures or docs are
still detected. Entropy alone does not flag random IDs or hashes. Overlapping
matches are reported once under the strongest rule. Scores are heuristics, not
probabilities. Artifact paths are evidence of exposure location, not AI authorship.

Reports contain paths, one-based line/column positions, rule IDs, confidence,
score, reasons and optional commit IDs. They contain no matched credential values,
input snippets or secret hashes. Paths are metadata: callers should avoid placing
secrets in filenames. Text escapes control characters; annotations escape workflow
command data; SARIF uses percent-encoded file URIs and Unicode code-point columns.

| Exit | Meaning |
| --- | --- |
| 0 | Completed; no findings meet `--fail-on` (default HIGH) |
| 1 | Completed; findings meet the failure threshold |
| 2 | Invalid arguments, input/Git failures, or report write failure |

Text prints PASS for no findings, WARNING for below-threshold findings, and FAIL
for threshold findings. Skips and shallow-history warnings are always reported;
a PASS only describes the inputs actually scanned, not skipped content.

## GitHub Action

The composite Action is Linux x86_64 only. It downloads the version matching
`action-version.txt`, checks `SHA256SUMS` before extraction, and runs the CLI.
Windows/macOS users can run the CLI directly. Action inputs are passed as data,
without shell evaluation. It preserves scanner exit codes and emits redacted
annotations by default. It does not upload reports or request write permissions.

Use **diff mode for a pull request gate**, with the PR head checked out and its
base commit fetched. Tracked mode is a full working-tree audit; history mode is
for investigating HEAD-reachable historical exposure. The default CLI/Action
mode remains tracked for explicit full-repository scans.

A pull request gate:

```yaml
name: Credential leakage guard
on: pull_request
permissions:
  contents: read
jobs:
  leakguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: KageRyo/LeakGuard@v0.1.0
        with:
          mode: diff
          base: ${{ github.event.pull_request.base.sha }}
          fail-on: high
```

For ignored/generated artifacts use newline-separated `paths` (no glob or shell
expansion):

```yaml
  - uses: KageRyo/LeakGuard@v0.1.0
    with:
      paths: |
        ./logs
        ./artifacts
      format: sarif
      output: leakguard.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: leakguard.sarif
```

The optional upload requires `security-events: write` in the consuming workflow.
Use `@v1` to follow the v1 Action series, or pin `@v0.1.0` for the exact
release shown above.
Only use `if: always()` when the report was actually produced; input/download
errors may leave no report. `mode: diff` requires `base`; combine explicit paths
only with the default tracked mode. `max-file-bytes` defaults to 10485760.

## Threat model and limitations

LeakGuard examines local text and Git objects. It never transmits candidates or
verifies credentials. It cannot guarantee exhaustive detection. Binary/encrypted
files, archives, images, arbitrary base64 decoding, custom organization rules,
credential remediation and full provider registries are outside v0.1. A JWT
pattern checks structure only. A PEM header can flag truncated key material.
Keep your provider scanning and push protection enabled and rotate exposed secrets.

## Development

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
python3 scripts/test-action-integration.py
```

Tests use synthetic credentials, real temporary Git repositories, and a local HTTP
release server. See [design](docs/superpowers/specs/2026-10-07-leakguard-design.md)
and [implementation plan](docs/superpowers/plans/2026-10-07-leakguard.md).
See [validation evidence and delivery boundaries](docs/validation.md) for the
tested scope and checks that remain dependent on remote CI or publication.
New commits follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
Licensed under [Apache-2.0](LICENSE).
