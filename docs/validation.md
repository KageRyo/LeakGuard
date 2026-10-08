# LeakGuard v0.2.0 pre-release validation

Date: 2026-10-08 (Asia/Taipei). Branch: `feat/v0.2-suppression`, based on `ad5a0a6` (main after the v0.1.0 release). Tested implementation commit: `d74265fa66b72f69a34445bc63d009dadec9911b`. This record is committed on top of it and changes no executable code.

v0.2.0 adds finding suppression: same-line `leakguard:allow` markers and a validated `.leakguard.toml` allow list. Suppressed findings never affect the exit code. Text and annotation summaries count them, JSON lists them under `suppressed`, and SARIF omits them from `results` while recording `suppressedCount`.

## Gates

All commands below exited 0 on Linux x86_64 with Rust stable 1.97.1. The minimum-version check used Rust 1.85.0. Dependencies added: `toml` 1.1.7 and `globset` 0.4.19; 0.4.19 is the newest `globset` release compatible with Rust 1.85.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo +1.85.0 check --locked --all-targets
cargo build --release --locked
python3 scripts/test-action-integration.py
shellcheck scripts/leakguard-action.sh
actionlint -shellcheck=
cargo run --release --locked --quiet -- scan
```

The Rust suites have 58 passing tests: 10 CLI, 10 detection, 21 Git modes, 1 report location and 16 suppression. The 38 v0.1.0 tests pass unchanged. The Action suite has 9 passing tests; two are new and cover the `config` input, default discovery and invalid configs.

## Acceptance evidence

| Requirement | Evidence |
| --- | --- |
| Inline markers | Every finding on a marked line is suppressed. The marker works with `#`, `//` and `<!--` comments and with CRLF lines. It is case-sensitive, and a marker on another line has no effect. Marker text after the token never appears in text, JSON, SARIF or annotations output (canary test). |
| Config validation | Each invalid shape exits 2 with an entry/field message, and a canary confirms that no config content is quoted. Invalid shapes: missing `paths`/`rules`, missing or blank reason, empty arrays, unknown rule or key, absolute, `..`, trailing-`/` or invalid glob patterns, TOML syntax errors, non-UTF-8 files, directories, and symlinked configs. A UTF-8 BOM and an empty file are accepted. |
| Matching | `*` stays within a directory and `**` crosses directories. `./`, `../` and absolute explicit paths normalize to the config directory. Files outside it match only rule-only entries. `paths` and `rules` must both match, and an inline marker takes precedence over config. |
| Discovery | `.leakguard.toml` is found at the Git top level, or in the current directory outside Git. A relative `--config` path resolves from the current directory, and its globs are relative to its own directory. A missing explicit config exits 2. |
| Git modes | Suppression applies in tracked, staged, history and diff modes. In history, an unmarked historical blob still fails after a later commit adds a marker. In diff mode, a marker counts only on an added line. A diff that modifies the config emits `This change modifies .leakguard.toml; review new suppressions`; one that does not stays silent. |
| Reports and exits | All-suppressed input is PASS with exit 0, and an unsuppressed HIGH finding still exits 1. Text and annotation summaries count suppressed findings. SARIF has empty `results` and `rules` plus `suppressedCount`. JSON suppressed entries keep every finding field plus `suppression`. |
| SARIF schema | A suppressed-only report and a finding report both validated against the official OASIS SARIF 2.1.0 JSON schema. |
| Action | The `config` input is forwarded as `--config=<value>` (a leading-dash value stays data). A repository config applies without the input. Invalid configs exit 2. |
| Dogfooding | `.leakguard.toml` suppresses `tests/**`. One inline marker covers the detector false positive at `scripts/action-smoke-fixture.py:17`. The self-scan reports `WARNING: 34 files scanned, 4 artifact/config files, 5 potential secrets, 32 suppressed, 0 skipped` and exits 0. CI runs it on Linux, Windows and macOS. |

The five remaining MEDIUM findings are detector false positives on prose and code, such as "Bearer header" and `let password = value`. They are the planned detector-precision follow-up, not suppression targets.

## Release delivery gates

Release delivery repeats the v0.1.0 sequence below with tag `v0.2.0`. `Cargo.toml`, `action-version.txt` and the README now say 0.2.0, and `.github/workflows/action-smoke.yml` invokes `KageRyo/LeakGuard@v0.2.0`. `v1` moves to the v0.2.0 release commit only after the public consumer smoke passes. Release notes must say that the text and annotation summary lines gained an `N suppressed` field, for anyone parsing them.

# LeakGuard v0.1.0 pre-release validation

Date: 2026-10-07 (Asia/Taipei). Branch: `feat/leakguard-v0.1`, based on `ac6f448`. Final tested code and verification commit: `f7fe4d8255a12352c7f7248e036dfacafdd38dc8`. Subsequent release-smoke maintenance does not change executable code. The extracted-archive smoke resolves its temporary fixture directory before scanning, because macOS `/var` is a symlink and the scanner rejects linked ancestors. This was reproduced locally with a symlink-backed `TMPDIR`; checksum, version, exit 0/1/2 and redaction checks all passed after resolution.

## Gates

All commands below passed on Linux x86_64. The full Rust integration suite has 38 passing tests: 10 detection, 9 filesystem/CLI, 18 Git modes, 1 report location. The Action suite has 7 passing tests, with multiple input/error subcases.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo +1.85.0 check --locked --all-targets
cargo build --release --locked
python3 scripts/test-action-integration.py
shellcheck scripts/leakguard-action.sh
actionlint -shellcheck=
cargo install --path . --root .superpowers/install --locked --offline --force
cargo build --release --locked --target x86_64-unknown-linux-gnu
RELEASE_TARGET=x86_64-unknown-linux-gnu RELEASE_TAG=v0.1.0 python3 scripts/package-release.py
```

Rust stable was 1.97.1; the independent minimum-version check used Rust 1.85.0. Workflow lint used actionlint 1.7.12 with its official archive checksum verified. Workflow shell lint is separate from the composite runner's ShellCheck gate. Action/workflow YAML parsed successfully.

Both a report without findings and a report with a synthetic finding validated against the official OASIS SARIF 2.1.0 JSON schema. The finding report had a Unicode code-point start column of 4 for `中😀 ` followed by a token and an absolute percent-encoded file URI. Schema-validation tooling is a development check only; it adds no scanner runtime dependencies.

Installed and freshly extracted binaries both returned the expected exit codes: 0 for clean input, 1 for a synthetic high-confidence credential, 2 for missing input. Text/JSON/SARIF/annotations and stderr did not contain the canary token. Repeated JSON scans produced identical reports.

## Acceptance audit

| Approved requirement | Evidence |
| --- | --- |
| Threat model, differentiation, scope, install and CI usage | README.md and CONTRIBUTING.md; unpublished Action/release examples explicitly labeled |
| Curated rules, context, entropy, path evidence, thresholds | tests/detection.rs: all provider families, valid/invalid JWT, low-entropy passwords, contextual JSON/YAML/headers and prefixed environment keys |
| Placeholders and benign random IDs | Detector tests suppress templates, empty values, examples, bare authorization prefixes and YAML scalar markers; entropy without credential evidence does not trigger |
| Deduplication and explanations | Same token emits one finding; nested database URL/provider matches preserve both pattern reasons without duplicating the result |
| Filesystem artifact selection and bounded input | CLI tests include ignored logs, overlapping paths, binary/invalid UTF-8/oversized inputs, symlinks and linked ancestors; `.git` internals excluded |
| Tracked, index, diff and history semantics | Real temporary Git repositories prove worktree/index separation, unborn index, staged deletions, deleted historical secrets, blob deduplication, merge-base PR additions, added-line positions, renames and fetched-history boundaries |
| Unusual filenames and invalid Git inputs | Tests include newlines, shell syntax, literal backslashes, brackets/colons, root trailing newline, missing revisions and unmerged index |
| Diff respects actual text and destination lines | Regressions cover `.gitattributes -diff`, configured inter-hunk context, pure rename, rename followed by source-directory creation, and an oversized BASE line with a small destination |
| Redacted, safe reports | Canary tests across all formats, annotation injection case, Unicode positions, JSON parsing/counts, SARIF rule references and official schema validation |
| Absolute SARIF paths | Report regression covers Windows drive paths, UNC authorities and percent escaping; installed Linux binary produces `file:///` URIs |
| PASS/WARNING/FAIL and exits 0/1/2 | CLI threshold tests, invalid argument/input/output tests, installed/extracted smoke tests and Action exit propagation |
| Verified Action download | Local HTTP server supplies a real version-matching release CLI; clean/finding paths, checksum rejection, literal shell-like paths, output errors, unsupported runners and a diverged PR diff tested |
| CI and release preparation | Pinned Action refs verified through GitHub API; workflow lint passes; CI has Linux/Windows/macOS and MSRV jobs; release matrix checks freshly extracted Linux/Windows/macOS packages before a draft; public consumer smoke runs after publication |
| Review | Independent whole-branch review found no Critical issues; two Important Git diff defects reproduced and fixed; reviewer confirmed material findings resolved; focused merge-base/release review independently reran 18 Git and 7 Action tests with no blockers |
| Conventional Commits | Implementation, fixes and documentation use `feat:`, `fix:`, `ci:` and `docs:`; existing initial commit preserved |

The review also identified bare authorization markers and environment prefixes; these now have regression coverage. Generic multiline YAML scalar extraction is explicitly outside v0.1; standalone provider and PEM patterns remain detectable. Patch-line buffering retains at most 512 bytes per line while draining the rest, so a large BASE line does not allocate an unbounded scanner buffer.

## Local artifact

The Linux archive was freshly generated, checked against its checksum sidecar, extracted and executed successfully:

```text
dist/leakguard-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
SHA256 2f680a166650f690af12e3e93faed093c5e8f2757adcde6fd8cefa8c18d515a7
```

Tag/package version mismatch was deliberately tested with `RELEASE_TAG=v0.1.1` and rejected before packaging. Version 0.1.0 matches Cargo.toml, action-version.txt and the extracted executable.

Local detailed command logs and smoke evidence are under `.superpowers/validation/` (ignored development scratch). Binary installation is isolated under `.superpowers/install/`; the user's global Cargo bin directory was not changed.

## Release delivery gates

This is the pre-release local evidence snapshot after the merge-base correction. Subsequent documentation commits do not change the tested runtime or verification scripts. The release tag and exact release-source SHA are recorded in the GitHub release notes, so release evidence is tied to the actual tagged tree.

PR #1 is open. Prior head `5b9a33f` passed Linux, Windows, macOS and MSRV hosted CI; those results do not substitute for checks of the revised head. Merge requires fresh success on every latest-head PR/push CI job and an exact-head match.

The approved delivery sequence is:

1. Latest-head CI passes, then merge PR #1 without bypassing changed gates.
2. Confirm main CI and tag `v0.1.0` at the tested merge commit.
3. The release matrix builds Linux x86_64 on Ubuntu 22.04, Windows x86_64 and macOS ARM64; each archive passes checksum, extracted version, exit 0/1/2 and redaction smoke before upload. Draft assembly verifies all three checksums.
4. Download draft assets, verify checksums/member layouts and smoke the Linux CLI and Action runner against the actual draft asset before publication.
5. Publish the verified draft. The `Published Action smoke` workflow invokes the real `KageRyo/LeakGuard@v0.1.0` with clean and finding fixtures; verify its result.
6. Create `v1` only after public consumer smoke passes, at the same release commit.

Publication results, native archive smoke and consumer Action evidence live in GitHub Actions and release notes. This file does not claim publication occurred before those gates. Marketplace listing remains a separate owner operation.

## Merge-base correction

`--diff BASE` now selects `merge-base(BASE, HEAD) -> HEAD`. The three new Git regressions prove that upstream removal does not make a retained credential into a PR addition, actual PR-introduced material still fails at its destination line, and unrelated history fails with exit 2 without echoing the revision. The new Action regression proves the same selection through the argument-forwarding and verified-download runner. README recommends diff for PR gates, tracked for full working-tree audit and history for historical investigation.
