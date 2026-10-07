# LeakGuard v0.1.0 local validation

Date: 2026-10-07 (Asia/Taipei).
Branch: `feat/leakguard-v0.1`, based on `ac6f448`.
Final tested code commit: `593014bb117bb0f751dd323f1f0cee89ecf98f84`.
Subsequent completion documentation does not change executable code.

## Gates

All commands below passed on Linux x86_64. The full Rust integration suite has
35 passing tests: 10 detection, 9 filesystem/CLI, 15 Git modes, 1 report location.
The Action suite has 6 passing tests, with multiple input/error subcases.

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

Rust stable was 1.97.1; the independent minimum-version check used Rust 1.85.0.
Workflow lint used actionlint 1.7.12 with its official archive checksum verified.
Workflow shell lint is separate from the composite runner's ShellCheck gate.
Action/workflow YAML parsed successfully.

Both a report without findings and a report with a synthetic finding validated
against the official OASIS SARIF 2.1.0 JSON schema. The finding report had a
Unicode code-point start column of 4 for `中😀 ` followed by a token and an
absolute percent-encoded file URI. Schema-validation tooling is a development
check only; it adds no scanner runtime dependencies.

Installed and freshly extracted binaries both returned the expected exit codes:
0 for clean input, 1 for a synthetic high-confidence credential, 2 for missing
input. Text/JSON/SARIF/annotations and stderr did not contain the canary token.
Repeated JSON scans produced identical reports.

## Acceptance audit

| Approved requirement | Evidence |
| --- | --- |
| Threat model, differentiation, scope, install and CI usage | README.md and CONTRIBUTING.md; unpublished Action/release examples explicitly labeled |
| Curated rules, context, entropy, path evidence, thresholds | tests/detection.rs: all provider families, valid/invalid JWT, low-entropy passwords, contextual JSON/YAML/headers and prefixed environment keys |
| Placeholders and benign random IDs | Detector tests suppress templates, empty values, examples, bare authorization prefixes and YAML scalar markers; entropy without credential evidence does not trigger |
| Deduplication and explanations | Same token emits one finding; nested database URL/provider matches preserve both pattern reasons without duplicating the result |
| Filesystem artifact selection and bounded input | CLI tests include ignored logs, overlapping paths, binary/invalid UTF-8/oversized inputs, symlinks and linked ancestors; `.git` internals excluded |
| Tracked, index, diff and history semantics | Real temporary Git repositories prove worktree/index separation, unborn index, staged deletions, deleted historical secrets, blob deduplication, added-line positions, renames and fetched-history boundaries |
| Unusual filenames and invalid Git inputs | Tests include newlines, shell syntax, literal backslashes, brackets/colons, root trailing newline, missing revisions and unmerged index |
| Diff respects actual text and destination lines | Regressions cover `.gitattributes -diff`, configured inter-hunk context, pure rename, rename followed by source-directory creation, and an oversized BASE line with a small destination |
| Redacted, safe reports | Canary tests across all formats, annotation injection case, Unicode positions, JSON parsing/counts, SARIF rule references and official schema validation |
| Absolute SARIF paths | Report regression covers Windows drive paths, UNC authorities and percent escaping; installed Linux binary produces `file:///` URIs |
| PASS/WARNING/FAIL and exits 0/1/2 | CLI threshold tests, invalid argument/input/output tests, installed/extracted smoke tests and Action exit propagation |
| Verified Action download | Local HTTP server supplies a real version-matching release CLI; clean/finding paths, checksum rejection, literal shell-like paths, output errors and unsupported runners tested |
| CI and release preparation | Pinned Action refs verified through GitHub API; workflow lint passes; CI has Linux/Windows/macOS and MSRV jobs; release matrix packages three targets and creates only a draft |
| Review | Independent whole-branch review found no Critical issues; two Important Git diff defects reproduced and fixed; reviewer reran the suite and confirmed material findings resolved |
| Conventional Commits | Implementation, fixes and documentation use `feat:`, `fix:`, `ci:` and `docs:`; existing initial commit preserved |

The review also identified bare authorization markers and environment prefixes;
these now have regression coverage. Generic multiline YAML scalar extraction is
explicitly outside v0.1; standalone provider and PEM patterns remain detectable.
Patch-line buffering retains at most 512 bytes per line while draining the rest,
so a large BASE line does not allocate an unbounded scanner buffer.

## Local artifact

The Linux archive was freshly generated, checked against its checksum sidecar,
extracted and executed successfully:

```text
dist/leakguard-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
SHA256 9736f1bd70b7aa674f78953882e43aaffea0e8ef037d3005b2d978fd687a3339
```

Tag/package version mismatch was deliberately tested with `RELEASE_TAG=v0.1.1`
and rejected before packaging. Version 0.1.0 matches Cargo.toml, action-version.txt
and the extracted executable.

Local detailed command logs and smoke evidence are under `.superpowers/validation/`
(ignored development scratch). Binary installation is isolated under
`.superpowers/install/`; the user's global Cargo bin directory was not changed.

## Remote delivery boundary

This implementation has not been pushed, merged, tagged or published. Hosted CI,
Windows/macOS runtime results, their release archives, and public consumer Action
downloads have not been verified. These require the next authorized delivery step.
There is no public `v1` tag or Marketplace publication claimed by this report.
The Action requires a published same-version Linux release before external use.

Publication requires fresh remote checks, three-platform archives/checksums,
extracted executable smoke tests and a real consumer Action run. The release
workflow prepares a draft; it does not publish automatically.
