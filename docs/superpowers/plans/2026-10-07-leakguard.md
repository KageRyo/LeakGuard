# LeakGuard Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement task by task.

**Goal:** Deliver the approved offline Rust leakage scanner and CI Action. **Architecture:** A detector emits redacted findings; input adapters select filesystem or Git text; reporters consume one serializable report. The CLI coordinates them. **Tech Stack:** Rust, clap, regex, serde/serde_json, base64, Git, Bash. **Spec:** ../specs/2026-10-07-leakguard-design.md

## Global Constraints

- No server, database, LLM, sibling runtime dependency, or credential verification.
- 10 MiB default input limit; no symlink following; explicit skip accounting.
- Scores: strong pattern 70, context/JWT 30, context +25, entropy +15, artifact +5.
- HIGH >=70, MEDIUM >=40; default failure threshold HIGH; exits 0/1/2.
- No candidate values or input snippets in any report or error.
- No remote push, merge, tag or publication in this implementation task.
- New commits follow Conventional Commits 1.0.0.

## Review Focus

- Filenames containing newlines, commas, percent signs and shell syntax remain data.
- Index contents differ from the worktree; staged scans must read index blobs.
- Git diff deletions, renames, merges and Unicode positions retain valid locations.
- Low-entropy passwords remain findings in strong contexts, while placeholders do not.
- Input errors, report failures and checksum failures cannot produce PASS.

### Task 1: Detector and report contract

**Files:** Cargo.toml, src/lib.rs, src/model.rs, src/detect.rs, tests/detection.rs, README.md. **Interfaces:** `detect(path: &str, text: &str) -> Vec<Finding>`; Finding exposes only rule/path/position/score/confidence/reasons/commit.

- [x] Write provider/context/placeholder/Unicode/overlap tests; run `cargo test --test detection` and confirm expected assertion failures with an empty detector.
- [x] Implement curated patterns, contextual extraction, entropy evidence and overlap deduplication.
- [x] Run the detector suite and confirm scores, redaction and false-positive cases.
- [x] Write threat model, scope, scoring and usage in README; commit as `feat: add redacted contextual credential detector`.

### Task 2: CLI, filesystem and reports

**Files:** src/main.rs, src/input.rs, src/report.rs, tests/cli.rs. **Interfaces:** `scan(options: &ScanOptions) -> Result<Report, String>`; `render(report: &Report, format: Format, threshold: Confidence) -> String`.

- [x] Write CLI subprocess tests for ignored artifacts, thresholds, skip accounting, symlinks, output failures, canary redaction and annotation escaping; confirm failures.
- [x] Implement recursive traversal, bounded reading, argparse, shared reports, text/JSON/SARIF/annotations and safe output writes.
- [x] Run `cargo test` and validate actual parsed SARIF/JSON locations and counts.
- [x] Commit as `feat: add filesystem scanning and CI reports`.

### Task 3: Git selection

**Files:** src/git.rs, src/input.rs, tests/git_modes.rs. **Interfaces:** Git adapter produces inputs with optional line filter and commit; filesystem and Git use the same detector and report accumulation.

- [x] Add real temporary-repository tests for working tree, staged content, deleted history, diff additions/renames, filenames, revisions and shallow scans.
- [x] Confirm these tests fail before replacing missing Git adapter behavior.
- [x] Implement NUL inventories, blob reads, HEAD-reachable history and diff added-line selection, with bounded reading and explicit skip/error accounting.
- [x] Run `cargo test`; commit as `feat: scan Git worktree index diffs and history`.

### Task 4: Action and automation

**Files:** action.yml, action-version.txt, scripts/leakguard-action.sh, scripts/test-action-integration.py, .github/workflows/ci.yml, .github/workflows/release.yml, CONTRIBUTING.md. **Interfaces:** versioned Linux archive and SHA256SUMS; newline-separated Action paths and environment variables become CLI argument arrays.

- [x] Write local HTTP release tests asserting exit 0/1/2, checksums and literal shell-like paths; confirm missing runner fails these tests.
- [x] Implement verified download/extraction and safe argument forwarding.
- [x] Run integration tests with the actual release CLI and synthetic server.
- [x] Add locked CI and three-platform release/checksum automation; commit as `ci: add verified composite action and release builds`.

### Task 5: Completion audit and review

- [x] Run `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`, `cargo build --release --locked` and Action integration.
- [x] Install binary into a local temporary prefix and prove clean/finding/error exits.
- [x] Obtain whole-branch code review; address material findings with regression tests.
- [x] Audit every spec acceptance item and record evidence in docs/validation.md.
- [x] Report local readiness and exact branch/commit; remote CI/release remain pending.
