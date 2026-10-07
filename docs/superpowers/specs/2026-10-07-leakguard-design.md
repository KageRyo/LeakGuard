# LeakGuard v0.1 design

Status: approved by the user on 2026-10-07; implemented and locally validated.

Evidence: ../../validation.md. Remote delivery is outside this implementation step.

## Purpose and scope

LeakGuard is a lightweight, offline secret and credential leakage guard for CI
pipelines and AI-assisted development. It detects potential credentials in source,
configuration, logs, test output, snapshots, JSON/YAML dumps, notebooks, and
generated artifacts. The initial product is an independent Rust CLI and GitHub
Action, with no server, database, LLM, or sibling-project runtime dependencies.

The supplied brief defines the intended capabilities. The precise defaults,
thresholds, report schema, and Git semantics below are proposed implementation
decisions. Publication, Marketplace setup, and remote pushes are separate delivery
steps and are not assumed to have been authorized by the supplied brief.

## Alternatives and selected approach

1. Recommended: a small Rust scanner combining a curated pattern set, contextual
   assignments, and entropy evidence. This covers the brief's offline single-binary
   workflow while keeping rules understandable and testable.
2. Wrap an existing scanner: quicker provider coverage, but adds a runtime dependency
   and gives less control over contextual artifact detection and explanations.
3. Build a broad provider rule registry: more maintenance and false-positive tuning
   than the v0.1 brief calls for. Defer this and organization-defined rules.

## Threat model and boundaries

Inputs are local text files or Git objects. LeakGuard never transmits candidates,
calls credential providers, or attempts to validate whether a credential is live.
Findings indicate potential exposure; confidence scores are heuristic evidence
scores, not calibrated probabilities or proof that a secret is valid.

The tool complements existing provider scanning by emphasizing generic credentials
and accidental exposure in artifacts. It does not promise exhaustive detection.
Encrypted files, archives, binary formats, screenshots, credential rotation,
network scanning, and decoding arbitrary base64 payloads are outside v0.1.
Notebook files and JSON/YAML dumps are scanned as text without executing content.

## CLI and input selection

Commands:

```sh
leakguard scan
leakguard scan --staged
leakguard scan --history
leakguard scan --diff BASE
leakguard scan ./logs ./artifacts
leakguard scan --format json
leakguard scan --format sarif --output leakguard.sarif
leakguard scan --format annotations
```

- With no paths or Git mode, scan the working-tree contents of tracked files in
  the current repository. This includes unstaged edits, excludes untracked files,
  and does not silently substitute a recursive directory scan outside Git.
- Explicit paths recursively include ignored and untracked text files, including
  `.env`, `*.local`, logs, and artifact directories. Exclude `.git` internals;
  do not follow symlinks. Deduplicate overlapping inputs and order paths stably.
- `--staged` reads index blobs, not working-tree copies; exclude staged deletions.
- `--diff BASE` compares `git merge-base BASE HEAD` with HEAD and scans added lines with their actual
  destination line numbers. Renames and binary changes are handled explicitly.
  Uncommitted changes require the default or staged mode.
  If no shared ancestor is available, fail with exit 2 rather than falling back
  to comparing BASE directly. This is the PR guard mode; tracked/history are audits.
- `--history` scans text blobs reachable from HEAD, including credentials removed
  in later commits. Associate each historical finding with its commit and path;
  deduplicate repeated occurrences of an unchanged blob at the same path.
  State clearly that other refs and unfetched shallow history are outside scope.
- Git modes are mutually exclusive and cannot be combined with explicit paths.
  Use argument-vector subprocess calls and NUL-delimited Git path inventories.
  Never interpolate filenames or revisions into shell commands.
- Default maximum file size is 10 MiB; expose `--max-file-bytes`. Report skipped
  oversized, binary, non-UTF-8, and symlink inputs with reasons and counts.
  Filesystem/Git read failures cause exit 2, preventing an incomplete scan from
  being reported as PASS. No silent truncation of oversized inputs.

## Detection and scoring

Separate candidate extraction from evidence scoring and report construction.
Start with a limited, documented set: AWS access key IDs, GitHub token families,
OpenAI-style keys, Google API keys, structurally plausible JWTs, PEM private key
headers, credential-bearing database URLs, and generic contextual credentials.
Patterns must be documented as syntax checks rather than credential verification.

Context recognizes case-insensitive keys such as `api_key`, `token`, `password`,
`secret`, `private_key`, and `authorization`, including quoted JSON keys,
assignment syntax, YAML mappings, Bearer headers, and Basic authorization values.
Require credential material rather than flagging the contextual word alone.

Proposed scoring, capped at 100:

- Recognized provider pattern, private-key header, or database password: 70.
- JWT or generic context candidate: 30.
- Credential assignment or authorization context: +25.
- At least 20 candidate characters and Shannon entropy >= 3.5 bits/character: +15.
- Artifact/config path evidence: +5.

HIGH is >= 70, MEDIUM is 40–69, LOW is below 40. Drop generic context candidates
below 40. Retain recognized patterns even if entropy is low. Suppress obvious
placeholders and template references such as `${TOKEN}`, `<your-token>`, empty
values, and documented example literals; do not suppress a real-looking token
simply because it appears in a test fixture or README. Do not flag high-entropy
hashes and identifiers without credential context or a recognized pattern.

Deduplicate overlapping matches at the same location, preserve all applicable
reasons, and report the strongest rule. Explain each score using its evidence.
Artifact path classification is descriptive, not a claim that the file was
generated by AI. No machine-learning or AI attribution claims.

## Reports and failure behavior

Text, JSON, SARIF 2.1.0, and GitHub workflow annotations share one report model.
Each finding contains rule ID, display name, path, one-based line/column,
confidence label, heuristic score, reasons, and optional historical commit ID.
Do not include matched secret values, source snippets, hashes of secret values,
or raw input lines in reports, diagnostic errors, or annotations.

Escape control characters in terminal output, GitHub annotation properties and
messages, and file URIs in SARIF. SARIF positions must follow the declared column
encoding. Deterministic ordering enables stable CI output. JSON includes scan
mode, scanned file/artifact counts, skipped counts/reasons, and findings.

`--fail-on high|medium|low` defaults to high:

- Exit 0: scan completed and no finding meets the failure threshold; text reports
  PASS with no findings and WARNING with below-threshold findings.
- Exit 1: one or more findings meet the threshold; text reports FAIL.
- Exit 2: arguments, scan inputs, Git commands, configuration, or report writes
  failed. Report-write failure must not obscure itself behind exit 0 or 1.

## GitHub Action and build delivery

Provide a root composite `action.yml`, author KageRyo, with inputs for paths,
Git mode/base revision, failure threshold, format, and report destination.
Pass inputs through environment variables and arrays, never shell-evaluate them.
Default to scanning checkout tracked files; allow logs/artifacts as explicit paths.
Users must fetch the requested history or diff base; missing objects fail clearly.

Use a same-version Linux x86_64 release binary and verify its archive against
`SHA256SUMS` before extracting or running it. Fail clearly on unsupported runners.
Default to redacted GitHub annotations; do not auto-upload reports or require
write permissions. Offer SARIF output with an explicit consumer upload example.

Local Action integration tests use a controlled synthetic release server and the
real CLI binary, proving valid download, checksum rejection, argument handling,
and propagation of exit codes without needing a public release.

CI runs formatting, Clippy with warnings denied, locked tests, a release build,
and Action integration checks. A release workflow builds Linux x86_64, Windows
x86_64, and macOS arm64 assets and checksums, with version consistency checks.
Prepare release automation without claiming that a public `v1` tag exists.
README examples label unpublished versions until an actual release is verified.

Use Conventional Commits 1.0.0 for new commits (`feat`, `fix`, `docs`, `test`,
`ci`, as appropriate); do not rewrite the existing initial commit.

## Acceptance evidence

1. README states purpose, threat model, differences from provider scanning,
   limitations, scoring, Git selection semantics, installation and CLI/CI examples.
2. Rust detector tests cover each supported rule, generic contexts, artifact
   evidence, placeholders, benign hashes, overlap deduplication, Unicode positions,
   and low-entropy credentials in strong contexts.
3. Temporary Git repositories prove default working-tree, index versus worktree,
   diff line numbers/deletions/renames, removed historical secrets, unusual paths,
   missing revisions, and shallow-history boundaries.
4. CLI tests prove path recursion including ignored artifacts, symlink/binary/size
   handling, deterministic reports, output errors, and threshold exit codes.
5. Canary secrets never appear in text, JSON, SARIF, annotation, or stderr output;
   malicious filenames cannot inject workflow commands or execute shell content.
6. SARIF parses as 2.1.0 with matching rule references and correct locations;
   JSON parses with accurate counts; annotations have escaped file properties.
7. Action integration verifies checksum and finding/error exit propagation.
8. Formatting, Clippy, locked tests, release build, and an installed-binary smoke
   test all pass locally. Hosted CI and publication remain separately identified
   until remote evidence exists.

## Implementation sequence after review

Write README and CLI/data contracts first; implement detection and redaction with
tests; implement filesystem/Git input selection; add reports and end-to-end tests;
add Action and CI/release automation; run full validation and review against every
acceptance item. A detailed implementation plan follows approval of this spec.
