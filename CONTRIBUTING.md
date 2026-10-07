# Contributing

Use Rust 1.85+ and Git. Run the checks listed in README before proposing changes.
Use synthetic credentials in tests; never submit actual secrets or credential
snippets in issues, pull requests or logs. Findings and diagnostics must stay
redacted. Keep detection evidence explainable and scanning offline.

New commits follow Conventional Commits 1.0.0, for example:

- `feat(scanner): add a contextual rule`
- `fix(git): preserve diff destination line numbers`
- `test(action): reject corrupt downloads`
- `docs: explain history boundaries`

Releases must keep Cargo.toml, action-version.txt, version tags and the pinned
consumer reference in .github/workflows/action-smoke.yml consistent.
Release automation creates a draft with three platform assets and SHA256SUMS.
Review the assets, fresh extracted binaries and hosted CI before publication.
The Linux Action requires a same-version published release; do not point consumers
at an unpublished major tag. A workflow_dispatch run builds artifacts without
creating a release. Marketplace publication is a separate owner action.
