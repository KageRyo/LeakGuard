use std::{
    fs,
    process::{Command, Output},
};
use tempfile::tempdir;
fn run(root: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .current_dir(root)
        .args(args)
        .output()
        .unwrap()
}
fn token() -> String {
    format!("ghp_{}", "Ab3xY9kLm2NqR7sTu4VwZ8cDe5FgH6jIp0KlMnOp")
}
#[test]
fn explicit_paths_include_ignored_artifacts_and_deduplicate() {
    let d = tempdir().unwrap();
    fs::create_dir(d.path().join("logs")).unwrap();
    fs::write(d.path().join(".gitignore"), "logs/\n").unwrap();
    fs::write(d.path().join("logs/a.log"), format!("token={}", token())).unwrap();
    let o = run(
        d.path(),
        &["scan", "logs", "logs/a.log", "--format", "json"],
    );
    assert_eq!(o.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(report["scanned_files"], 1);
    assert_eq!(report["scanned_artifacts"], 1);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
}
#[test]
fn thresholds_warning_and_failure() {
    let d = tempdir().unwrap();
    fs::write(d.path().join("a.txt"), "password=aaaaaa").unwrap();
    let o = run(d.path(), &["scan", "a.txt"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(String::from_utf8(o.stdout).unwrap().contains("WARNING"));
    let o = run(d.path(), &["scan", "a.txt", "--fail-on", "medium"]);
    assert_eq!(o.status.code(), Some(1));
}
#[test]
fn all_reports_are_redacted_and_parseable() {
    let d = tempdir().unwrap();
    fs::write(d.path().join("a.txt"), format!("中😀 {}", token())).unwrap();
    for format in ["text", "json", "sarif", "annotations"] {
        let o = run(d.path(), &["scan", "a.txt", "--format", format]);
        assert_eq!(o.status.code(), Some(1));
        assert!(!String::from_utf8_lossy(&o.stdout).contains(&token()));
        assert!(!String::from_utf8_lossy(&o.stderr).contains(&token()));
        if format == "sarif" {
            let s: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
            assert_eq!(s["version"], "2.1.0");
            assert_eq!(s["runs"][0]["columnKind"], "unicodeCodePoints");
            assert_eq!(
                s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startColumn"],
                4
            );
            let id = &s["runs"][0]["results"][0]["ruleId"];
            assert_eq!(id, &s["runs"][0]["tool"]["driver"]["rules"][0]["id"]);
        }
    }
}
#[test]
fn skips_size_binary_and_invalid_utf8_and_reports_clean_pass() {
    let d = tempdir().unwrap();
    fs::write(d.path().join("big.txt"), "x".repeat(101)).unwrap();
    fs::write(d.path().join("bin.txt"), [0, 1, 2]).unwrap();
    fs::write(d.path().join("bad.txt"), [255, 254]).unwrap();
    fs::write(d.path().join("small.txt"), "safe").unwrap();
    let o = run(
        d.path(),
        &["scan", ".", "--max-file-bytes", "100", "--format", "json"],
    );
    assert_eq!(o.status.code(), Some(0));
    let r: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(r["scanned_files"], 1);
    assert_eq!(r["skipped"].as_array().unwrap().len(), 3);
}
#[test]
fn errors_do_not_leak_user_values_or_succeed() {
    let d = tempdir().unwrap();
    for args in [
        vec!["scan", "missing"],
        vec!["scan", "--format", "secret-canary"],
        vec!["scan", "--staged", "--history"],
        vec!["scan", "--max-file-bytes", "0", "."],
    ] {
        let o = run(d.path(), &args);
        assert_eq!(o.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&o.stderr).contains("secret-canary"));
    }
    fs::write(d.path().join("clean.txt"), "safe").unwrap();
    let o = run(
        d.path(),
        &["scan", "clean.txt", "--output", "missing/report.json"],
    );
    assert_eq!(o.status.code(), Some(2));
}
#[cfg(unix)]
#[test]
fn symlinks_are_skipped_and_git_internals_excluded() {
    let d = tempdir().unwrap();
    fs::create_dir(d.path().join(".git")).unwrap();
    fs::write(d.path().join(".git/config"), token()).unwrap();
    fs::write(d.path().join("clean.txt"), "safe").unwrap();
    std::os::unix::fs::symlink(".git/config", d.path().join("link")).unwrap();
    let o = run(d.path(), &["scan", ".", "--format", "json"]);
    assert_eq!(o.status.code(), Some(0));
    let r: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(r["scanned_files"], 1);
    assert_eq!(r["skipped"][0]["reason"], "symlink");
}
#[cfg(unix)]
#[test]
fn workflow_commands_cannot_be_injected_by_paths() {
    let d = tempdir().unwrap();
    let name = "evil%,file\n::error::injected.txt";
    fs::write(d.path().join(name), token()).unwrap();
    let o = run(d.path(), &["scan", name, "--format", "annotations"]);
    assert_eq!(o.status.code(), Some(1));
    let text = String::from_utf8(o.stdout).unwrap();
    assert_eq!(text.lines().filter(|s| s.starts_with("::error")).count(), 1);
    assert!(text.contains("%25%2Cfile%0A"));
    let o = run(d.path(), &["scan", name, "--format", "sarif"]);
    let s: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(
        s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap()
            .contains("%0A")
    );
}
