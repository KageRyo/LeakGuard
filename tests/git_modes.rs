use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::{TempDir, tempdir};
fn git(root: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "git setup failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap().trim().into()
}
fn repo() -> TempDir {
    let d = tempdir().unwrap();
    git(d.path(), &["init", "-q"]);
    git(d.path(), &["config", "user.email", "test@example.invalid"]);
    git(d.path(), &["config", "user.name", "Test"]);
    d
}
fn token() -> String {
    format!("ghp_{}", "Ab3xY9kLm2NqR7sTu4VwZ8cDe5FgH6jIp0KlMnOp")
}
fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .current_dir(root)
        .args(["scan", "--format", "json"])
        .args(args)
        .output()
        .unwrap()
}
fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap()
}
fn commit(root: &Path) {
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "fixture"]);
}
#[test]
fn default_reads_tracked_worktree_and_staged_reads_changed_index() {
    let d = repo();
    fs::write(d.path().join("a.txt"), "safe").unwrap();
    commit(d.path());
    fs::write(d.path().join("a.txt"), token()).unwrap();
    git(d.path(), &["add", "a.txt"]);
    fs::write(d.path().join("a.txt"), "safe").unwrap();
    fs::write(d.path().join("untracked.txt"), token()).unwrap();
    assert_eq!(run(d.path(), &[]).status.code(), Some(0));
    let o = run(d.path(), &["--staged"]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(json(&o)["scanned_files"], 1);
    fs::write(d.path().join("a.txt"), "safe").unwrap();
    git(d.path(), &["add", "a.txt"]);
    assert_eq!(json(&run(d.path(), &["--staged"]))["scanned_files"], 0);
}
#[test]
fn default_sees_unstaged_secret_and_missing_tracked_file_is_a_skip() {
    let d = repo();
    fs::write(d.path().join("a.txt"), "safe").unwrap();
    commit(d.path());
    fs::write(d.path().join("a.txt"), token()).unwrap();
    assert_eq!(run(d.path(), &[]).status.code(), Some(1));
    fs::remove_file(d.path().join("a.txt")).unwrap();
    let o = run(d.path(), &[]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(json(&o)["skipped"].as_array().unwrap().len(), 1);
}
#[test]
fn history_finds_removed_secret_and_deduplicates_unchanged_blob() {
    let d = repo();
    fs::write(d.path().join("a.txt"), token()).unwrap();
    commit(d.path());
    fs::write(d.path().join("other.txt"), "safe").unwrap();
    commit(d.path());
    fs::remove_file(d.path().join("a.txt")).unwrap();
    commit(d.path());
    let o = run(d.path(), &["--history"]);
    assert_eq!(o.status.code(), Some(1));
    let j = json(&o);
    assert_eq!(j["findings"].as_array().unwrap().len(), 1);
    assert_eq!(j["findings"][0]["commit"].as_str().unwrap().len(), 40);
    assert_eq!(run(d.path(), &[]).status.code(), Some(0));
}
#[test]
fn diff_reports_added_lines_ignores_existing_secrets_and_handles_renames() {
    let d = repo();
    fs::write(d.path().join("old.txt"), format!("{}\nsafe\n", token())).unwrap();
    commit(d.path());
    let base = git(d.path(), &["rev-parse", "HEAD"]);
    git(d.path(), &["mv", "old.txt", "renamed file.txt"]);
    fs::write(
        d.path().join("renamed file.txt"),
        format!("{}\nsafe\n{}\n", token(), token()),
    )
    .unwrap();
    commit(d.path());
    let o = run(d.path(), &["--diff", &base]);
    assert_eq!(o.status.code(), Some(1));
    let j = json(&o);
    assert_eq!(j["findings"].as_array().unwrap().len(), 1);
    assert_eq!(j["findings"][0]["line"], 3);
    assert_eq!(j["findings"][0]["path"], "renamed file.txt");
    let base = git(d.path(), &["rev-parse", "HEAD"]);
    fs::remove_file(d.path().join("renamed file.txt")).unwrap();
    commit(d.path());
    let o = run(d.path(), &["--diff", &base]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(json(&o)["scanned_files"], 0);
}
#[cfg(unix)]
#[test]
fn unusual_paths_symlinks_and_size_limits_are_safe_in_git_modes() {
    let d = repo();
    let name = "-a\n$(touch SHOULD_NOT_EXIST).txt";
    fs::write(d.path().join(name), token()).unwrap();
    std::os::unix::fs::symlink(name, d.path().join("link")).unwrap();
    commit(d.path());
    let o = run(d.path(), &["--history"]);
    assert_eq!(o.status.code(), Some(1));
    let j = json(&o);
    assert_eq!(j["findings"][0]["path"], name);
    assert_eq!(j["skipped"][0]["reason"], "symlink");
    assert!(!d.path().join("SHOULD_NOT_EXIST").exists());
    let o = run(d.path(), &["--history", "--max-file-bytes", "8"]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(json(&o)["scanned_files"], 0);
}
#[test]
fn git_errors_fail_without_echoing_revision() {
    let d = repo();
    fs::write(d.path().join("a.txt"), "safe").unwrap();
    commit(d.path());
    for rev in ["secret-canary", "--output=secret-canary"] {
        let o = run(d.path(), &["--diff", rev]);
        assert_eq!(o.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&o.stderr).contains("secret-canary"));
    }
    let other = tempdir().unwrap();
    assert_eq!(run(other.path(), &[]).status.code(), Some(2));
}
#[test]
fn shallow_history_is_explicit_and_subdirectories_scan_repository_root() {
    let d = repo();
    fs::write(d.path().join("a.txt"), "safe").unwrap();
    commit(d.path());
    fs::write(d.path().join("a.txt"), token()).unwrap();
    commit(d.path());
    let clone = tempdir().unwrap();
    git(
        clone.path(),
        &[
            "clone",
            "-q",
            "--depth",
            "1",
            &format!("file://{}", d.path().display()),
            "copy",
        ],
    );
    let o = run(&clone.path().join("copy"), &["--history"]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(json(&o)["warnings"].as_array().unwrap().len(), 1);
    fs::create_dir(d.path().join("sub")).unwrap();
    let o = run(&d.path().join("sub"), &[]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(json(&o)["findings"][0]["path"], "a.txt");
}

#[test]
fn unborn_index_and_staged_deletion() {
    let d = repo();
    fs::write(d.path().join("a.txt"), token()).unwrap();
    git(d.path(), &["add", "a.txt"]);
    assert_eq!(run(d.path(), &["--staged"]).status.code(), Some(1));
    commit(d.path());
    git(d.path(), &["rm", "a.txt"]);
    let o = run(d.path(), &["--staged"]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(json(&o)["scanned_files"], 0);
}

#[test]
fn diff_ignores_configured_interhunk_context() {
    let d = repo();
    fs::write(
        d.path().join("a.txt"),
        format!("old\n{}\nsafe\nold\n", token()),
    )
    .unwrap();
    commit(d.path());
    let base = git(d.path(), &["rev-parse", "HEAD"]);
    fs::write(
        d.path().join("a.txt"),
        format!("new\n{}\nsafe\nnew\n", token()),
    )
    .unwrap();
    commit(d.path());
    git(d.path(), &["config", "diff.interHunkContext", "10"]);
    let o = run(d.path(), &["--diff", &base]);
    assert_eq!(o.status.code(), Some(0));
    assert!(json(&o)["findings"].as_array().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn repository_root_ending_with_newline_and_literal_pathspecs() {
    let outer = tempdir().unwrap();
    let root = outer.path().join("repo\n");
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "-q"]);
    git(&root, &["config", "user.email", "test@example.invalid"]);
    git(&root, &["config", "user.name", "Test"]);
    let name = "[brackets]:colon.txt";
    fs::write(root.join(name), "safe").unwrap();
    commit(&root);
    let base = git(&root, &["rev-parse", "HEAD"]);
    fs::write(root.join(name), token()).unwrap();
    commit(&root);
    let o = run(&root, &["--diff", &base]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(json(&o)["findings"][0]["path"], name);
}

#[test]
fn text_marked_binary_by_git_attributes_is_still_scanned_in_diff() {
    let d = repo();
    fs::write(d.path().join(".gitattributes"), "*.txt -diff\n").unwrap();
    fs::write(d.path().join("a.txt"), "safe").unwrap();
    commit(d.path());
    let base = git(d.path(), &["rev-parse", "HEAD"]);
    fs::write(d.path().join("a.txt"), token()).unwrap();
    commit(d.path());
    let o = run(d.path(), &["--diff", &base]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(json(&o)["findings"][0]["line"], 1);
}

#[test]
fn renamed_file_line_selection_does_not_include_new_source_directory() {
    let d = repo();
    let old = format!("{}\n{}", token(), "safe\n".repeat(30));
    fs::write(d.path().join("a"), &old).unwrap();
    commit(d.path());
    let base = git(d.path(), &["rev-parse", "HEAD"]);
    git(d.path(), &["mv", "a", "b"]);
    fs::write(d.path().join("b"), format!("{old}extra safe\n")).unwrap();
    fs::create_dir(d.path().join("a")).unwrap();
    fs::write(d.path().join("a/x"), "new safe\n").unwrap();
    commit(d.path());
    let o = run(d.path(), &["--diff", &base]);
    assert_eq!(o.status.code(), Some(0));
    assert!(json(&o)["findings"].as_array().unwrap().is_empty());
}

#[test]
fn oversized_base_line_does_not_hide_small_destination_secret() {
    let d = repo();
    fs::write(d.path().join("a.txt"), "x".repeat(2 * 1024 * 1024)).unwrap();
    commit(d.path());
    let base = git(d.path(), &["rev-parse", "HEAD"]);
    fs::write(d.path().join("a.txt"), token()).unwrap();
    commit(d.path());
    let o = run(d.path(), &["--diff", &base, "--max-file-bytes", "128"]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(json(&o)["scanned_files"], 1);
}

#[test]
fn unmerged_index_is_an_error() {
    let d = repo();
    fs::write(d.path().join("a.txt"), "base\n").unwrap();
    commit(d.path());
    let main = git(d.path(), &["branch", "--show-current"]);
    git(d.path(), &["checkout", "-qb", "other"]);
    fs::write(d.path().join("a.txt"), "other\n").unwrap();
    commit(d.path());
    git(d.path(), &["checkout", "-q", &main]);
    fs::write(d.path().join("a.txt"), "main\n").unwrap();
    commit(d.path());
    let merge = Command::new("git")
        .current_dir(d.path())
        .args(["merge", "other"])
        .output()
        .unwrap();
    assert!(!merge.status.success());
    assert_eq!(run(d.path(), &["--staged"]).status.code(), Some(2));
    assert_eq!(run(d.path(), &[]).status.code(), Some(2));
}

#[test]
fn pure_rename_does_not_report_existing_secret() {
    let d = repo();
    fs::write(d.path().join("a.txt"), token()).unwrap();
    commit(d.path());
    let base = git(d.path(), &["rev-parse", "HEAD"]);
    git(d.path(), &["mv", "a.txt", "b.txt"]);
    commit(d.path());
    let o = run(d.path(), &["--diff", &base]);
    assert_eq!(o.status.code(), Some(0));
    assert!(json(&o)["findings"].as_array().unwrap().is_empty());
}

#[test]
fn divergent_base_removal_does_not_make_retained_credential_a_pr_addition() {
    let d = repo();
    fs::write(d.path().join("existing.txt"), token()).unwrap();
    commit(d.path());
    let main = git(d.path(), &["branch", "--show-current"]);
    git(d.path(), &["checkout", "-qb", "pr"]);
    fs::write(d.path().join("pr.txt"), "safe change\n").unwrap();
    commit(d.path());
    git(d.path(), &["checkout", "-q", &main]);
    fs::write(
        d.path().join("existing.txt"),
        "credential removed upstream\n",
    )
    .unwrap();
    commit(d.path());
    git(d.path(), &["checkout", "-q", "pr"]);
    let o = run(d.path(), &["--diff", &main]);
    assert_eq!(o.status.code(), Some(0));
    assert!(json(&o)["findings"].as_array().unwrap().is_empty());
    assert_eq!(json(&o)["scanned_files"], 1);
}

#[test]
fn divergent_base_still_detects_credentials_introduced_by_pr() {
    let d = repo();
    fs::write(d.path().join("existing.txt"), token()).unwrap();
    commit(d.path());
    let main = git(d.path(), &["branch", "--show-current"]);
    git(d.path(), &["checkout", "-qb", "pr"]);
    let new_token = format!("ghs_{}", "Z9x8C7v6B5n4M3a2S1d0F9g8H7j6K5l4P3q2R1s0");
    fs::write(d.path().join("pr.txt"), format!("safe\n{new_token}\n")).unwrap();
    commit(d.path());
    git(d.path(), &["checkout", "-q", &main]);
    fs::write(
        d.path().join("existing.txt"),
        "credential removed upstream\n",
    )
    .unwrap();
    commit(d.path());
    git(d.path(), &["checkout", "-q", "pr"]);
    let o = run(d.path(), &["--diff", &main]);
    assert_eq!(o.status.code(), Some(1));
    let r = json(&o);
    assert_eq!(r["findings"].as_array().unwrap().len(), 1);
    assert_eq!(r["findings"][0]["path"], "pr.txt");
    assert_eq!(r["findings"][0]["line"], 2);
    assert!(!String::from_utf8_lossy(&o.stdout).contains(&new_token));
}

#[test]
fn unrelated_history_has_no_merge_base_and_fails_closed() {
    let d = repo();
    fs::write(d.path().join("a.txt"), "safe").unwrap();
    commit(d.path());
    let base = git(d.path(), &["rev-parse", "HEAD"]);
    git(d.path(), &["checkout", "--orphan", "unrelated"]);
    git(d.path(), &["rm", "-rf", "."]);
    fs::write(d.path().join("b.txt"), "safe").unwrap();
    commit(d.path());
    let o = run(d.path(), &["--diff", &base]);
    assert_eq!(o.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&o.stderr).contains(&base));
    assert!(o.stdout.is_empty());
}
