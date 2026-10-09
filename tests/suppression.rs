use leakguard::{
    detect::detect,
    model::{Report, SuppressionKind},
    suppress::{Config, inline_marker},
};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;

fn token() -> String {
    format!("ghp_{}", "Ab3xY9kLm2NqR7sTu4VwZ8cDe5FgH6jIp0KlMnOp")
}
fn config(dir: &Path, text: &str) -> Result<Option<Config>, String> {
    fs::write(dir.join(".leakguard.toml"), text).unwrap();
    Config::load(dir, None)
}
fn findings(paths: &[&str]) -> Report {
    Report {
        findings: paths.iter().flat_map(|p| detect(p, &token())).collect(),
        ..Report::default()
    }
}
fn suppressed_paths(report: &Report) -> Vec<&str> {
    report
        .suppressed
        .iter()
        .map(|s| s.finding.path.as_str())
        .collect()
}
#[test]
fn missing_default_config_is_absent_but_explicit_config_is_required() {
    let d = tempdir().unwrap();
    assert!(Config::load(d.path(), None).unwrap().is_none());
    let e = Config::load(d.path(), Some(&d.path().join("missing.toml")))
        .err()
        .unwrap();
    assert_eq!(e, "cannot read suppression config");
}
#[test]
fn globs_match_relative_to_the_config_directory() {
    let d = tempdir().unwrap();
    let c = config(
        d.path(),
        "[[allow]]\npaths = [\"tests/*\", \"./fixtures/**\"]\nreason = \"synthetic\"\n",
    )
    .unwrap()
    .unwrap();
    let mut r = findings(&[
        "tests/a.rs",
        "tests/deep/a.rs",
        "fixtures/x/y.log",
        "src/a.rs",
    ]);
    c.apply(&mut r, d.path());
    assert_eq!(suppressed_paths(&r), ["tests/a.rs", "fixtures/x/y.log"]);
    assert_eq!(r.findings.len(), 2);
    assert_eq!(r.suppressed[0].suppression.kind, SuppressionKind::Config);
    assert_eq!(
        r.suppressed[0].suppression.reason.as_deref(),
        Some("synthetic")
    );
}
#[test]
fn explicit_paths_are_normalized_and_outside_files_match_only_rule_entries() {
    let d = tempdir().unwrap();
    let c = config(
        d.path(),
        "[[allow]]\npaths = [\"logs/**\"]\nreason = \"fixtures\"\n\n[[allow]]\nrules = [\"context-credential\"]\nreason = \"contextual noise\"\n",
    )
    .unwrap()
    .unwrap();
    let absolute = d.path().join("logs/a.log");
    let mut r = findings(&["./logs/a.log", absolute.to_str().unwrap()]);
    c.apply(&mut r, d.path());
    assert_eq!(r.suppressed.len(), 2);
    let sub = d.path().join("sub");
    let mut r = findings(&["../logs/b.log", "../../outside/logs/c.log"]);
    c.apply(&mut r, &sub);
    assert_eq!(suppressed_paths(&r), ["../logs/b.log"]);
    let mut r = Report {
        findings: detect("../../outside/a.txt", "password = 'aaaaaa'"),
        ..Report::default()
    };
    assert_eq!(r.findings[0].rule_id, "context-credential");
    c.apply(&mut r, &sub);
    assert_eq!(
        r.suppressed[0].suppression.reason.as_deref(),
        Some("contextual noise")
    );
}
#[test]
fn entries_require_both_specified_conditions() {
    let d = tempdir().unwrap();
    let c = config(
        d.path(),
        "[[allow]]\npaths = [\"docs/**\"]\nrules = [\"jwt\"]\nreason = \"examples\"\n",
    )
    .unwrap()
    .unwrap();
    let mut r = findings(&["docs/a.md"]);
    c.apply(&mut r, d.path());
    assert!(r.suppressed.is_empty());
    assert_eq!(r.findings.len(), 1);
}
#[test]
fn byte_order_mark_and_empty_config_are_accepted() {
    let d = tempdir().unwrap();
    let c = config(
        d.path(),
        "\u{feff}[[allow]]\nrules = [\"github-token\"]\nreason = \"bom\"\n",
    )
    .unwrap()
    .unwrap();
    let mut r = findings(&["a.txt"]);
    c.apply(&mut r, d.path());
    assert_eq!(r.suppressed.len(), 1);
    let c = config(d.path(), "").unwrap().unwrap();
    let mut r = findings(&["a.txt"]);
    c.apply(&mut r, d.path());
    assert_eq!(r.findings.len(), 1);
}
#[test]
fn invalid_configs_fail_without_quoting_content() {
    let d = tempdir().unwrap();
    let p = "invalid suppression config";
    let relative = format!("{p}: allow[0].paths[0] must be a relative path without ..");
    for (text, expected) in [
        (
            "[[allow]]\nreason = \"r\"\n",
            format!("{p}: allow[0] requires paths or rules"),
        ),
        (
            "[[allow]]\npaths = [\"a\"]\n",
            format!("{p}: allow[0] requires reason"),
        ),
        (
            "[[allow]]\npaths = [\"a\"]\nreason = \"  \"\n",
            format!("{p}: allow[0] requires reason"),
        ),
        (
            "[[allow]]\npaths = []\nreason = \"r\"\n",
            format!("{p}: allow[0].paths must not be empty"),
        ),
        (
            "[[allow]]\nrules = []\nreason = \"r\"\n",
            format!("{p}: allow[0].rules must not be empty"),
        ),
        (
            "[[allow]]\nrules = [\"jwt\", \"CANARY\"]\nreason = \"r\"\n",
            format!("{p}: allow[0].rules[1] is not a known rule"),
        ),
        (
            "[[allow]]\npaths = [\"/CANARY\"]\nreason = \"r\"\n",
            relative.clone(),
        ),
        (
            "[[allow]]\npaths = [\"a/../CANARY\"]\nreason = \"r\"\n",
            relative.clone(),
        ),
        (
            "[[allow]]\npaths = [\"C:/CANARY\"]\nreason = \"r\"\n",
            relative.clone(),
        ),
        (
            "[[allow]]\npaths = [\"CANARY/\"]\nreason = \"r\"\n",
            format!("{p}: allow[0].paths[0] must not end with /; use a /** suffix"),
        ),
        (
            "[[allow]]\npaths = [\".\"]\nreason = \"r\"\n",
            format!("{p}: allow[0].paths[0] must not be empty"),
        ),
        (
            "[[allow]]\npaths = [\"CANARY[\"]\nreason = \"r\"\n",
            format!("{p}: allow[0].paths[0] is not a valid glob"),
        ),
        (
            "[[allow]]\nrules = [\"jwt\"]\nreason = \"r\"\n\n[[allow]]\nrules = [\"jwt\"]\n",
            format!("{p}: allow[1] requires reason"),
        ),
        (
            "[[allow]]\nreason = \"r\"\nCANARY = 1\n",
            format!("{p} at line 3"),
        ),
        ("CANARY = 1\n", format!("{p} at line 1")),
        ("[[allow]\nCANARY", format!("{p} at line 1")),
    ] {
        let e = config(d.path(), text).err().unwrap();
        assert_eq!(e, expected, "{text}");
        assert!(!e.contains("CANARY"));
    }
}
#[test]
fn unreadable_configs_are_errors() {
    let d = tempdir().unwrap();
    fs::write(d.path().join("bad.toml"), [0xff, 0xfe, 0x00]).unwrap();
    let e = Config::load(d.path(), Some(&d.path().join("bad.toml")))
        .err()
        .unwrap();
    assert_eq!(e, "cannot read suppression config");
    fs::create_dir(d.path().join(".leakguard.toml")).unwrap();
    let e = Config::load(d.path(), None).err().unwrap();
    assert_eq!(e, "cannot read suppression config");
}
#[cfg(unix)]
#[test]
fn linked_config_is_never_followed() {
    let d = tempdir().unwrap();
    fs::write(
        d.path().join("real.toml"),
        "[[allow]]\nrules = [\"jwt\"]\nreason = \"r\"\n",
    )
    .unwrap();
    std::os::unix::fs::symlink("real.toml", d.path().join(".leakguard.toml")).unwrap();
    let e = Config::load(d.path(), None).err().unwrap();
    assert_eq!(e, "cannot read suppression config");
}
#[test]
fn inline_marker_is_exact_and_case_sensitive() {
    assert!(inline_marker("token = x # leakguard:allow fixture"));
    assert!(inline_marker("<!-- leakguard:allow -->"));
    assert!(!inline_marker("token = x # LeakGuard:Allow"));
    assert!(!inline_marker("token = x # leakguard: allow"));
}
fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_leakguard"))
        .current_dir(root)
        .arg("scan")
        .args(args)
        .output()
        .unwrap()
}
fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap()
}
#[test]
fn inline_marker_suppresses_every_finding_on_its_line_only() {
    let d = tempdir().unwrap();
    fs::write(
        d.path().join("a.py"),
        format!(
            "pair = ['{t}', '{t}']  # leakguard:allow fixture\n",
            t = token()
        ),
    )
    .unwrap();
    let o = run(d.path(), &["a.py", "--format", "json"]);
    assert_eq!(o.status.code(), Some(0));
    let j = json(&o);
    assert!(j["findings"].as_array().unwrap().is_empty());
    assert_eq!(j["suppressed"].as_array().unwrap().len(), 2);
    assert_eq!(j["suppressed"][0]["suppression"]["kind"], "inline");
    assert!(j["suppressed"][0]["suppression"]["reason"].is_null());
    fs::write(
        d.path().join("b.py"),
        format!("# leakguard:allow\nvalue = '{}'\n", token()),
    )
    .unwrap();
    assert_eq!(run(d.path(), &["b.py"]).status.code(), Some(1));
}
#[test]
fn inline_marker_works_with_any_comment_style_and_crlf_but_is_case_sensitive() {
    let d = tempdir().unwrap();
    for (name, line) in [
        (
            "a.sh",
            format!("TOKEN={} # leakguard:allow\r\nnext\r\n", token()),
        ),
        (
            "a.rs",
            format!("let t = \"{}\"; // leakguard:allow\r\n", token()),
        ),
        (
            "a.html",
            format!("<p>{}</p> <!-- leakguard:allow -->\n", token()),
        ),
    ] {
        fs::write(d.path().join(name), line).unwrap();
        assert_eq!(run(d.path(), &[name]).status.code(), Some(0), "{name}");
    }
    fs::write(
        d.path().join("upper.sh"),
        format!("TOKEN={} # LeakGuard:Allow\n", token()),
    )
    .unwrap();
    assert_eq!(run(d.path(), &["upper.sh"]).status.code(), Some(1));
}
#[test]
fn inline_marker_is_ignored_in_generated_output_but_config_still_applies() {
    let d = tempdir().unwrap();
    // A log line can echo attacker-controlled text next to a leaked token.
    let line = format!("GET /login ua=\"leakguard:allow\" auth={}\n", token());
    for path in [
        "app.log",
        "Build/Test.LOG",
        "logs/a.txt",
        "artifacts/run.txt",
        "snapshots/a.snap",
        "generated/a.rs",
        "out/test-output.txt",
    ] {
        let file = d.path().join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, &line).unwrap();
        assert_eq!(run(d.path(), &[path]).status.code(), Some(1), "{path}");
    }
    for path in ["fixtures/a.txt", "ci.yml", ".env.example", "notes.json"] {
        let file = d.path().join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, &line).unwrap();
        assert_eq!(run(d.path(), &[path]).status.code(), Some(0), "{path}");
    }
    fs::write(
        d.path().join(".leakguard.toml"),
        "[[allow]]\npaths = [\"logs/**\"]\nreason = \"recorded fixtures\"\n",
    )
    .unwrap();
    let o = run(d.path(), &["logs/a.txt", "--format", "json"]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(json(&o)["suppressed"][0]["suppression"]["kind"], "config");
}
#[test]
fn inline_reason_never_reaches_any_report() {
    let d = tempdir().unwrap();
    fs::write(
        d.path().join("a.txt"),
        format!("{} leakguard:allow CANARYREASON\n", token()),
    )
    .unwrap();
    for format in ["text", "json", "sarif", "annotations"] {
        let o = run(d.path(), &["a.txt", "--format", format]);
        assert_eq!(o.status.code(), Some(0), "{format}");
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(!all.contains("CANARYREASON"), "{format}");
        assert!(!all.contains(&token()), "{format}");
    }
}
#[test]
fn default_config_applies_to_explicit_paths_in_any_spelling() {
    let d = tempdir().unwrap();
    // The scanner skips linked ancestors such as macOS /var, so use the physical path.
    #[cfg(unix)]
    let root = fs::canonicalize(d.path()).unwrap();
    #[cfg(not(unix))]
    let root = d.path().to_path_buf();
    fs::create_dir_all(root.join("fixtures/deep")).unwrap();
    fs::write(root.join("fixtures/deep/a.log"), token()).unwrap();
    fs::write(
        root.join(".leakguard.toml"),
        "[[allow]]\npaths = [\"fixtures/**\"]\nreason = \"synthetic logs\"\n",
    )
    .unwrap();
    let absolute = root.join("fixtures/deep/a.log");
    for path in [
        "fixtures",
        "./fixtures/deep/a.log",
        absolute.to_str().unwrap(),
    ] {
        let o = run(&root, &[path, "--format", "json"]);
        assert_eq!(o.status.code(), Some(0), "{path}");
        assert_eq!(
            json(&o)["suppressed"][0]["suppression"]["reason"],
            "synthetic logs"
        );
    }
}
#[test]
fn explicit_config_paths_are_relative_to_its_own_directory() {
    let d = tempdir().unwrap();
    fs::create_dir(d.path().join("conf")).unwrap();
    fs::create_dir(d.path().join("sub")).unwrap();
    fs::write(
        d.path().join("conf/lg.toml"),
        "[[allow]]\npaths = [\"a.txt\"]\nreason = \"conf-relative\"\n",
    )
    .unwrap();
    fs::write(d.path().join("a.txt"), token()).unwrap();
    fs::write(d.path().join("conf/a.txt"), token()).unwrap();
    let o = run(
        d.path(),
        &[
            "a.txt",
            "conf/a.txt",
            "--config",
            "conf/lg.toml",
            "--format",
            "json",
        ],
    );
    assert_eq!(o.status.code(), Some(1));
    let j = json(&o);
    assert_eq!(j["findings"][0]["path"], "a.txt");
    assert_eq!(j["suppressed"][0]["path"], "conf/a.txt");
    let o = run(
        &d.path().join("sub"),
        &["../conf/a.txt", "--config", "../conf/lg.toml"],
    );
    assert_eq!(o.status.code(), Some(0));
}
#[test]
fn inline_marker_takes_precedence_over_config() {
    let d = tempdir().unwrap();
    fs::write(
        d.path().join(".leakguard.toml"),
        "[[allow]]\nrules = [\"github-token\"]\nreason = \"all tokens\"\n",
    )
    .unwrap();
    fs::write(
        d.path().join("a.txt"),
        format!("{} # leakguard:allow\n{}\n", token(), token()),
    )
    .unwrap();
    let j = json(&run(d.path(), &["a.txt", "--format", "json"]));
    assert_eq!(j["suppressed"][0]["suppression"]["kind"], "inline");
    assert_eq!(j["suppressed"][1]["suppression"]["kind"], "config");
    assert_eq!(j["suppressed"][1]["suppression"]["reason"], "all tokens");
}
#[test]
fn config_errors_exit_two_and_unsuppressed_findings_still_fail() {
    let d = tempdir().unwrap();
    fs::write(d.path().join("a.txt"), token()).unwrap();
    let o = run(d.path(), &["a.txt", "--config", "missing.toml"]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&o.stderr),
        "LeakGuard error: cannot read suppression config\n"
    );
    fs::write(
        d.path().join(".leakguard.toml"),
        "[[allow]]\npaths = [\"CANARY\"]\n",
    )
    .unwrap();
    let o = run(d.path(), &["a.txt"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&o.stderr).contains("CANARY"));
    fs::write(
        d.path().join(".leakguard.toml"),
        "[[allow]]\npaths = [\"other.txt\"]\nreason = \"r\"\n",
    )
    .unwrap();
    assert_eq!(run(d.path(), &["a.txt"]).status.code(), Some(1));
}
