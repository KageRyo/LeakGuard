use leakguard::{
    detect::detect,
    model::{Report, SuppressionKind},
    suppress::{Config, inline_marker},
};
use std::{fs, path::Path};
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
