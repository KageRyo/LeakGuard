use leakguard::{
    detect::detect,
    model::{Confidence, Report},
    report::{Format, render},
};
#[test]
fn windows_absolute_and_unc_locations_are_file_uris() {
    let token = format!("ghp_{}", "Ab3xY9kLm2NqR7sTu4VwZ8cDe5FgH6jIp0KlMnOp");
    for (path, expected) in [
        ("C:/logs/secret%.txt", "file:///C:/logs/secret%25.txt"),
        (
            "//server/share/secret.txt",
            "file://server/share/secret.txt",
        ),
    ] {
        let report = Report {
            findings: detect(path, &token),
            ..Report::default()
        };
        let sarif: serde_json::Value =
            serde_json::from_str(&render(&report, Format::Sarif, Confidence::High)).unwrap();
        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            expected
        );
    }
}
