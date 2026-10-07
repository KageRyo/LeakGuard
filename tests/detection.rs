use leakguard::{detect::detect, model::Confidence};

fn github() -> String {
    format!("ghp_{}", "Ab3xY9kLm2NqR7sTu4VwZ8cDe5FgH6jIp0KlMnOp")
}
#[test]
fn provider_families_detect_without_exposing_values() {
    for (rule, value) in [
        ("aws-access-key", format!("AKIA{}", "Q7X3Z9M2L8P5R4S6")),
        ("github-token", github()),
        (
            "github-token",
            format!("github_pat_{}", "AbCd1234".repeat(11)),
        ),
        ("openai-key", format!("sk-proj-{}", "AbCd1234".repeat(6))),
        ("google-api-key", format!("AIza{}", "AbCd123".repeat(5))),
        ("private-key", "-----BEGIN RSA PRIVATE KEY-----".into()),
        (
            "database-url",
            "postgresql://alice:veryprivate@db/app".into(),
        ),
    ] {
        let found = detect("src/app.rs", &value);
        assert_eq!(found.len(), 1, "{rule}");
        assert_eq!(found[0].rule_id, rule);
        assert_eq!(found[0].confidence, Confidence::High);
        assert!(!serde_json::to_string(&found).unwrap().contains(&value));
    }
}
#[test]
fn contexts_include_json_yaml_assignments_and_headers() {
    for text in [
        "password = 'aaaaaa'",
        "\"api_key\": \"sensitive-value\"",
        "secret: aaaaaa",
        "Authorization: Basic YWxpY2U6cGFzc3dvcmQ=",
        "Authorization: Bearer abcdef123456",
        "PRIVATE_KEY=someprivatevalue",
    ] {
        let f = detect("config.local", text);
        assert_eq!(f.len(), 1, "missing contextual candidate");
        assert!(f[0].score >= 55);
    }
}
#[test]
fn entropy_and_artifact_evidence_increase_score_and_deduplicate() {
    let text = format!("api_key = '{}'", github());
    let f = detect("logs/debug.log", &text);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].score, 100);
    assert_eq!(f[0].rule_id, "github-token");
    assert!(f[0].reasons.iter().any(|r| r.contains("entropy")));
    assert!(f[0].reasons.iter().any(|r| r.contains("context")));
    assert!(f[0].reasons.iter().any(|r| r.contains("artifact")));
}
#[test]
fn suppress_placeholders_but_not_low_entropy_passwords() {
    for text in [
        "token=${TOKEN}",
        "password='<your-token>'",
        "secret: changeme",
        "api_key=your_api_key",
        "token: null",
        "token=",
        "token=''",
    ] {
        assert!(detect(".env", text).is_empty(), "placeholder detected");
    }
    assert_eq!(detect("test.json", "password=aaaaaaaa")[0].score, 60);
}
#[test]
fn benign_hashes_and_context_words_do_not_trigger() {
    assert!(
        detect(
            "src/code.rs",
            "let digest = 'd8c70e7460a35b982ac945701bc85761'; // password authorization token"
        )
        .is_empty()
    );
    assert!(detect("README.md", &github()).len() == 1);
}
#[test]
fn unicode_positions_count_code_points() {
    let f = detect("a.txt", &format!("first\n中😀 {}", github()));
    assert_eq!((f[0].line, f[0].column), (2, 4));
}
#[test]
fn structurally_valid_jwt_and_invalid_lookalikes() {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl";
    let f = detect("a.txt", jwt);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].rule_id, "jwt");
    assert_eq!(f[0].confidence, Confidence::Medium);
    assert!(detect("a.txt", "eyJnotjson.abcd.abcdefgh").is_empty());
}

#[test]
fn bare_authorization_prefixes_and_yaml_markers_are_not_material() {
    for input in [
        "Authorization: Basic",
        "Authorization: Bearer",
        "token=Bearer",
        "password: |",
        "password: >-",
    ] {
        assert!(
            detect("a.yml", input).is_empty(),
            "bare credential marker detected"
        );
    }
}

#[test]
fn common_prefixed_environment_credentials_have_context() {
    for input in [
        "DB_PASSWORD=aaaaaa",
        "client_secret=aaaaaa",
        "AWS_SECRET_ACCESS_KEY=aaaaaa",
        "OPENAI_API_KEY=aaaaaa",
    ] {
        let f = detect(".env", input);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].score, 60);
    }
}

#[test]
fn overlapping_known_rules_preserve_each_pattern_reason() {
    let input = format!("postgres://alice:{}@db/app", github());
    let f = detect("a.txt", &input);
    assert_eq!(f.len(), 1);
    assert!(f[0].reasons.iter().any(|r| r.contains("database-url")));
    assert!(f[0].reasons.iter().any(|r| r.contains("github-token")));
}
