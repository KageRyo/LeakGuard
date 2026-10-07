use crate::model::{Confidence, Finding};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use regex::Regex;
use std::{collections::BTreeMap, sync::LazyLock};

struct Rule {
    id: &'static str,
    name: &'static str,
    regex: Regex,
    base: u8,
}
static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    [
        ("aws-access-key", "AWS access key ID", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", 70),
        ("github-token", "GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{80,255})\b", 70),
        ("openai-key", "OpenAI-style API key", r"\bsk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,255}\b", 70),
        ("google-api-key", "Google API key", r"\bAIza[A-Za-z0-9_-]{35}\b", 70),
        ("private-key", "PEM private key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", 70),
        ("database-url", "Database URL with password", r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|mssql)://[^\s/:@]+:[^\s/@]+@[^\s\x22\x27]+", 70),
        ("jwt", "Structurally plausible JWT", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", 30),
    ].into_iter().map(|(id, name, pattern, base)| Rule { id, name, regex: Regex::new(pattern).expect("static rule"), base }).collect()
});
static CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r#"(?i)\b(?:api[_-]?key|access[_-]?token|token|password|passwd|secret|private[_-]?key|authorization)\b["']?\s*[:=]\s*(?:(?:bearer|basic)\s+)?(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s,;}\]]+))"#
).expect("static context")
});
static BEARER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bbearer\s+([A-Za-z0-9_.~+/=-]{6,})").expect("static bearer")
});

pub fn is_artifact(path: &str) -> bool {
    let p = path.to_ascii_lowercase().replace('\\', "/");
    p.split('/').any(|s| {
        matches!(
            s,
            "logs" | "artifacts" | "snapshots" | "fixtures" | "generated"
        )
    }) || [
        ".log",
        ".env",
        ".local",
        ".json",
        ".yaml",
        ".yml",
        ".ipynb",
        "test-output.txt",
    ]
    .iter()
    .any(|s| p.ends_with(s))
        || p.rsplit('/').next().is_some_and(|s| s.starts_with(".env."))
}
fn placeholder(value: &str) -> bool {
    let v = value.trim().trim_matches(['\'', '"']).to_ascii_lowercase();
    v.is_empty()
        || v.starts_with("${")
        || v.starts_with("{{")
        || v.starts_with('<')
        || v.starts_with("your_")
        || v.starts_with("your-")
        || matches!(
            v.as_str(),
            "null"
                | "none"
                | "true"
                | "false"
                | "changeme"
                | "change_me"
                | "example"
                | "placeholder"
                | "redacted"
                | "[redacted]"
                | "********"
        )
}
fn entropy(value: &str) -> f64 {
    let mut counts = BTreeMap::new();
    for c in value.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let n = value.chars().count() as f64;
    counts
        .values()
        .map(|&count| {
            let p = count as f64 / n;
            -p * p.log2()
        })
        .sum()
}
fn jwt_valid(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let decode = |p: &str| {
        URL_SAFE_NO_PAD
            .decode(p)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
    };
    let Some(header) = decode(parts[0]) else {
        return false;
    };
    header.get("alg").is_some_and(|v| v.is_string())
        && decode(parts[1]).is_some_and(|v| v.is_object())
        && URL_SAFE_NO_PAD
            .decode(parts[2])
            .is_ok_and(|b| !b.is_empty())
}
struct Candidate<'a> {
    start: usize,
    end: usize,
    value: &'a str,
    id: &'static str,
    name: &'static str,
    base: u8,
    context: bool,
}

pub fn detect(path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let mut contexts = Vec::new();
        for caps in CONTEXT.captures_iter(line) {
            let value = (1..=3).find_map(|i| caps.get(i)).expect("value capture");
            if !placeholder(value.as_str()) {
                contexts.push(value);
            }
        }
        for caps in BEARER.captures_iter(line) {
            let value = caps.get(1).expect("bearer value");
            if !placeholder(value.as_str()) {
                contexts.push(value);
            }
        }
        let mut candidates = Vec::new();
        for rule in RULES.iter() {
            for value in rule.regex.find_iter(line) {
                if placeholder(value.as_str()) || (rule.id == "jwt" && !jwt_valid(value.as_str())) {
                    continue;
                }
                // A templated database password is not credential material.
                if rule.id == "database-url" {
                    let password = value
                        .as_str()
                        .split_once("://")
                        .and_then(|(_, v)| v.split_once(':'))
                        .and_then(|(_, v)| v.split_once('@'))
                        .map(|(v, _)| v)
                        .unwrap_or("");
                    if placeholder(password) {
                        continue;
                    }
                }
                candidates.push(Candidate {
                    start: value.start(),
                    end: value.end(),
                    value: value.as_str(),
                    id: rule.id,
                    name: rule.name,
                    base: rule.base,
                    context: contexts
                        .iter()
                        .any(|c| c.start() < value.end() && value.start() < c.end()),
                });
            }
        }
        for value in contexts {
            candidates.push(Candidate {
                start: value.start(),
                end: value.end(),
                value: value.as_str(),
                id: "context-credential",
                name: "Contextual credential",
                base: 30,
                context: true,
            });
        }
        // Stronger recognized rules own overlapping contextual candidates.
        candidates.sort_by_key(|c| (std::cmp::Reverse(c.base), c.start));
        let mut accepted: Vec<(usize, usize)> = Vec::new();
        for c in candidates {
            if accepted.iter().any(|&(s, e)| s < c.end && c.start < e) {
                continue;
            }
            let mut score = c.base;
            let mut reasons = vec![if c.id == "context-credential" {
                "credential candidate".into()
            } else {
                format!("matched {} pattern", c.id)
            }];
            if c.context {
                score += 25;
                reasons.push("credential context".into());
            }
            if c.value.chars().count() >= 20 && entropy(c.value) >= 3.5 {
                score += 15;
                reasons.push("high entropy".into());
            }
            if is_artifact(path) {
                score += 5;
                reasons.push("artifact/config path".into());
            }
            score = score.min(100);
            if c.id == "context-credential" && score < 40 {
                continue;
            }
            accepted.push((c.start, c.end));
            findings.push(Finding {
                rule_id: c.id.into(),
                name: c.name.into(),
                path: path.into(),
                line: line_index + 1,
                column: line[..c.start].chars().count() + 1,
                score,
                confidence: Confidence::from_score(score),
                reasons,
                commit: None,
            });
        }
    }
    findings.sort_by_key(|f| (f.line, f.column));
    findings
}
