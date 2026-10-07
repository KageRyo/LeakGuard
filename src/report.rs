use crate::model::{Confidence, Report};
use clap::ValueEnum;
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Format {
    Text,
    Json,
    Sarif,
    Annotations,
}
pub fn terminal(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
fn command_data(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}
fn command_property(value: &str) -> String {
    command_data(value).replace(':', "%3A").replace(',', "%2C")
}
fn uri(path: &str) -> String {
    let drive = path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && path.as_bytes().get(1) == Some(&b':')
        && path.as_bytes().get(2) == Some(&b'/');
    let encoded: String = path
        .bytes()
        .enumerate()
        .map(|(i, b)| {
            if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) || (drive && i == 1) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    if drive {
        format!("file:///{encoded}")
    } else if path.starts_with("//") {
        format!("file:{encoded}")
    } else if path.starts_with('/') {
        format!("file://{encoded}")
    } else {
        encoded
    }
}
pub fn render(report: &Report, format: Format, threshold: Confidence) -> String {
    match format {
        Format::Json => serde_json::to_string_pretty(report).expect("serializable report") + "\n",
        Format::Text => {
            let state = if report.fails(threshold) {
                "FAIL"
            } else if report.findings.is_empty() {
                "PASS"
            } else {
                "WARNING"
            };
            let mut text = format!(
                "{state}: {} files scanned, {} artifact/config files, {} potential secrets, {} skipped\n",
                report.scanned_files,
                report.scanned_artifacts,
                report.findings.len(),
                report.skipped.len()
            );
            for f in &report.findings {
                text.push_str(&format!(
                    "{:?} {}:{}:{} {} score={}{}\n  {}\n",
                    f.confidence,
                    terminal(&f.path),
                    f.line,
                    f.column,
                    f.name,
                    f.score,
                    f.commit
                        .as_ref()
                        .map(|c| format!(" commit={c}"))
                        .unwrap_or_default(),
                    f.reasons.join("; ")
                ));
            }
            for s in &report.skipped {
                text.push_str(&format!("SKIP {}: {}\n", terminal(&s.path), s.reason));
            }
            for warning in &report.warnings {
                text.push_str(&format!("WARNING: {}\n", terminal(warning)));
            }
            text
        }
        Format::Annotations => {
            let mut text = String::new();
            for f in &report.findings {
                let level = if f.confidence >= threshold {
                    "error"
                } else {
                    "warning"
                };
                let message = format!(
                    "{} ({:?}, score={}){}: {}",
                    f.name,
                    f.confidence,
                    f.score,
                    f.commit
                        .as_ref()
                        .map(|c| format!(" commit={c}"))
                        .unwrap_or_default(),
                    f.reasons.join("; ")
                );
                text.push_str(&format!(
                    "::{level} file={},line={},col={},title=LeakGuard::{}\n",
                    command_property(&f.path),
                    f.line,
                    f.column,
                    command_data(&message)
                ));
            }
            for s in &report.skipped {
                text.push_str(&format!(
                    "::warning title=LeakGuard skipped input::{}: {}\n",
                    command_data(&s.path),
                    s.reason
                ));
            }
            for warning in &report.warnings {
                text.push_str(&format!(
                    "::warning title=LeakGuard::{}\n",
                    command_data(warning)
                ));
            }
            text.push_str(&format!(
                "LeakGuard: {} files scanned; {} potential secrets; {} skipped\n",
                report.scanned_files,
                report.findings.len(),
                report.skipped.len()
            ));
            text
        }
        Format::Sarif => {
            let mut rules = BTreeMap::new();
            for f in &report.findings {
                rules.insert(f.rule_id.clone(), f.name.clone());
            }
            let rule_ids: Vec<_> = rules.keys().cloned().collect();
            let descriptors: Vec<_> = rules
                .iter()
                .map(|(id, name)| json!({"id":id,"shortDescription":{"text":name}}))
                .collect();
            let results: Vec<_> = report.findings.iter().map(|f| json!({
                "ruleId": f.rule_id, "ruleIndex": rule_ids.binary_search(&f.rule_id).expect("known rule"),
                "level": if f.confidence >= threshold {"error"} else {"warning"},
                "message": {"text": format!("{}: {}", f.name, f.reasons.join("; "))},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri(&f.path)}, "region": {"startLine": f.line, "startColumn": f.column}}}],
                "properties": {"score":f.score,"confidence":f.confidence,"commit":f.commit}
            })).collect();
            let notifications: Vec<_> = report.skipped.iter().map(|s| json!({"level":"warning","message":{"text":format!("Skipped {}: {}", s.path, s.reason)}}))
                .chain(report.warnings.iter().map(|w| json!({"level":"warning","message":{"text":w}}))).collect();
            serde_json::to_string_pretty(&json!({
                "$schema":"https://json.schemastore.org/sarif-2.1.0.json", "version":"2.1.0",
                "runs":[{"tool":{"driver":{"name":"LeakGuard","version":env!("CARGO_PKG_VERSION"),"informationUri":"https://github.com/KageRyo/LeakGuard","rules":descriptors}},
                    "columnKind":"unicodeCodePoints", "results":results,
                    "invocations":[{"executionSuccessful":true,"toolExecutionNotifications":notifications}],
                    "properties":{"mode":report.mode,"scannedFiles":report.scanned_files,"scannedArtifacts":report.scanned_artifacts,"skippedCount":report.skipped.len()}}]
            })).expect("serializable SARIF") + "\n"
        }
    }
}
