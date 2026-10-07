use clap::ValueEnum;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}
impl Confidence {
    pub fn from_score(score: u8) -> Self {
        if score >= 70 {
            Self::High
        } else if score >= 40 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub name: String,
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub score: u8,
    pub confidence: Confidence,
    pub reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub path: String,
    pub reason: String,
}
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub mode: String,
    pub scanned_files: usize,
    pub scanned_artifacts: usize,
    pub skipped: Vec<Skipped>,
    pub warnings: Vec<String>,
    pub findings: Vec<Finding>,
}
impl Report {
    pub fn fails(&self, threshold: Confidence) -> bool {
        self.findings.iter().any(|f| f.confidence >= threshold)
    }
}
