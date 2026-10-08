use crate::{
    detect::known_rule,
    input::path_string,
    model::{Report, SuppressedFinding, Suppression, SuppressionKind},
};
use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use std::{
    fs,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
};

pub const FILE_NAME: &str = ".leakguard.toml";
const MARKER: &str = "leakguard:allow";
const READ_ERROR: &str = "cannot read suppression config";

/// True when a physical line carries the exact, case-sensitive inline marker.
pub fn inline_marker(line: &str) -> bool {
    line.contains(MARKER)
}
/// Resolves `.` and `..` lexically, without touching the filesystem.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                } else if !out.has_root() {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    out
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    allow: Vec<RawEntry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    paths: Option<Vec<String>>,
    rules: Option<Vec<String>>,
    reason: Option<String>,
}
struct Entry {
    paths: Option<GlobSet>,
    rules: Option<Vec<String>>,
    reason: String,
}
pub struct Config {
    file: PathBuf,
    dir: PathBuf,
    entries: Vec<Entry>,
}

fn parse(text: &str) -> Result<Vec<RawEntry>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    toml::from_str::<RawConfig>(text)
        .map(|c| c.allow)
        // Report only the line: TOML messages can quote config content.
        .map_err(|e| match e.span() {
            Some(span) => {
                let line = text.as_bytes()[..span.start.min(text.len())]
                    .iter()
                    .filter(|&&b| b == b'\n')
                    .count()
                    + 1;
                format!("invalid suppression config at line {line}")
            }
            None => "invalid suppression config".into(),
        })
}
fn glob(pattern: &str) -> Result<Glob, &'static str> {
    let bytes = pattern.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if pattern.starts_with(['/', '\\']) || drive || pattern.split('/').any(|c| c == "..") {
        return Err("must be a relative path without ..");
    }
    // A gitignore-style directory pattern would silently match no file.
    if pattern.ends_with('/') {
        return Err("must not end with /; use a /** suffix");
    }
    let cleaned = pattern
        .split('/')
        .filter(|c| *c != ".")
        .collect::<Vec<_>>()
        .join("/");
    if cleaned.is_empty() {
        return Err("must not be empty");
    }
    GlobBuilder::new(&cleaned)
        .literal_separator(true)
        .build()
        .map_err(|_| "is not a valid glob")
}
fn compile(i: usize, raw: RawEntry) -> Result<Entry, String> {
    let fail = |detail: String| format!("invalid suppression config: allow[{i}]{detail}");
    if raw.paths.is_none() && raw.rules.is_none() {
        return Err(fail(" requires paths or rules".into()));
    }
    let reason = raw
        .reason
        .map(|r| r.trim().to_owned())
        .filter(|r| !r.is_empty())
        .ok_or_else(|| fail(" requires reason".into()))?;
    let paths = match raw.paths {
        None => None,
        Some(patterns) if patterns.is_empty() => {
            return Err(fail(".paths must not be empty".into()));
        }
        Some(patterns) => {
            let mut set = GlobSetBuilder::new();
            for (j, p) in patterns.iter().enumerate() {
                set.add(glob(p).map_err(|detail| fail(format!(".paths[{j}] {detail}")))?);
            }
            Some(
                set.build()
                    .map_err(|_| fail(".paths is not a valid glob set".into()))?,
            )
        }
    };
    let rules = match raw.rules {
        None => None,
        Some(rules) if rules.is_empty() => {
            return Err(fail(".rules must not be empty".into()));
        }
        Some(rules) => {
            if let Some(j) = rules.iter().position(|r| !known_rule(r)) {
                return Err(fail(format!(".rules[{j}] is not a known rule")));
            }
            Some(rules)
        }
    };
    Ok(Entry {
        paths,
        rules,
        reason,
    })
}

impl Config {
    /// Loads `explicit`, or `.leakguard.toml` under `root` when it exists.
    pub fn load(root: &Path, explicit: Option<&Path>) -> Result<Option<Self>, String> {
        let current = std::env::current_dir().map_err(|_| "cannot determine current directory")?;
        let file = normalize(&match explicit {
            Some(path) => current.join(path),
            None => root.join(FILE_NAME),
        });
        // Like scanned inputs, a linked config is never followed.
        let metadata = match fs::symlink_metadata(&file) {
            Ok(m) => m,
            Err(e) if explicit.is_none() && e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(READ_ERROR.into()),
        };
        if !metadata.is_file() {
            return Err(READ_ERROR.into());
        }
        let text = fs::read(&file)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or(READ_ERROR)?;
        let entries = parse(&text)?
            .into_iter()
            .enumerate()
            .map(|(i, raw)| compile(i, raw))
            .collect::<Result<_, _>>()?;
        let dir = file.parent().map(Path::to_path_buf).unwrap_or_default();
        Ok(Some(Self { file, dir, entries }))
    }
    /// Returns the first matching entry's reason; `rel_path` is `None` outside the config directory.
    pub fn matches(&self, rel_path: Option<&str>, rule_id: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| {
                e.paths
                    .as_ref()
                    .is_none_or(|set| rel_path.is_some_and(|p| set.is_match(p)))
                    && e.rules
                        .as_ref()
                        .is_none_or(|rules| rules.iter().any(|r| r == rule_id))
            })
            .map(|e| e.reason.as_str())
    }
    /// Moves config-matched findings to `report.suppressed`; relative paths resolve against `base`.
    pub fn apply(&self, report: &mut Report, base: &Path) {
        for f in std::mem::take(&mut report.findings) {
            let absolute = normalize(&base.join(&f.path));
            let rel = absolute
                .strip_prefix(&self.dir)
                .ok()
                .and_then(|p| path_string(p).ok());
            match self.matches(rel.as_deref(), &f.rule_id) {
                Some(reason) => report.suppressed.push(SuppressedFinding {
                    suppression: Suppression {
                        kind: SuppressionKind::Config,
                        reason: Some(reason.into()),
                    },
                    finding: f,
                }),
                None => report.findings.push(f),
            }
        }
    }
    /// The config file's repository-relative path when it lies inside `root`.
    pub fn repo_path(&self, root: &Path) -> Option<String> {
        self.file
            .strip_prefix(normalize(root))
            .ok()
            .and_then(|p| path_string(p).ok())
    }
}
