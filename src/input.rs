use crate::{
    detect::{detect, is_artifact},
    model::{Report, Skipped},
};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

#[derive(Debug)]
pub struct ScanOptions {
    pub paths: Vec<PathBuf>,
    pub staged: bool,
    pub history: bool,
    pub diff: Option<String>,
    pub max_file_bytes: usize,
}
pub fn skip(report: &mut Report, path: &str, reason: &str) {
    report.skipped.push(Skipped {
        path: path.into(),
        reason: reason.into(),
    });
}
pub fn add_bytes(
    report: &mut Report,
    path: &str,
    bytes: &[u8],
    limit: usize,
    commit: Option<&str>,
    lines: Option<&BTreeSet<usize>>,
) {
    if bytes.len() > limit {
        skip(report, path, "oversized");
        return;
    }
    if bytes.contains(&0) {
        skip(report, path, "binary");
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        skip(report, path, "invalid UTF-8");
        return;
    };
    report.scanned_files += 1;
    report.scanned_artifacts += usize::from(is_artifact(path));
    for mut f in detect(path, text) {
        if lines.is_some_and(|set| !set.contains(&f.line)) {
            continue;
        }
        f.commit = commit.map(str::to_owned);
        report.findings.push(f);
    }
}
pub fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(|s| s.replace('\\', "/"))
        .ok_or_else(|| "input path is not valid UTF-8".into())
}
fn git_internal(path: &Path) -> bool {
    path.components()
        .any(|c| c == Component::Normal(".git".as_ref()))
}
fn symlink_ancestor(path: &Path) -> bool {
    path.ancestors()
        .any(|a| fs::symlink_metadata(a).is_ok_and(|m| m.file_type().is_symlink()))
}
fn walk(
    path: &Path,
    seen: &mut BTreeSet<PathBuf>,
    report: &mut Report,
    limit: usize,
    tracked: bool,
) -> Result<(), String> {
    if git_internal(path) {
        return Ok(());
    }
    let label = path_string(path)?;
    // Reject linked ancestors as well as the final component.
    if symlink_ancestor(path) {
        if seen.insert(path.to_path_buf()) {
            skip(report, &label, "symlink");
        }
        return Ok(());
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if tracked && e.kind() == std::io::ErrorKind::NotFound => {
            skip(report, &label, "deleted working-tree file");
            return Ok(());
        }
        Err(_) => return Err("cannot inspect input path".into()),
    };
    if metadata.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)
            .map_err(|_| "cannot list input directory")?
            .map(|e| {
                e.map(|v| v.path())
                    .map_err(|_| "cannot read directory entry")
            })
            .collect::<Result<_, _>>()?;
        entries.sort();
        for entry in entries {
            walk(&entry, seen, report, limit, tracked)?;
        }
    } else if metadata.is_file() {
        let canonical = fs::canonicalize(path).map_err(|_| "cannot resolve input file")?;
        if !seen.insert(canonical) {
            return Ok(());
        }
        if metadata.len() > limit as u64 {
            skip(report, &label, "oversized");
            return Ok(());
        }
        let file = fs::File::open(path).map_err(|_| "cannot open input file")?;
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read input file")?;
        add_bytes(report, &label, &bytes, limit, None, None);
    } else {
        skip(report, &label, "non-regular file");
    }
    Ok(())
}
pub fn scan_tracked_paths(
    report: &mut Report,
    root: &Path,
    paths: Vec<PathBuf>,
    limit: usize,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for path in paths {
        // Keep report paths repository-relative, regardless of invocation directory.
        let old_findings = report.findings.len();
        let old_skips = report.skipped.len();
        walk(&root.join(&path), &mut seen, report, limit, true)?;
        let label = path_string(&path)?;
        for f in &mut report.findings[old_findings..] {
            f.path = label.clone();
        }
        for s in &mut report.skipped[old_skips..] {
            s.path = label.clone();
        }
    }
    Ok(())
}
pub fn scan(options: &ScanOptions) -> Result<Report, String> {
    if options.max_file_bytes == 0 || options.max_file_bytes == usize::MAX {
        return Err("invalid file size limit".into());
    }
    let mut report = if options.paths.is_empty() {
        crate::git::scan_git(options)?
    } else {
        let mut r = Report {
            mode: "paths".into(),
            ..Report::default()
        };
        let mut seen = BTreeSet::new();
        let mut paths = options.paths.clone();
        paths.sort();
        for path in paths {
            walk(&path, &mut seen, &mut r, options.max_file_bytes, false)?;
        }
        r
    };
    report.findings.sort_by(|a, b| {
        (&a.path, a.line, a.column, &a.commit, &a.rule_id)
            .cmp(&(&b.path, b.line, b.column, &b.commit, &b.rule_id))
    });
    report
        .skipped
        .sort_by(|a, b| (&a.path, &a.reason).cmp(&(&b.path, &b.reason)));
    Ok(report)
}
