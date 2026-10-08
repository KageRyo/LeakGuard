use crate::{
    input::{ScanOptions, add_bytes, scan_tracked_paths, skip},
    model::Report,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn command(root: &Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(root)
        .args(["--no-pager", "--literal-pathspecs"])
        .stderr(Stdio::null());
    c
}
fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let o = command(root)
        .args(args)
        .output()
        .map_err(|_| "cannot execute Git")?;
    if !o.status.success() {
        return Err("Git operation failed; check repository, revision and fetched objects".into());
    }
    Ok(o.stdout)
}
fn string(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes).map_err(|_| "Git metadata is not UTF-8".into())
}
fn nul_strings(bytes: &[u8]) -> Result<Vec<&str>, String> {
    bytes
        .split(|&b| b == 0)
        .filter(|v| !v.is_empty())
        .map(|v| std::str::from_utf8(v).map_err(|_| "Git paths are not UTF-8".into()))
        .collect()
}
fn revision(root: &Path, value: &str) -> Result<String, String> {
    Ok(string(git(
        root,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{value}^{{commit}}"),
        ],
    )?)?
    .trim()
    .into())
}
#[derive(Clone)]
struct Entry {
    mode: String,
    oid: String,
    path: String,
}
fn index(root: &Path) -> Result<Vec<Entry>, String> {
    let bytes = git(root, &["ls-files", "--stage", "-z"])?;
    nul_strings(&bytes)?
        .into_iter()
        .map(|record| {
            let (meta, path) = record
                .split_once('\t')
                .ok_or("invalid Git index metadata")?;
            let fields: Vec<_> = meta.split_whitespace().collect();
            if fields.len() != 3 || fields[2] != "0" {
                return Err("unmerged Git index; resolve conflicts before scanning".into());
            }
            Ok(Entry {
                mode: fields[0].into(),
                oid: fields[1].into(),
                path: path.into(),
            })
        })
        .collect()
}
fn tree(root: &Path, commit: &str) -> Result<Vec<Entry>, String> {
    let bytes = git(root, &["ls-tree", "-r", "-z", commit])?;
    nul_strings(&bytes)?
        .into_iter()
        .map(|record| {
            let (meta, path) = record.split_once('\t').ok_or("invalid Git tree metadata")?;
            let fields: Vec<_> = meta.split_whitespace().collect();
            if fields.len() != 3 {
                return Err("invalid Git tree metadata".into());
            }
            Ok(Entry {
                mode: fields[0].into(),
                oid: fields[2].into(),
                path: path.into(),
            })
        })
        .collect()
}
fn read_entry(
    root: &Path,
    e: &Entry,
    report: &mut Report,
    limit: usize,
    commit: Option<&str>,
    lines: Option<&BTreeSet<usize>>,
) -> Result<(), String> {
    if e.mode == "120000" {
        skip(report, &e.path, "symlink");
        return Ok(());
    }
    if e.mode == "160000" {
        skip(report, &e.path, "submodule");
        return Ok(());
    }
    let size: u64 = string(git(root, &["cat-file", "-s", &e.oid])?)?
        .trim()
        .parse()
        .map_err(|_| "invalid Git object size")?;
    if size > limit as u64 {
        skip(report, &e.path, "oversized");
        return Ok(());
    }
    let mut child = command(root)
        .args(["cat-file", "blob", &e.oid])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| "cannot read Git blob")?;
    let mut bytes = Vec::new();
    let result = child
        .stdout
        .take()
        .ok_or("missing Git output")?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes);
    if result.is_err() || bytes.len() > limit {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| "cannot wait for Git blob")?;
    result.map_err(|_| "cannot read Git blob")?;
    if !status.success() {
        return Err("Git blob read failed".into());
    }
    add_bytes(report, &e.path, &bytes, limit, commit, lines);
    Ok(())
}
fn added_lines(root: &Path, old_oid: &str, new_oid: &str) -> Result<BTreeSet<usize>, String> {
    let mut c = command(root);
    c.args([
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--text",
        "--unified=0",
        "--inter-hunk-context=0",
        "--no-color",
        old_oid,
        new_oid,
    ]);
    let mut child = c
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| "cannot execute Git diff")?;
    let stdout = child.stdout.take().ok_or("missing Git diff output")?;
    let mut selected = BTreeSet::new();
    let mut reader = BufReader::new(stdout);
    let mut buffer = Vec::new();
    // Stream patches: raw credential-bearing lines never enter reports or errors.
    let result = (|| -> Result<(), String> {
        loop {
            buffer.clear();
            if !line_prefix(&mut reader, &mut buffer).map_err(|_| "cannot read Git diff")? {
                break;
            }
            if buffer.starts_with(b"@@ ") {
                let line = std::str::from_utf8(&buffer).map_err(|_| "invalid Git diff header")?;
                let range = line
                    .split_whitespace()
                    .nth(2)
                    .and_then(|s| s.strip_prefix('+'))
                    .ok_or("invalid Git diff range")?;
                let (start, count) = range.split_once(',').unwrap_or((range, "1"));
                let start: usize = start.parse().map_err(|_| "invalid Git diff line")?;
                let count: usize = count.parse().map_err(|_| "invalid Git diff count")?;
                let end = start.checked_add(count).ok_or("Git diff range overflow")?;
                selected.extend(start..end);
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| "cannot wait for Git diff")?;
    result?;
    if !status.success() {
        return Err("Git diff failed".into());
    }
    Ok(selected)
}
// Keep only the header prefix, draining long credential-bearing patch lines in
// fixed-size chunks. A large BASE line must not defeat the HEAD input limit.
fn line_prefix(reader: &mut impl BufRead, prefix: &mut Vec<u8>) -> std::io::Result<bool> {
    let mut consumed_any = false;
    loop {
        let bytes = reader.fill_buf()?;
        if bytes.is_empty() {
            return Ok(consumed_any);
        }
        consumed_any = true;
        let end = bytes.iter().position(|&b| b == b'\n').map(|i| i + 1);
        let count = end.unwrap_or(bytes.len());
        let retain = count.min(512usize.saturating_sub(prefix.len()));
        prefix.extend_from_slice(&bytes[..retain]);
        reader.consume(count);
        if end.is_some() {
            return Ok(true);
        }
    }
}
/// The repository's top-level directory as reported by Git.
pub fn toplevel(current: &Path) -> Result<PathBuf, String> {
    let output = string(git(current, &["rev-parse", "--show-toplevel"])?)?;
    Ok(PathBuf::from(output.strip_suffix('\n').unwrap_or(&output)))
}
pub fn scan_git(options: &ScanOptions, root: &Path) -> Result<Report, String> {
    let mode = if options.history {
        "history"
    } else if options.staged {
        "staged"
    } else if options.diff.is_some() {
        "diff"
    } else {
        "tracked"
    };
    let mut report = Report {
        mode: mode.into(),
        ..Report::default()
    };
    let limit = options.max_file_bytes;
    if options.history {
        let head = revision(root, "HEAD")?;
        if string(git(root, &["rev-parse", "--is-shallow-repository"])?)?.trim() == "true" {
            report.warnings.push(
                "Shallow repository: history includes only fetched HEAD-reachable commits".into(),
            );
        }
        let commits = string(git(root, &["rev-list", "--reverse", &head])?)?;
        let mut seen = BTreeSet::new();
        for commit in commits.lines() {
            for e in tree(root, commit)? {
                if seen.insert((e.oid.clone(), e.path.clone())) {
                    read_entry(root, &e, &mut report, limit, Some(commit), None)?;
                }
            }
        }
    } else if options.staged {
        let changed = git(
            root,
            &[
                "diff",
                "--cached",
                "--name-only",
                "--no-ext-diff",
                "--no-textconv",
                "--diff-filter=ACMRTUXB",
                "-z",
            ],
        )?;
        let paths: BTreeSet<_> = nul_strings(&changed)?.into_iter().collect();
        for e in index(root)? {
            if paths.contains(e.path.as_str()) {
                read_entry(root, &e, &mut report, limit, None, None)?;
            }
        }
    } else if let Some(base) = &options.diff {
        let base = revision(root, base)?;
        let head = revision(root, "HEAD")?;
        let base = string(
            git(root, &["merge-base", &base, &head])
                .map_err(|_| "cannot determine merge base; fetch shared history before scanning")?,
        )?
        .trim()
        .to_owned();
        let bytes = git(
            root,
            &[
                "diff",
                "--name-status",
                "--find-renames",
                "--no-ext-diff",
                "--no-textconv",
                "--diff-filter=ACMRT",
                "-z",
                &base,
                &head,
                "--",
            ],
        )?;
        let fields = nul_strings(&bytes)?;
        let entries: BTreeMap<_, _> = tree(root, &head)?
            .into_iter()
            .map(|e| (e.path.clone(), e))
            .collect();
        let previous: BTreeMap<_, _> = tree(root, &base)?
            .into_iter()
            .map(|e| (e.path.clone(), e))
            .collect();
        let mut i = 0;
        while i < fields.len() {
            let status = fields[i];
            i += 1;
            let first = *fields.get(i).ok_or("invalid Git diff inventory")?;
            i += 1;
            let (source, path) = if status.starts_with(['R', 'C']) {
                let dest = *fields.get(i).ok_or("invalid Git rename inventory")?;
                i += 1;
                (Some(first), dest)
            } else {
                (None, first)
            };
            let e = entries.get(path).ok_or("missing Git destination object")?;
            // Check size before invoking a potentially large diff.
            if e.mode == "120000" || e.mode == "160000" {
                read_entry(root, e, &mut report, limit, None, None)?;
                continue;
            }
            let size: u64 = string(git(root, &["cat-file", "-s", &e.oid])?)?
                .trim()
                .parse()
                .map_err(|_| "invalid Git object size")?;
            if size > limit as u64 {
                skip(&mut report, path, "oversized");
                continue;
            }
            let old = previous
                .get(source.unwrap_or(path))
                .filter(|e| e.mode != "120000" && e.mode != "160000");
            let lines = old
                .map(|old| added_lines(root, &old.oid, &e.oid))
                .transpose()?;
            read_entry(root, e, &mut report, limit, None, lines.as_ref())?;
        }
    } else {
        let mut paths = Vec::new();
        for e in index(root)? {
            if e.mode == "160000" {
                skip(&mut report, &e.path, "submodule");
            } else {
                paths.push(PathBuf::from(e.path));
            }
        }
        scan_tracked_paths(&mut report, root, paths, limit)?;
    }
    Ok(report)
}
