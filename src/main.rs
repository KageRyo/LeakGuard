use clap::{ArgGroup, Parser, Subcommand, error::ErrorKind};
use leakguard::{
    input::{ScanOptions, scan},
    model::Confidence,
    report::{Format, render},
};
use std::{io::Write, path::PathBuf};

#[derive(Parser)]
#[command(version, about = "Offline secret and credential leakage guard")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Scan(Args),
}
#[derive(clap::Args)]
#[command(group(ArgGroup::new("git-mode").args(["staged", "history", "diff"]).multiple(false)))]
struct Args {
    #[arg(conflicts_with_all = ["staged", "history", "diff"])]
    paths: Vec<PathBuf>,
    #[arg(long)]
    staged: bool,
    #[arg(long)]
    history: bool,
    #[arg(long, value_name = "BASE")]
    diff: Option<String>,
    #[arg(long, value_enum, default_value = "high")]
    fail_on: Confidence,
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long, default_value = "10485760")]
    max_file_bytes: usize,
}
fn execute() -> Result<i32, String> {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) => {
            e.print().map_err(|_| "cannot write help output")?;
            return Ok(0);
        }
        Err(_) => return Err("invalid arguments; use leakguard scan --help".into()),
    };
    let Command::Scan(args) = cli.command;
    let report = scan(&ScanOptions {
        paths: args.paths,
        staged: args.staged,
        history: args.history,
        diff: args.diff,
        max_file_bytes: args.max_file_bytes,
    })?;
    let rendered = render(&report, args.format, args.fail_on);
    if let Some(path) = args.output {
        std::fs::write(path, rendered).map_err(|_| "cannot write report file")?;
    } else {
        std::io::stdout()
            .lock()
            .write_all(rendered.as_bytes())
            .map_err(|_| "cannot write report output")?;
    }
    Ok(i32::from(report.fails(args.fail_on)))
}
fn main() {
    let code = match execute() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("LeakGuard error: {message}");
            2
        }
    };
    std::process::exit(code);
}
