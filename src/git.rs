use crate::{input::ScanOptions, model::Report};
pub fn scan_git(_options: &ScanOptions) -> Result<Report, String> {
    Err("Git scanning not implemented".into())
}
