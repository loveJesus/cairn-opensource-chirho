// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16

//! Typed read-only JSONL decoding shared by signed record adapters.

use anyhow::{Context, Result};
use cairn_durable_chirho::log_path_chirho::open_log_no_follow_chirho;
use serde::de::DeserializeOwned;
use std::io::Read;
use std::path::Path;

/// A log's whole text: `None` only for a genuine absence. A log that cannot be examined or read (a link, a directory,
/// a pipe, a permission error) refuses, never read as empty, and a pipe is never waited on.
pub fn read_log_text_chirho(path_chirho: &Path) -> Result<Option<String>> {
    let Some(mut file_chirho) = open_log_no_follow_chirho(path_chirho)
        .with_context(|| format!("examine {}", path_chirho.display()))?
    else {
        return Ok(None);
    };
    let mut text_chirho = String::new();
    file_chirho
        .read_to_string(&mut text_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    Ok(Some(text_chirho))
}

/// Every record of a JSONL log. Only a genuine absence reads as no records; a log that cannot be examined or read (a
/// link, a directory, a pipe, a permission error) refuses, never read as empty.
pub fn load_serialized_jsonl_chirho<T>(path_chirho: &Path) -> Result<Vec<T>>
where
    T: DeserializeOwned,
{
    let Some(text_chirho) = read_log_text_chirho(path_chirho)? else {
        return Ok(Vec::new());
    };
    text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(|line_chirho| serde_json::from_str(line_chirho).map_err(Into::into))
        .collect()
}
