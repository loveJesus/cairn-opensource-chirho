// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Shared display helpers for signed-evidence JSONL listings.

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayRecordChirho<T> {
    pub line_chirho: u64,
    pub record_chirho: Option<T>,
    pub validation_error_chirho: Option<String>,
}

impl<T> DisplayRecordChirho<T> {
    pub fn valid_chirho(&self) -> bool {
        self.record_chirho.is_some() && self.validation_error_chirho.is_none()
    }
}

pub fn load_jsonl_for_display_chirho<T, F>(
    path_chirho: &Path,
    record_name_chirho: &str,
    family_validation_error_chirho: Option<&str>,
    seq_chirho: F,
) -> Result<Vec<DisplayRecordChirho<T>>>
where
    T: DeserializeOwned,
    F: Fn(&T) -> u64,
{
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut out_chirho = Vec::new();
    let mut expected_seq_chirho = 0_u64;
    for (line_idx_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let line_number_chirho = line_idx_chirho as u64 + 1;
        match serde_json::from_str::<T>(line_chirho) {
            Ok(record_chirho) => {
                let actual_seq_chirho = seq_chirho(&record_chirho);
                let validation_error_chirho = if actual_seq_chirho != expected_seq_chirho {
                    Some(format!(
                        "{record_name_chirho} seq {actual_seq_chirho} did not match line {expected_seq_chirho}"
                    ))
                } else {
                    family_validation_error_chirho.map(str::to_string)
                };
                out_chirho.push(DisplayRecordChirho {
                    line_chirho: line_number_chirho,
                    record_chirho: Some(record_chirho),
                    validation_error_chirho,
                });
            }
            Err(_) => out_chirho.push(DisplayRecordChirho {
                line_chirho: line_number_chirho,
                record_chirho: None,
                validation_error_chirho: Some(format!("decode {record_name_chirho} failed")),
            }),
        }
        expected_seq_chirho += 1;
    }
    Ok(out_chirho)
}
