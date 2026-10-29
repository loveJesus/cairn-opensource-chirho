// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Holds one log's verified view and the steps that change it: the file stamp, the checks for a change the view
//! cannot extend, and the streaming ingest of new lines into the log type's index.

use crate::{FallbackCauseChirho, PrefixLogChirho};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};

/// What a stat says about the log. An append always grows it; any other change in place moves its timestamps, and
/// user space can set mtime back but not ctime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FileStampChirho {
    pub(crate) dev_chirho: u64,
    pub(crate) ino_chirho: u64,
    pub(crate) len_chirho: u64,
    mtime_ns_chirho: i128,
    ctime_ns_chirho: i128,
}

#[cfg(unix)]
pub(crate) fn file_stamp_chirho(metadata_chirho: &std::fs::Metadata) -> FileStampChirho {
    use std::os::unix::fs::MetadataExt;
    FileStampChirho {
        dev_chirho: metadata_chirho.dev(),
        ino_chirho: metadata_chirho.ino(),
        len_chirho: metadata_chirho.len(),
        mtime_ns_chirho: i128::from(metadata_chirho.mtime()) * 1_000_000_000
            + i128::from(metadata_chirho.mtime_nsec()),
        ctime_ns_chirho: i128::from(metadata_chirho.ctime()) * 1_000_000_000
            + i128::from(metadata_chirho.ctime_nsec()),
    }
}

#[cfg(not(unix))]
pub(crate) fn file_stamp_chirho(metadata_chirho: &std::fs::Metadata) -> FileStampChirho {
    let mtime_ns_chirho = metadata_chirho
        .modified()
        .ok()
        .and_then(|time_chirho| time_chirho.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |since_chirho| since_chirho.as_nanos() as i128);
    FileStampChirho {
        len_chirho: metadata_chirho.len(),
        mtime_ns_chirho,
        ..FileStampChirho::default()
    }
}

pub(crate) struct ViewChirho<I> {
    /// Distinguishes this view from one rebuilt later, so a background job applies only to the view it read.
    pub(crate) view_id_chirho: u64,
    pub(crate) verifier_id_chirho: String,
    /// The stat of the open handle at the last update.
    pub(crate) stamp_chirho: FileStampChirho,
    pub(crate) verified_len_chirho: u64,
    pub(crate) record_count_chirho: u64,
    /// The last verified line: its start offset and its exact bytes.
    pub(crate) anchor_chirho: Option<(u64, Vec<u8>)>,
    /// The log type's index, folded in file order from verified bytes only.
    pub(crate) index_chirho: I,
    /// When the whole log was last verified, by a full load, an integrity pass or an index rebuild.
    pub(crate) last_full_ms_chirho: u64,
    pub(crate) job_in_flight_chirho: Option<crate::BackgroundJobChirho>,
}

impl<I: Default> ViewChirho<I> {
    pub(crate) fn empty_chirho(
        verifier_id_chirho: &str,
        stamp_chirho: FileStampChirho,
        now_ms_chirho: u64,
    ) -> Self {
        static NEXT_VIEW_ID_CHIRHO: AtomicU64 = AtomicU64::new(1);
        Self {
            view_id_chirho: NEXT_VIEW_ID_CHIRHO.fetch_add(1, Ordering::Relaxed),
            verifier_id_chirho: verifier_id_chirho.to_string(),
            stamp_chirho,
            verified_len_chirho: 0,
            record_count_chirho: 0,
            anchor_chirho: None,
            index_chirho: I::default(),
            last_full_ms_chirho: now_ms_chirho,
            job_in_flight_chirho: None,
        }
    }
}

/// The first reason, in a fixed order, that the view cannot be extended from its verified prefix.
pub(crate) fn fallback_cause_chirho<L: PrefixLogChirho>(
    view_chirho: &ViewChirho<L::IndexChirho>,
    log_chirho: &L,
    stamp_chirho: &FileStampChirho,
    file_chirho: &mut File,
) -> Result<Option<FallbackCauseChirho>> {
    if view_chirho.verifier_id_chirho != log_chirho.verifier_id_chirho() {
        return Ok(Some(FallbackCauseChirho::VerifierChangedChirho));
    }
    if (stamp_chirho.dev_chirho, stamp_chirho.ino_chirho)
        != (
            view_chirho.stamp_chirho.dev_chirho,
            view_chirho.stamp_chirho.ino_chirho,
        )
    {
        return Ok(Some(FallbackCauseChirho::IdentityChangedChirho));
    }
    if stamp_chirho.len_chirho < view_chirho.verified_len_chirho {
        return Ok(Some(FallbackCauseChirho::ShrunkChirho));
    }
    if *stamp_chirho == view_chirho.stamp_chirho {
        return Ok(None);
    }
    // Same length, new timestamps: something changed in place, which the appender never does.
    if stamp_chirho.len_chirho == view_chirho.stamp_chirho.len_chirho {
        return Ok(Some(FallbackCauseChirho::RewrittenInPlaceChirho));
    }
    if !anchor_intact_chirho(view_chirho, file_chirho)? {
        return Ok(Some(FallbackCauseChirho::AnchorChangedChirho));
    }
    Ok(None)
}

fn anchor_intact_chirho<I>(view_chirho: &ViewChirho<I>, file_chirho: &mut File) -> Result<bool> {
    let Some((offset_chirho, bytes_chirho)) = &view_chirho.anchor_chirho else {
        // No record yet: only an empty verified prefix is consistent with that.
        return Ok(view_chirho.verified_len_chirho == 0);
    };
    file_chirho.seek(SeekFrom::Start(*offset_chirho))?;
    let mut current_chirho = vec![0u8; bytes_chirho.len()];
    match file_chirho.read_exact(&mut current_chirho) {
        Ok(()) => Ok(&current_chirho == bytes_chirho),
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error_chirho) => Err(error_chirho.into()),
    }
}

/// Verify and fold every line between the verified prefix and `end_len_chirho` (the stamp's length, so the stamp
/// and the prefix describe the same bytes), one line at a time. A complete line that fails to parse or verify
/// fails the call, as in a full scan; a final line without its newline counts only when it parses.
pub(crate) fn ingest_chirho<L: PrefixLogChirho>(
    log_chirho: &L,
    file_chirho: &mut File,
    view_chirho: &mut ViewChirho<L::IndexChirho>,
    end_len_chirho: u64,
) -> Result<()> {
    let start_chirho = view_chirho.verified_len_chirho;
    file_chirho.seek(SeekFrom::Start(start_chirho))?;
    let mut reader_chirho = BufReader::new(
        file_chirho
            .by_ref()
            .take(end_len_chirho.saturating_sub(start_chirho)),
    );
    let mut consumed_chirho = 0u64;
    let mut line_chirho = Vec::new();
    loop {
        line_chirho.clear();
        let read_chirho = reader_chirho
            .read_until(b'\n', &mut line_chirho)
            .with_context(|| format!("read {}", log_chirho.path_chirho().display()))?;
        if read_chirho == 0 {
            break;
        }
        let terminated_chirho = line_chirho.last() == Some(&b'\n');
        let parsed_chirho = match std::str::from_utf8(&line_chirho) {
            Ok(text_chirho) => {
                let content_chirho = text_chirho.trim_end_matches(['\n', '\r']);
                if content_chirho.trim().is_empty() {
                    if !terminated_chirho {
                        break;
                    }
                    consumed_chirho += read_chirho as u64;
                    continue;
                }
                log_chirho.parse_chirho(content_chirho)
            }
            Err(error_chirho) => Err(anyhow::Error::new(error_chirho).context(format!(
                "non-UTF-8 line in {}",
                log_chirho.path_chirho().display()
            ))),
        };
        let record_chirho = match parsed_chirho {
            Ok(record_chirho) => record_chirho,
            Err(error_chirho) if terminated_chirho => return Err(error_chirho),
            // An unterminated tail that does not parse is a write still in flight, or a torn tail.
            Err(_) => break,
        };
        log_chirho.verify_and_fold_chirho(
            &mut view_chirho.index_chirho,
            record_chirho,
            view_chirho.record_count_chirho,
        )?;
        view_chirho.record_count_chirho += 1;
        view_chirho.anchor_chirho = Some((
            start_chirho + consumed_chirho,
            std::mem::take(&mut line_chirho),
        ));
        consumed_chirho += read_chirho as u64;
    }
    view_chirho.verified_len_chirho = start_chirho + consumed_chirho;
    Ok(())
}
