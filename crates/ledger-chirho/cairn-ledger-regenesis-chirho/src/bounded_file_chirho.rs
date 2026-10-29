// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Regenesis wrapper around the shared identity-stable bounded file reader.

use std::io;
use std::path::Path;

pub(crate) fn read_bounded_regular_file_chirho(
    path_chirho: &Path,
    max_bytes_chirho: u64,
) -> io::Result<Vec<u8>> {
    cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        path_chirho,
        max_bytes_chirho,
    )
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root_chirho() -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nonce_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cairn-regenesis-bounded-file-{nanos_chirho}-{}-{nonce_chirho}-chirho",
            std::process::id()
        ))
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_refuses_growth_symlinks_and_hard_links_chirho() {
        let root_chirho = temp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let file_path_chirho = root_chirho.join("evidence-chirho.json");
        fs::write(&file_path_chirho, b"1234").unwrap();
        assert_eq!(
            read_bounded_regular_file_chirho(&file_path_chirho, 4).unwrap(),
            b"1234"
        );

        fs::write(&file_path_chirho, b"12345").unwrap();
        assert!(read_bounded_regular_file_chirho(&file_path_chirho, 4).is_err());

        #[cfg(unix)]
        {
            let target_path_chirho = root_chirho.join("target-chirho.json");
            let symlink_path_chirho = root_chirho.join("symlink-chirho.json");
            let hard_link_path_chirho = root_chirho.join("hard-link-chirho.json");
            fs::write(&target_path_chirho, b"1234").unwrap();
            std::os::unix::fs::symlink(&target_path_chirho, &symlink_path_chirho).unwrap();
            assert!(read_bounded_regular_file_chirho(&symlink_path_chirho, 4).is_err());
            fs::hard_link(&target_path_chirho, &hard_link_path_chirho).unwrap();
            assert!(read_bounded_regular_file_chirho(&target_path_chirho, 4).is_err());
            assert!(read_bounded_regular_file_chirho(&hard_link_path_chirho, 4).is_err());
        }

        fs::remove_dir_all(root_chirho).unwrap();
    }

    #[cfg(not(unix))]
    #[test]
    fn bounded_reader_refuses_without_stable_file_identity_chirho() {
        let root_chirho = temp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let file_path_chirho = root_chirho.join("evidence-chirho.json");
        fs::write(&file_path_chirho, b"1234").unwrap();
        assert!(read_bounded_regular_file_chirho(&file_path_chirho, 4).is_err());
        fs::remove_dir_all(root_chirho).unwrap();
    }
}
