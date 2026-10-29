// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms for the typed resource-exhaustion check: the four resource codes count, and permission, a
//! wrong file type, absence, a flattened error and a real out-of-files failure are each told apart.

use super::*;

#[test]
fn each_resource_code_counts_chirho() {
    for code_chirho in [
        libc::EMFILE,
        libc::ENFILE,
        libc::ENOSPC,
        libc::EAGAIN,
        libc::EWOULDBLOCK,
    ] {
        assert!(
            io_error_is_resource_exhaustion_chirho(&io::Error::from_raw_os_error(code_chirho)),
            "OS code {code_chirho} is a resource exhaustion"
        );
    }
}

#[test]
fn permission_type_absence_and_integrity_do_not_count_chirho() {
    for code_chirho in [
        libc::EACCES,
        libc::EPERM,
        libc::EISDIR,
        libc::ENOTDIR,
        libc::ENOENT,
        libc::EIO,
        libc::ELOOP,
    ] {
        assert!(
            !io_error_is_resource_exhaustion_chirho(&io::Error::from_raw_os_error(code_chirho)),
            "OS code {code_chirho} is not a resource exhaustion"
        );
    }
}

#[test]
fn an_error_without_an_os_code_does_not_count_chirho() {
    let flattened_chirho = io::Error::other("Too many open files (os error 24)");
    assert!(!io_error_is_resource_exhaustion_chirho(&flattened_chirho));
}

#[test]
fn a_real_directory_read_is_not_a_resource_chirho() {
    let error_chirho = fs::read(std::env::temp_dir()).unwrap_err();
    assert!(
        error_chirho.raw_os_error().is_some(),
        "the read failed with a real OS code"
    );
    assert!(!io_error_is_resource_exhaustion_chirho(&error_chirho));
}
