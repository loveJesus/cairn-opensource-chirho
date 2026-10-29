// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Embeds the source commit in the binary, so a hash found on a host resolves to a tree.
//!
//! The mechanism itself (supplied commit first, git-derived fallback, `unknown` marker, `-dirty`
//! suffix, and why each of those is the way it is) now lives in `cairn-build-identity-chirho`,
//! because the elector and the composed geo nodes need exactly the same thing and a second copy
//! would be a second thing to keep true.

fn main() {
    cairn_build_identity_chirho::build_script_chirho::emit_build_commit_chirho();
}
