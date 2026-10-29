// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The item-6 drill's evidence-PACKAGING harness: assemble shareable members into a bundle with a
//! recursive relative SHA-256 manifest and a self-tested verifier, refuse to publish if any member
//! trips the REUSED forbidden-marker/no-leak scan, always carry a fixed nonclaims block, and keep
//! host-private raw captures out of the bundle by type.
//!
//! # WHAT THIS MIRRORS FROM `b5-hosted-contested-election-chirho.py`
//!
//! * **A recursive relative SHA-256 manifest.** One `sha256(bytes)  <relative-name>` line per member
//!   (byte-for-byte the `sha256sum` format, so an operator can cross-check with the standard tool),
//!   sorted by name, plus a domain-separated bundle digest. A tampered member changes its line, so the
//!   digest changes and [`verify_shareable_bundle_chirho`] refuses.
//! * **A self-tested verifier.** [`bundle_verifier_selftest_chirho`] runs a fixed set of known-good and
//!   known-bad controls (the analog of b5's `20/20` selftest gate) and [`BUNDLE_SELFTEST_CONTROL_COUNT_CHIRHO`]
//!   pins the count, so a control silently dropped is a failure, not a smaller green.
//! * **A no-leak scan on every member.** [`scan_forbidden_markers_chirho`] — the SAME scan the shareable
//!   packet uses (host paths, bearer tokens, free-text principals, raw provider bytes). One scan, one
//!   marker list, never duplicated. Fail closed: any member that trips it blocks the WHOLE bundle.
//! * **An explicit nonclaims block.** A fixed, reviewed [`ITEM6_DRILL_NONCLAIMS_CHIRHO`] member is
//!   auto-appended to every bundle, so the honest scope always travels with the evidence.
//!
//! # HOST-PRIVATE CAPTURES ARE EXCLUDED BY TYPE
//!
//! Raw captures (former-owner logs, `nft list`, process tables) are a DIFFERENT type
//! ([`HostPrivateCaptureChirho`]) that the bundle builder cannot accept — there is no
//! `From<HostPrivateCaptureChirho>` for a member, so exclusion is structural, not a discipline. On a
//! host these stay under the drill root at mode `600` (the executor's job, 6.6). As a DEFENSE-IN-DEPTH
//! backstop, the no-leak scan rejects a member whose bytes carry a denylisted TOKEN (a host path, a
//! bearer, a principal, provider bytes) — proven by a control. But the scan is a literal-token denylist,
//! NOT a complete leak filter: it does NOT catch bare PII SHAPES — a path-free `nft list` line carrying
//! only an overlay IP, a bare email, or a key-id token would pass (reviewer 6.5-d MEDIUM). The PRIMARY
//! guarantee is STRUCTURAL/TYPED: this crate's sanctioned producer emits only the typed, free-text-free
//! packet. Item 6.6, which will gate ARBITRARY drill-evidence members, MUST keep those members
//! typed/bounded (or add IP/email/token shape-detection) — never rely on this scan as the primary control.

use cairn_ledger_regenesis_chirho::{
    scan_forbidden_markers_chirho, LedgerRegenesisRefusalChirho,
    ShareableEvidenceRefusalReasonChirho,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The domain-separation tag for the bundle's recursive SHA-256 manifest — pinned, like b5's pinned
/// verifier digest. The bundle digest is `sha256(domain || "\n"-joined sorted member lines)`.
const BUNDLE_MANIFEST_DOMAIN_CHIRHO: &str = "cairn-item6-drill-evidence-bundle-manifest-v1-chirho";

/// The reserved member name the packager uses for the auto-appended nonclaims block; a caller cannot
/// supply a member with this name.
const NONCLAIMS_MEMBER_NAME_CHIRHO: &str = "nonclaims-chirho.json";
const NONCLAIMS_SCHEMA_CHIRHO: &str = "cairn-item6-drill-evidence-nonclaims-v1-chirho";

/// The fixed, reviewed honest-scope nonclaims that travel with every bundle. Constant English (like
/// b5's `nonclaims_chirho`), never drill-derived free text, so it is safe to ship and is
/// no-leak-scanned like every other member.
pub const ITEM6_DRILL_NONCLAIMS_CHIRHO: &[&str] = &[
    "this is the item-6 observer logic and evidence-packaging harness tested locally; no host was \
     contacted and no healing drill was executed",
    "the observer channel is read-only and holds no signing key or write, relay, or activation \
     authority; it cannot depose, elect, or mint",
    "no money moved, no ledger appended, no compensation ran, and no production gate opened",
    "host-private raw captures such as logs, packet-filter listings, and process tables are excluded \
     from this bundle by type and stay under the drill root at restricted mode",
    "a dedicated on-the-wire deposition-belief endpoint (observer option d2) is a non-goal for item 6",
];

/// One SHAREABLE bundle member: a safe relative name and its exact bytes. Only members that pass the
/// no-leak scan (and whose name is a safe relative token) enter a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareableBundleMemberChirho {
    relative_name_chirho: String,
    bytes_chirho: Vec<u8>,
}

impl ShareableBundleMemberChirho {
    /// Build a shareable member. This does NOT scan — packaging is the gate — so a member can be
    /// constructed and then correctly REFUSED by [`package_shareable_bundle_chirho`], which is exactly
    /// how the planted-needle controls exercise the real gate.
    pub fn new_chirho(relative_name_chirho: impl Into<String>, bytes_chirho: Vec<u8>) -> Self {
        Self {
            relative_name_chirho: relative_name_chirho.into(),
            bytes_chirho,
        }
    }

    pub fn relative_name_chirho(&self) -> &str {
        &self.relative_name_chirho
    }

    pub fn bytes_chirho(&self) -> &[u8] {
        &self.bytes_chirho
    }
}

/// A HOST-PRIVATE raw capture (former-owner logs, `nft list`, process tables). A DIFFERENT type from
/// [`ShareableBundleMemberChirho`], so the bundle builder cannot accept one by construction. On a host
/// these stay under the drill root at mode `600`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPrivateCaptureChirho {
    pub capture_kind_chirho: HostPrivateCaptureKindChirho,
    raw_bytes_chirho: Vec<u8>,
}

/// Which host-private raw capture this is. Bounded label; the raw bytes never leave the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPrivateCaptureKindChirho {
    FormerOwnerLogChirho,
    NftListChirho,
    ProcessTableChirho,
}

impl HostPrivateCaptureChirho {
    pub fn new_chirho(
        capture_kind_chirho: HostPrivateCaptureKindChirho,
        raw_bytes_chirho: Vec<u8>,
    ) -> Self {
        Self {
            capture_kind_chirho,
            raw_bytes_chirho,
        }
    }

    /// The raw bytes stay host-private. This surfaces them ONLY so a control can prove the packager
    /// refuses them if they are ever routed into a shareable member; there is deliberately no
    /// conversion into a member.
    pub fn raw_bytes_chirho(&self) -> &[u8] {
        &self.raw_bytes_chirho
    }
}

/// Which class of forbidden marker a member tripped — a bounded projection of the reused scan's reason
/// (the marker LISTS live in `cairn-ledger-regenesis-chirho`, never duplicated here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForbiddenMarkerReasonChirho {
    HostPathChirho,
    BearerChirho,
    PrincipalChirho,
    ProviderBytesChirho,
    OtherChirho,
}

impl ForbiddenMarkerReasonChirho {
    fn from_regenesis_reason_chirho(reason_chirho: &ShareableEvidenceRefusalReasonChirho) -> Self {
        match reason_chirho {
            ShareableEvidenceRefusalReasonChirho::ForbiddenHostPathChirho => Self::HostPathChirho,
            ShareableEvidenceRefusalReasonChirho::ForbiddenBearerMarkerChirho => Self::BearerChirho,
            ShareableEvidenceRefusalReasonChirho::ForbiddenPrincipalMarkerChirho => {
                Self::PrincipalChirho
            }
            ShareableEvidenceRefusalReasonChirho::ForbiddenProviderBytesChirho => {
                Self::ProviderBytesChirho
            }
            _ => Self::OtherChirho,
        }
    }
}

/// Why a bundle was refused. Every refusal fails CLOSED: nothing is published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleRefusalChirho {
    /// No members were supplied; an empty bundle would report success while carrying nothing.
    NoMembersChirho,
    /// A member name was not a safe relative `[a-z0-9._-]` token (or contained `..`), so it could
    /// carry a path into the manifest.
    UnsafeMemberNameChirho { name_chirho: String },
    /// Two members shared a name, so a manifest line would be ambiguous.
    DuplicateMemberNameChirho { name_chirho: String },
    /// A caller member used the reserved nonclaims name.
    ReservedMemberNameChirho { name_chirho: String },
    /// A member tripped the reused no-leak scan. The bundle is NOT published.
    ForbiddenMarkerChirho {
        member_name_chirho: String,
        reason_chirho: ForbiddenMarkerReasonChirho,
    },
    /// A verifier check failed: the recomputed manifest did not equal the stored one (a tampered
    /// member), so the bundle is not trusted.
    ManifestMismatchChirho,
}

impl std::fmt::Display for BundleRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMembersChirho => formatter_chirho.write_str("bundle has no members"),
            Self::UnsafeMemberNameChirho { name_chirho } => {
                write!(
                    formatter_chirho,
                    "bundle member name is unsafe: {name_chirho}"
                )
            }
            Self::DuplicateMemberNameChirho { name_chirho } => {
                write!(
                    formatter_chirho,
                    "bundle member name is duplicated: {name_chirho}"
                )
            }
            Self::ReservedMemberNameChirho { name_chirho } => {
                write!(
                    formatter_chirho,
                    "bundle member used the reserved name: {name_chirho}"
                )
            }
            Self::ForbiddenMarkerChirho {
                member_name_chirho,
                reason_chirho,
            } => write!(
                formatter_chirho,
                "bundle member {member_name_chirho} tripped the no-leak scan: {reason_chirho:?}"
            ),
            Self::ManifestMismatchChirho => {
                formatter_chirho.write_str("bundle manifest did not match the members")
            }
        }
    }
}

impl std::error::Error for BundleRefusalChirho {}

/// The recursive relative SHA-256 manifest of a bundle's members: one `sha256(bytes)  <relative-name>`
/// line per member (sorted by name), plus the domain-separated bundle digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleManifestChirho {
    lines_chirho: Vec<String>,
    bundle_digest_chirho: String,
}

impl BundleManifestChirho {
    pub fn lines_chirho(&self) -> &[String] {
        &self.lines_chirho
    }

    pub fn bundle_digest_chirho(&self) -> &str {
        &self.bundle_digest_chirho
    }
}

/// A packaged, publishable evidence bundle: the ordered members (including the auto-appended nonclaims
/// block) and the recursive SHA-256 manifest. Every member has passed the no-leak scan; the manifest
/// is exact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareableEvidenceBundleChirho {
    members_chirho: Vec<ShareableBundleMemberChirho>,
    manifest_chirho: BundleManifestChirho,
}

impl ShareableEvidenceBundleChirho {
    pub fn members_chirho(&self) -> &[ShareableBundleMemberChirho] {
        &self.members_chirho
    }

    pub fn manifest_chirho(&self) -> &BundleManifestChirho {
        &self.manifest_chirho
    }

    /// True if the bundle carries the fixed nonclaims member. Every bundle the packager builds does.
    pub fn has_nonclaims_chirho(&self) -> bool {
        self.members_chirho
            .iter()
            .any(|member_chirho| member_chirho.relative_name_chirho == NONCLAIMS_MEMBER_NAME_CHIRHO)
    }
}

#[derive(Serialize)]
struct NonclaimsBlockChirho {
    schema_chirho: &'static str,
    nonclaims_chirho: &'static [&'static str],
}

fn nonclaims_bytes_chirho() -> Vec<u8> {
    let block_chirho = NonclaimsBlockChirho {
        schema_chirho: NONCLAIMS_SCHEMA_CHIRHO,
        nonclaims_chirho: ITEM6_DRILL_NONCLAIMS_CHIRHO,
    };
    serde_json::to_vec(&block_chirho).expect("fixed nonclaims block is serializable")
}

/// The fixed nonclaims member every bundle carries (auto-appended by the packager). Public so a
/// control can assert its content and that it passes the no-leak scan.
pub fn nonclaims_member_chirho() -> ShareableBundleMemberChirho {
    ShareableBundleMemberChirho {
        relative_name_chirho: NONCLAIMS_MEMBER_NAME_CHIRHO.to_owned(),
        bytes_chirho: nonclaims_bytes_chirho(),
    }
}

fn sha256_hex_chirho(bytes_chirho: &[u8]) -> String {
    let digest_chirho = Sha256::digest(bytes_chirho);
    let mut hex_chirho = String::with_capacity(digest_chirho.len() * 2);
    for byte_chirho in digest_chirho {
        hex_chirho.push_str(&format!("{byte_chirho:02x}"));
    }
    hex_chirho
}

fn validate_member_name_chirho(name_chirho: &str) -> Result<(), BundleRefusalChirho> {
    let safe_chirho = !name_chirho.is_empty()
        && name_chirho.len() <= 128
        && name_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase()
                || byte_chirho.is_ascii_digit()
                || matches!(byte_chirho, b'.' | b'_' | b'-')
        })
        && !name_chirho.contains("..");
    if safe_chirho {
        Ok(())
    } else {
        Err(BundleRefusalChirho::UnsafeMemberNameChirho {
            name_chirho: name_chirho.to_owned(),
        })
    }
}

/// Run the REUSED no-leak scan on one member, mapping a scan refusal into a bundle refusal that names
/// the offending member and the marker class.
fn scan_member_chirho(
    member_chirho: &ShareableBundleMemberChirho,
) -> Result<(), BundleRefusalChirho> {
    match scan_forbidden_markers_chirho(&member_chirho.bytes_chirho) {
        Ok(()) => Ok(()),
        Err(LedgerRegenesisRefusalChirho::ShareableEvidenceRefusedChirho { reason_chirho }) => {
            Err(BundleRefusalChirho::ForbiddenMarkerChirho {
                member_name_chirho: member_chirho.relative_name_chirho.clone(),
                reason_chirho: ForbiddenMarkerReasonChirho::from_regenesis_reason_chirho(
                    &reason_chirho,
                ),
            })
        }
        Err(_) => Err(BundleRefusalChirho::ForbiddenMarkerChirho {
            member_name_chirho: member_chirho.relative_name_chirho.clone(),
            reason_chirho: ForbiddenMarkerReasonChirho::OtherChirho,
        }),
    }
}

/// Build the recursive relative SHA-256 manifest for a set of members: validate each name, refuse a
/// duplicate, emit one sorted `sha256sum`-format line each, and domain-separate the bundle digest.
fn build_manifest_chirho(
    members_chirho: &[ShareableBundleMemberChirho],
) -> Result<BundleManifestChirho, BundleRefusalChirho> {
    let mut named_lines_chirho: Vec<(String, String)> = Vec::with_capacity(members_chirho.len());
    for member_chirho in members_chirho {
        validate_member_name_chirho(&member_chirho.relative_name_chirho)?;
        if named_lines_chirho
            .iter()
            .any(|(name_chirho, _line_chirho)| name_chirho == &member_chirho.relative_name_chirho)
        {
            return Err(BundleRefusalChirho::DuplicateMemberNameChirho {
                name_chirho: member_chirho.relative_name_chirho.clone(),
            });
        }
        let line_chirho = format!(
            "{}  {}",
            sha256_hex_chirho(&member_chirho.bytes_chirho),
            member_chirho.relative_name_chirho
        );
        named_lines_chirho.push((member_chirho.relative_name_chirho.clone(), line_chirho));
    }
    named_lines_chirho.sort_by(|left_chirho, right_chirho| left_chirho.0.cmp(&right_chirho.0));
    let lines_chirho: Vec<String> = named_lines_chirho
        .into_iter()
        .map(|(_name_chirho, line_chirho)| line_chirho)
        .collect();
    let joined_chirho = lines_chirho.join("\n");
    let digest_input_chirho = [
        BUNDLE_MANIFEST_DOMAIN_CHIRHO.as_bytes(),
        joined_chirho.as_bytes(),
    ]
    .concat();
    Ok(BundleManifestChirho {
        lines_chirho,
        bundle_digest_chirho: sha256_hex_chirho(&digest_input_chirho),
    })
}

/// Package shareable members into a bundle, or refuse. THE PRIVACY GATE: it refuses an empty bundle,
/// refuses the reserved nonclaims name, runs the reused no-leak scan on every caller member (fail
/// closed — one trip blocks the whole bundle), auto-appends the fixed nonclaims block, and builds the
/// recursive SHA-256 manifest (which validates names and refuses duplicates).
pub fn package_shareable_bundle_chirho(
    members_chirho: Vec<ShareableBundleMemberChirho>,
) -> Result<ShareableEvidenceBundleChirho, BundleRefusalChirho> {
    if members_chirho.is_empty() {
        return Err(BundleRefusalChirho::NoMembersChirho);
    }
    for member_chirho in &members_chirho {
        if member_chirho.relative_name_chirho == NONCLAIMS_MEMBER_NAME_CHIRHO {
            return Err(BundleRefusalChirho::ReservedMemberNameChirho {
                name_chirho: member_chirho.relative_name_chirho.clone(),
            });
        }
        validate_member_name_chirho(&member_chirho.relative_name_chirho)?;
        scan_member_chirho(member_chirho)?;
    }
    let mut all_members_chirho = members_chirho;
    let nonclaims_chirho = nonclaims_member_chirho();
    // Belt-and-suspenders: the fixed nonclaims block is scanned like everything else.
    scan_member_chirho(&nonclaims_chirho)?;
    all_members_chirho.push(nonclaims_chirho);
    let manifest_chirho = build_manifest_chirho(&all_members_chirho)?;
    Ok(ShareableEvidenceBundleChirho {
        members_chirho: all_members_chirho,
        manifest_chirho,
    })
}

/// Re-verify a packaged bundle: recompute each member's SHA-256, rebuild the manifest, check it equals
/// the stored manifest (a tampered member fails here), and re-run the no-leak scan on every member.
/// This is the bundle's frozen verifier — the analog of b5's frozen verifier plus digest pin.
pub fn verify_shareable_bundle_chirho(
    bundle_chirho: &ShareableEvidenceBundleChirho,
) -> Result<(), BundleRefusalChirho> {
    let recomputed_chirho = build_manifest_chirho(&bundle_chirho.members_chirho)?;
    if recomputed_chirho != bundle_chirho.manifest_chirho {
        return Err(BundleRefusalChirho::ManifestMismatchChirho);
    }
    for member_chirho in &bundle_chirho.members_chirho {
        scan_member_chirho(member_chirho)?;
    }
    Ok(())
}

/// The number of controls the bundle-verifier selftest runs. Pinned like b5's `20/20` gate: the
/// selftest asserts EXACTLY this many controls ran and every one behaved, so a control silently
/// dropped is a failure, not a smaller green.
pub const BUNDLE_SELFTEST_CONTROL_COUNT_CHIRHO: usize = 11;

/// The result of the bundle-verifier selftest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleSelftestReportChirho {
    pub controls_run_chirho: usize,
    pub controls_passed_chirho: usize,
}

impl BundleSelftestReportChirho {
    /// True iff exactly the pinned number of controls ran and every one behaved.
    pub fn all_behaved_chirho(&self) -> bool {
        self.controls_run_chirho == BUNDLE_SELFTEST_CONTROL_COUNT_CHIRHO
            && self.controls_passed_chirho == self.controls_run_chirho
    }
}

fn safe_member_chirho() -> ShareableBundleMemberChirho {
    // A bounded digest/status control: 64-hex digest + a fixed status label, no free text.
    ShareableBundleMemberChirho::new_chirho(
        "durable-state-digest-chirho.txt",
        format!("digest={}\nstatus=verified-chirho\n", "0".repeat(64)).into_bytes(),
    )
}

/// Run the bundle-verifier selftest: a fixed set of known-good and known-bad controls, each asserting
/// the packager/verifier behaves. Mirrors b5's selftest — the harness must pass its own controls
/// before it is trusted to package a drill. Every control's PASS is `true` iff the gate did the right
/// thing; a needle control passes iff publication was BLOCKED with the right marker class.
pub fn bundle_verifier_selftest_chirho() -> BundleSelftestReportChirho {
    let mut controls_chirho: Vec<bool> = Vec::new();

    // 1. A safe bundle packages AND verifies.
    let safe_bundle_chirho = package_shareable_bundle_chirho(vec![safe_member_chirho()]);
    controls_chirho.push(match &safe_bundle_chirho {
        Ok(bundle_chirho) => {
            bundle_chirho.has_nonclaims_chirho()
                && verify_shareable_bundle_chirho(bundle_chirho).is_ok()
        }
        Err(_) => false,
    });

    // 2-5. Each planted needle BLOCKS publication with the right marker class (positive controls that
    // the gate FIRES, not merely that it exists).
    let needle_cases_chirho = [
        (
            "/var/lib/cairn-chirho/x",
            ForbiddenMarkerReasonChirho::HostPathChirho,
        ),
        (
            "bearer secret-token",
            ForbiddenMarkerReasonChirho::BearerChirho,
        ),
        (
            "free_text_principal=owner",
            ForbiddenMarkerReasonChirho::PrincipalChirho,
        ),
        (
            "raw_provider_bytes=payload",
            ForbiddenMarkerReasonChirho::ProviderBytesChirho,
        ),
    ];
    for (needle_chirho, expected_reason_chirho) in needle_cases_chirho {
        let member_chirho = ShareableBundleMemberChirho::new_chirho(
            "needle-chirho.txt",
            needle_chirho.as_bytes().to_vec(),
        );
        controls_chirho.push(matches!(
            package_shareable_bundle_chirho(vec![member_chirho]),
            Err(BundleRefusalChirho::ForbiddenMarkerChirho { reason_chirho, .. })
                if reason_chirho == expected_reason_chirho
        ));
    }

    // 6. A tampered member fails the verifier.
    controls_chirho.push(
        match package_shareable_bundle_chirho(vec![safe_member_chirho()]) {
            Ok(mut bundle_chirho) => {
                bundle_chirho.members_chirho[0]
                    .bytes_chirho
                    .extend_from_slice(b"tamper");
                matches!(
                    verify_shareable_bundle_chirho(&bundle_chirho),
                    Err(BundleRefusalChirho::ManifestMismatchChirho)
                )
            }
            Err(_) => false,
        },
    );

    // 7. A host-private capture's bytes are rejected if routed into a shareable member.
    let capture_chirho = HostPrivateCaptureChirho::new_chirho(
        HostPrivateCaptureKindChirho::FormerOwnerLogChirho,
        b"deposed at /var/lib/cairn-item6-drill-chirho/owner".to_vec(),
    );
    let leaked_member_chirho = ShareableBundleMemberChirho::new_chirho(
        "leaked-capture-chirho.txt",
        capture_chirho.raw_bytes_chirho().to_vec(),
    );
    controls_chirho.push(matches!(
        package_shareable_bundle_chirho(vec![leaked_member_chirho]),
        Err(BundleRefusalChirho::ForbiddenMarkerChirho {
            reason_chirho: ForbiddenMarkerReasonChirho::HostPathChirho,
            ..
        })
    ));

    // 8. An empty bundle is refused.
    controls_chirho.push(matches!(
        package_shareable_bundle_chirho(Vec::new()),
        Err(BundleRefusalChirho::NoMembersChirho)
    ));

    // 9. An unsafe member name (containing `/`) is refused.
    controls_chirho.push(matches!(
        package_shareable_bundle_chirho(vec![ShareableBundleMemberChirho::new_chirho(
            "sub/dir-chirho.txt",
            b"safe".to_vec()
        )]),
        Err(BundleRefusalChirho::UnsafeMemberNameChirho { .. })
    ));

    // 10. A duplicate member name is refused.
    controls_chirho.push(matches!(
        package_shareable_bundle_chirho(vec![
            ShareableBundleMemberChirho::new_chirho("dup-chirho.txt", b"a".to_vec()),
            ShareableBundleMemberChirho::new_chirho("dup-chirho.txt", b"b".to_vec()),
        ]),
        Err(BundleRefusalChirho::DuplicateMemberNameChirho { .. })
    ));

    // 11. The fixed nonclaims block itself survives the no-leak scan (a safe control, not a needle).
    controls_chirho.push(scan_member_chirho(&nonclaims_member_chirho()).is_ok());

    let controls_passed_chirho = controls_chirho
        .iter()
        .filter(|passed_chirho| **passed_chirho)
        .count();
    BundleSelftestReportChirho {
        controls_run_chirho: controls_chirho.len(),
        controls_passed_chirho,
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn safe_control_member_chirho() -> ShareableBundleMemberChirho {
        safe_member_chirho()
    }

    #[test]
    fn safe_bundle_packages_and_verifies_with_nonclaims_chirho() {
        let bundle_chirho = package_shareable_bundle_chirho(vec![safe_control_member_chirho()])
            .expect("a safe member packages");
        assert!(bundle_chirho.has_nonclaims_chirho());
        // members = the caller member + the auto-appended nonclaims block.
        assert_eq!(bundle_chirho.members_chirho().len(), 2);
        // The manifest has one line per member and a 64-hex bundle digest.
        assert_eq!(bundle_chirho.manifest_chirho().lines_chirho().len(), 2);
        assert_eq!(
            bundle_chirho.manifest_chirho().bundle_digest_chirho().len(),
            64
        );
        verify_shareable_bundle_chirho(&bundle_chirho).expect("a freshly packaged bundle verifies");
    }

    #[test]
    fn each_planted_needle_blocks_publication_and_safe_control_survives_chirho() {
        // The privacy mutation arms: each planted needle BLOCKS the whole bundle with its marker class.
        let needle_cases_chirho = [
            (
                "/etc/cairn-chirho/secrets",
                ForbiddenMarkerReasonChirho::HostPathChirho,
            ),
            ("Bearer abc.def", ForbiddenMarkerReasonChirho::BearerChirho),
            (
                "email_address=owner@example.test",
                ForbiddenMarkerReasonChirho::PrincipalChirho,
            ),
            (
                "provider_payload={...}",
                ForbiddenMarkerReasonChirho::ProviderBytesChirho,
            ),
        ];
        for (needle_chirho, expected_reason_chirho) in needle_cases_chirho {
            let member_chirho = ShareableBundleMemberChirho::new_chirho(
                "candidate-chirho.txt",
                needle_chirho.as_bytes().to_vec(),
            );
            let refusal_chirho = package_shareable_bundle_chirho(vec![member_chirho]).unwrap_err();
            assert!(
                matches!(
                    refusal_chirho,
                    BundleRefusalChirho::ForbiddenMarkerChirho { reason_chirho, .. }
                        if reason_chirho == expected_reason_chirho
                ),
                "needle {needle_chirho:?} must block with {expected_reason_chirho:?}, got {refusal_chirho:?}"
            );
        }
        // Positive control: a safe bounded digest/status member is NOT a false positive.
        package_shareable_bundle_chirho(vec![safe_control_member_chirho()])
            .expect("safe control survives the no-leak scan");
    }

    #[test]
    fn a_needle_beside_safe_members_blocks_the_whole_bundle_chirho() {
        // Fail closed at the bundle level: one dirty member sinks the whole publish, not just itself.
        let refusal_chirho = package_shareable_bundle_chirho(vec![
            safe_control_member_chirho(),
            ShareableBundleMemberChirho::new_chirho(
                "second-chirho.txt",
                b"authorization: bearer leak".to_vec(),
            ),
        ])
        .unwrap_err();
        assert!(matches!(
            refusal_chirho,
            BundleRefusalChirho::ForbiddenMarkerChirho { .. }
        ));
    }

    #[test]
    fn a_tampered_member_fails_the_verifier_chirho() {
        // The manifest is exact: mutate one member's bytes after packaging and the recomputed manifest
        // no longer matches, so the frozen verifier refuses.
        let mut bundle_chirho =
            package_shareable_bundle_chirho(vec![safe_control_member_chirho()]).unwrap();
        bundle_chirho.members_chirho[0]
            .bytes_chirho
            .extend_from_slice(b"tamper");
        let refusal_chirho = verify_shareable_bundle_chirho(&bundle_chirho).unwrap_err();
        assert_eq!(refusal_chirho, BundleRefusalChirho::ManifestMismatchChirho);
    }

    #[test]
    fn a_tampered_manifest_digest_fails_the_verifier_chirho() {
        let mut bundle_chirho =
            package_shareable_bundle_chirho(vec![safe_control_member_chirho()]).unwrap();
        bundle_chirho.manifest_chirho.bundle_digest_chirho = "f".repeat(64);
        assert_eq!(
            verify_shareable_bundle_chirho(&bundle_chirho).unwrap_err(),
            BundleRefusalChirho::ManifestMismatchChirho
        );
    }

    #[test]
    fn host_private_capture_bytes_are_refused_by_the_packager_chirho() {
        // Host-private captures are excluded by TYPE (there is no conversion into a member); as a
        // backstop, if a capture's bytes were routed into a member, the no-leak scan rejects them.
        let capture_chirho = HostPrivateCaptureChirho::new_chirho(
            HostPrivateCaptureKindChirho::NftListChirho,
            b"table ip filter chain input at /var/lib/cairn-item6-drill-chirho".to_vec(),
        );
        let leaked_member_chirho = ShareableBundleMemberChirho::new_chirho(
            "leaked-nft-list-chirho.txt",
            capture_chirho.raw_bytes_chirho().to_vec(),
        );
        let refusal_chirho =
            package_shareable_bundle_chirho(vec![leaked_member_chirho]).unwrap_err();
        assert!(matches!(
            refusal_chirho,
            BundleRefusalChirho::ForbiddenMarkerChirho {
                reason_chirho: ForbiddenMarkerReasonChirho::HostPathChirho,
                ..
            }
        ));
    }

    #[test]
    fn empty_reserved_dup_and_unsafe_names_are_refused_chirho() {
        assert_eq!(
            package_shareable_bundle_chirho(Vec::new()).unwrap_err(),
            BundleRefusalChirho::NoMembersChirho
        );
        assert!(matches!(
            package_shareable_bundle_chirho(vec![ShareableBundleMemberChirho::new_chirho(
                NONCLAIMS_MEMBER_NAME_CHIRHO,
                b"caller-collision".to_vec()
            )])
            .unwrap_err(),
            BundleRefusalChirho::ReservedMemberNameChirho { .. }
        ));
        assert!(matches!(
            package_shareable_bundle_chirho(vec![ShareableBundleMemberChirho::new_chirho(
                "Bad Name.txt",
                b"x".to_vec()
            )])
            .unwrap_err(),
            BundleRefusalChirho::UnsafeMemberNameChirho { .. }
        ));
    }

    #[test]
    fn manifest_lines_match_sha256sum_format_chirho() {
        // An operator can cross-check a member with the standard `sha256sum` tool: the line is
        // `<64-hex>  <name>` (two spaces), and the hex is sha256 of the member bytes.
        let member_chirho =
            ShareableBundleMemberChirho::new_chirho("only-chirho.txt", b"the-exact-bytes".to_vec());
        let bundle_chirho = package_shareable_bundle_chirho(vec![member_chirho]).unwrap();
        let expected_line_chirho =
            format!("{}  only-chirho.txt", sha256_hex_chirho(b"the-exact-bytes"));
        assert!(bundle_chirho
            .manifest_chirho()
            .lines_chirho()
            .contains(&expected_line_chirho));
    }

    #[test]
    fn selftest_runs_every_pinned_control_and_all_behave_chirho() {
        let report_chirho = bundle_verifier_selftest_chirho();
        assert_eq!(
            report_chirho.controls_run_chirho,
            BUNDLE_SELFTEST_CONTROL_COUNT_CHIRHO
        );
        assert_eq!(
            report_chirho.controls_passed_chirho,
            report_chirho.controls_run_chirho
        );
        assert!(report_chirho.all_behaved_chirho());
    }
}
