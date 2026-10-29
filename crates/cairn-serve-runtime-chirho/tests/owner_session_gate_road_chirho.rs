// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him
// should not perish, but have everlasting life. — John 3:16 (KJV)

//! Executes the discriminating tampered-kind-without-resigning arm through the REAL promote route,
//! `POST /app-review-chirho/:kind/:id/:app/promote-chirho`, whose owner gate is
//! `require_owner_session_chirho`.
//!
//! Why this file exists separately from `publish_owner_gate_chirho`: that suite covers the
//! `/publish-chirho` session branch, which now calls the VERIFIED `ensure_owner_principal_chirho`.
//! `require_owner_session_chirho` is a different gate on a different road with twelve production
//! callers, and reading says nothing on that road verifies the identity log. Reading is not
//! measurement, so this executes it.
//!
//! The discriminator is the gate's own REFUSAL IDENTITY, never the status code alone: the promote
//! handler fails for unrelated reasons once the gate is passed, so two arms could otherwise return
//! the same 4xx for entirely different reasons and look like agreement.

use cairn_chirho::identity_chirho;
use cairn_serve_runtime_chirho::serve_quiet_with_registration_token_chirho;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
};

const REG_TOKEN_CHIRHO: &str = "owner-road-reg-token-chirho";
const PUBLISH_TOKEN_CHIRHO: &str = "owner-road-publish-token-chirho";
const CREDENTIAL_CHIRHO: &str = "OwnerRoadP4ssw0rd";
/// The literal `require_owner_session_chirho` emits when it refuses a non-owner kind. Presence of
/// this string means the gate DECIDED; absence means execution went past it.
const GATE_REFUSAL_CHIRHO: &str = "requires an owner principal";
/// A credential the "attacker" in the composition arm does NOT hold.
const VICTIM_CREDENTIAL_CHIRHO: &str = "VictimOwnerP4ssw0rd";

/// Instrument control: the gate must actually refuse an honest non-owner, or the other two arms
/// are measuring a gate that never fires and every verdict below is vacuous.
#[test]
fn an_untampered_user_session_is_refused_by_the_owner_gate_chirho() {
    with_server_chirho("road-user", |_root_chirho, addr_chirho| {
        let user_chirho = register_user_chirho(addr_chirho);
        let token_chirho = login_token_chirho(addr_chirho, &user_chirho);
        let response_chirho = promote_chirho(addr_chirho, &user_chirho, &token_chirho);
        let body_chirho = String::from_utf8_lossy(&response_chirho.body_chirho).to_string();
        assert_eq!(
            response_chirho.status_chirho, 403,
            "an honest user must be refused by the owner gate; body={body_chirho}"
        );
        assert!(
            body_chirho.contains(GATE_REFUSAL_CHIRHO),
            "the refusal must carry the GATE's identity, not some downstream error; body={body_chirho}"
        );
    });
}

/// The measurement. A `kind_chirho` flipped user -> Owner WITHOUT resigning is exactly the case a
/// signature check catches and a raw read cannot. `/publish-chirho` refuses it. This asserts the
/// same property on the owner-session road.
///
/// MIGRATION PATH: if this arm goes RED with the response lacking `GATE_REFUSAL_CHIRHO`, the gate
/// admitted a forged owner claim and the finding is real — do not "fix" the test. If it goes red
/// because the status is 401, the fixture's session broke and the arm proves nothing; repair the
/// fixture first.
#[test]
fn a_kind_corrupted_without_resigning_is_refused_by_the_owner_gate_chirho() {
    with_server_chirho("road-corrupt", |root_chirho, addr_chirho| {
        let user_chirho = register_user_chirho(addr_chirho);
        let token_chirho = login_token_chirho(addr_chirho, &user_chirho);

        let log_chirho = root_chirho.join("identities-chirho.jsonl");
        let text_chirho = std::fs::read_to_string(&log_chirho).expect("identity log");
        let tampered_chirho = text_chirho.replace(
            "\"kind_chirho\":\"UserChirho\"",
            "\"kind_chirho\":\"OwnerChirho\"",
        );
        assert_ne!(
            tampered_chirho, text_chirho,
            "arming: the tamper must actually change the identity log, or this arm proves nothing"
        );
        std::fs::write(&log_chirho, &tampered_chirho).expect("write tampered log");

        let response_chirho = promote_chirho(addr_chirho, &user_chirho, &token_chirho);
        let body_chirho = String::from_utf8_lossy(&response_chirho.body_chirho).to_string();
        assert_ne!(
            response_chirho.status_chirho, 401,
            "fixture check: a 401 means the session itself failed, so this arm measured nothing"
        );
        // RETARGETED after the verified-map repair, fixture untouched. Before it, this returned
        // 400 "object ... not in store" — the PROMOTE handler's error, i.e. past the gate and
        // byte-equivalent to a real owner. It now dies at the gate.
        assert!(
            !body_chirho.contains("not in store"),
            "the forged owner must not reach promote business logic; status={} body={body_chirho}",
            response_chirho.status_chirho
        );
        assert_eq!(
            response_chirho.status_chirho, 400,
            "the unverifiable row fails the whole verified map load, which takes the gate's \
             pre-existing Err arm; body={body_chirho}"
        );
        assert!(
            body_chirho.contains("signature invalid"),
            "assert the REASON, not merely a 4xx: the refusal must name signature verification, or \
             this arm would pass for an unrelated failure; body={body_chirho}"
        );
    });
}

/// Positive control for "past the gate": a real Owner must NOT receive the gate refusal, so that
/// the assertion above can distinguish admitted from refused rather than passing for any 4xx.
#[test]
fn a_real_owner_session_is_not_refused_by_the_owner_gate_chirho() {
    with_server_chirho("road-owner", |root_chirho, addr_chirho| {
        let owner_chirho = register_owner_chirho(root_chirho);
        let token_chirho = login_token_chirho(addr_chirho, &owner_chirho);
        let response_chirho = promote_chirho(addr_chirho, &owner_chirho, &token_chirho);
        let body_chirho = String::from_utf8_lossy(&response_chirho.body_chirho).to_string();
        assert!(
            !body_chirho.contains(GATE_REFUSAL_CHIRHO),
            "a real owner must pass the gate; if this fires the discriminator is broken and both \
             other arms are meaningless. status={} body={body_chirho}",
            response_chirho.status_chirho
        );
        // Pin what "past the gate" LOOKS like, so the tampered arm's outcome can be compared to an
        // authorized principal's rather than merely to the absence of one string.
        assert_eq!(
            response_chirho.status_chirho, 400,
            "past-the-gate shape: the promote handler rejects the fabricated candidate; body={body_chirho}"
        );
        assert!(
            body_chirho.contains("not in store"),
            "past-the-gate shape: the error must come from the promote handler; body={body_chirho}"
        );
    });
}

/// gpt #19733 asks whether `verify_session_record_chirho` taking its PUBLIC KEY from an unverified
/// identity row is a SEPARATE integrity issue. Measured here: swap that row's `pubkey_chirho` for
/// another real principal's, without resigning, and try the existing session.
///
/// The session carries TWO proofs — `proof_chirho` against the identity pubkey, and `sig_chirho`
/// against the ROOT key. Only the root key is unforgeable by a log writer. So the question is
/// whether the pubkey read fails OPEN (escalation) or CLOSED (denial only).
#[test]
fn a_swapped_pubkey_without_resigning_invalidates_the_session_chirho() {
    with_server_chirho("road-pubkey", |root_chirho, addr_chirho| {
        let victim_chirho = register_user_chirho(addr_chirho);
        let token_chirho = login_token_chirho(addr_chirho, &victim_chirho);
        // Sanity: the session works BEFORE the swap, or the arm proves nothing.
        let before_chirho = promote_chirho(addr_chirho, &victim_chirho, &token_chirho);
        assert_eq!(
            before_chirho.status_chirho, 403,
            "arming: the honest session must reach the owner gate before the swap"
        );

        let other_chirho = register_user_chirho(addr_chirho);
        let log_chirho = root_chirho.join("identities-chirho.jsonl");
        let text_chirho = std::fs::read_to_string(&log_chirho).expect("identity log");
        let victim_key_chirho = pubkey_for_chirho(&text_chirho, &victim_chirho);
        let other_key_chirho = pubkey_for_chirho(&text_chirho, &other_chirho);
        assert_ne!(
            victim_key_chirho, other_key_chirho,
            "arming: two principals must have different keys for this swap to mean anything"
        );
        let swapped_chirho = text_chirho.replacen(&victim_key_chirho, &other_key_chirho, 1);
        assert_ne!(
            swapped_chirho, text_chirho,
            "arming: the pubkey swap must actually change the log"
        );
        std::fs::write(&log_chirho, &swapped_chirho).expect("write swapped log");

        let after_chirho = promote_chirho(addr_chirho, &victim_chirho, &token_chirho);
        let body_chirho = String::from_utf8_lossy(&after_chirho.body_chirho).to_string();
        assert!(
            !body_chirho.contains("not in store"),
            "FAIL-OPEN: a swapped pubkey must not leave the session usable; status={} body={body_chirho}",
            after_chirho.status_chirho
        );
        assert!(
            (400..500).contains(&after_chirho.status_chirho),
            "a session whose local key proof no longer verifies must be refused; status={}",
            after_chirho.status_chirho
        );
    });
}

/// The pricing question in gpt #19733: is the SMALLEST repair the kind decision alone, or does the
/// login road need treatment too? Measures three things about ONE forged-owner row:
///   1. does login mint a session for a row whose signature does not verify?
///   2. does the VERIFIED check (the 88b6c579 repair pattern) refuse that principal?
///   3. does the unrepaired owner-session road admit it?
///
/// Together those price the repair without assuming the publish one-liner transfers.
#[test]
fn a_forged_owner_row_logs_in_yet_the_verified_check_refuses_it_chirho() {
    with_server_chirho("road-pricing", |root_chirho, addr_chirho| {
        let user_chirho = register_user_chirho(addr_chirho);
        let log_chirho = root_chirho.join("identities-chirho.jsonl");
        let text_chirho = std::fs::read_to_string(&log_chirho).expect("identity log");
        let tampered_chirho = text_chirho.replace(
            "\"kind_chirho\":\"UserChirho\"",
            "\"kind_chirho\":\"OwnerChirho\"",
        );
        assert_ne!(
            tampered_chirho, text_chirho,
            "arming: the tamper must actually change the identity log"
        );
        std::fs::write(&log_chirho, &tampered_chirho).expect("write tampered log");

        // (1) LOGIN, fresh — not a token minted before the tamper.
        let token_chirho = login_token_chirho(addr_chirho, &user_chirho);
        assert!(
            !token_chirho.is_empty(),
            "recorded: login admits a row whose signature no longer verifies"
        );

        // (2) The verified check — the repair pattern that closed /publish-chirho.
        let verified_chirho =
            cairn_chirho::app_chirho::ensure_owner_principal_chirho(root_chirho, &user_chirho);
        assert!(
            verified_chirho.is_err(),
            "the VERIFIED check must refuse a forged owner row; that is what prices the repair"
        );

        // (3) The unrepaired road, same principal, same process.
        let response_chirho = promote_chirho(addr_chirho, &user_chirho, &token_chirho);
        let body_chirho = String::from_utf8_lossy(&response_chirho.body_chirho).to_string();
        // RETARGETED: pre-repair this asserted the road ADMITTED the principal the verified check
        // refused — the whole point of the finding. Post-repair the road and the verified check
        // agree, which is the repair's success condition stated as an arm.
        assert!(
            !body_chirho.contains("not in store"),
            "the road must now agree with the verified check and refuse; status={} body={body_chirho}",
            response_chirho.status_chirho
        );
    });
}

/// Extract a principal's `pubkey_chirho` from the raw identity log. Fails loudly: a silent empty
/// string would make the swap above a no-op that still passed its own assertions.
fn pubkey_for_chirho(log_chirho: &str, principal_chirho: &str) -> String {
    let line_chirho = log_chirho
        .lines()
        .find(|line_chirho| line_chirho.contains(&format!("\"{principal_chirho}\"")))
        .unwrap_or_else(|| panic!("no identity row for {principal_chirho}"));
    let key_chirho = between_chirho(line_chirho, "\"pubkey_chirho\":\"", "\"");
    assert!(
        !key_chirho.is_empty(),
        "pubkey_chirho must parse out of the row for {principal_chirho}"
    );
    key_chirho
}

/// claude_chirho #19734 §4 flagged this as adjacent-and-unmeasured: does a writable CREDENTIAL
/// store compose with a writable identity log into session forgery? Measured rather than reasoned.
///
/// First fact, from the layout: the credential is NOT a separate signed log. It lives in the
/// per-principal key file `identity-keys-chirho/<principal>.json` beside the SECRET KEY, and
/// `load_identity_key_record_chirho` checks only that the principal name matches — no signature.
/// So "writable credential store" and "writable key file" are the same capability.
///
/// The attack: overwrite a victim OWNER's key file with the attacker's own, so the attacker's
/// credential opens the victim's account. This deliberately leaves the identity ROW untouched, so
/// the verified loader has nothing to object to — which is exactly the case that would slip past
/// the repair being priced.
#[test]
fn an_overwritten_credential_alone_does_not_forge_owner_authority_chirho() {
    with_server_chirho("road-compose", |root_chirho, addr_chirho| {
        let victim_chirho = register_owner_with_chirho(root_chirho, VICTIM_CREDENTIAL_CHIRHO);
        let attacker_chirho = register_user_chirho(addr_chirho);

        // Arming: without the overwrite the attacker's credential must NOT open the victim, or the
        // arm below would pass for a reason that has nothing to do with the key file.
        assert!(
            try_login_chirho(addr_chirho, &victim_chirho, CREDENTIAL_CHIRHO).is_none(),
            "arming: the attacker's credential must not open the victim before the overwrite"
        );

        let keys_chirho = root_chirho.join("identity-keys-chirho");
        let victim_path_chirho =
            keys_chirho.join(format!("{}.json", victim_chirho.replace('/', "__")));
        let attacker_path_chirho =
            keys_chirho.join(format!("{}.json", attacker_chirho.replace('/', "__")));
        let attacker_key_chirho =
            std::fs::read_to_string(&attacker_path_chirho).expect("attacker key file");
        let forged_chirho = attacker_key_chirho.replace(&attacker_chirho, &victim_chirho);
        assert_ne!(
            forged_chirho, attacker_key_chirho,
            "arming: the principal rewrite must actually change the copied key file"
        );
        std::fs::write(&victim_path_chirho, &forged_chirho).expect("overwrite victim key file");

        // The identity ROW is untouched, so a verified load still accepts the victim.
        assert!(
            cairn_chirho::app_chirho::ensure_owner_principal_chirho(root_chirho, &victim_chirho)
                .is_ok(),
            "arming: the victim's signed identity row must still verify, or this arm is not testing \
             the case that slips past the repair"
        );

        // (1) Does the overwritten credential open the account?
        let token_chirho = try_login_chirho(addr_chirho, &victim_chirho, CREDENTIAL_CHIRHO);
        // (2) Whether or not it does, the session must not yield owner authority: the minted proof
        // is signed by the ATTACKER's key while the victim's row still publishes the victim's
        // pubkey, and verify_session_record_chirho checks the proof against THAT.
        if let Some(token_chirho) = token_chirho {
            let response_chirho = promote_chirho(addr_chirho, &victim_chirho, &token_chirho);
            let body_chirho = String::from_utf8_lossy(&response_chirho.body_chirho).to_string();
            assert!(
                !body_chirho.contains("not in store"),
                "FAIL-OPEN COMPOSITION: overwriting the key file alone yielded owner authority; \
                 status={} body={body_chirho}",
                response_chirho.status_chirho
            );
        }
    });
}

/// PFECHIRHO/claude_chirho #19735 named the composition my earlier arm deliberately did NOT test,
/// and warned it could produce FALSE CLOSURE: swap the victim's `pubkey_chirho` to a key you hold
/// AND supply a matching proof, so the circular verification succeeds. That is principal FORGERY
/// rather than escalation.
///
/// The step that makes it real is LOGIN: the attacker cannot sign `sig_chirho`, but the SERVER will,
/// because `login_identity_internal_chirho` does only a raw existence check and then signs a session
/// whose `proof_chirho` comes from whatever secret sits in the key file.
///
/// This arm executes the full composition and then asks the question that decides the repair's
/// scope: does the VERIFIED check refuse the same principal? If yes, the one-line kind swap is
/// sufficient and there is no false closure. If no, the repair is a road, not a line.
#[test]
fn the_full_forgery_composition_is_refused_by_the_verified_check_chirho() {
    with_server_chirho("road-forge", |root_chirho, addr_chirho| {
        let victim_chirho = register_owner_with_chirho(root_chirho, VICTIM_CREDENTIAL_CHIRHO);
        let attacker_chirho = register_user_chirho(addr_chirho);

        let log_path_chirho = root_chirho.join("identities-chirho.jsonl");
        let log_chirho = std::fs::read_to_string(&log_path_chirho).expect("identity log");
        let victim_key_chirho = pubkey_for_chirho(&log_chirho, &victim_chirho);
        let attacker_key_chirho = pubkey_for_chirho(&log_chirho, &attacker_chirho);

        // (1) swap the victim's published pubkey for the attacker's, WITHOUT resigning the row.
        let swapped_chirho = log_chirho.replacen(&victim_key_chirho, &attacker_key_chirho, 1);
        assert_ne!(
            swapped_chirho, log_chirho,
            "arming: the pubkey swap must actually change the identity log"
        );
        std::fs::write(&log_path_chirho, &swapped_chirho).expect("write swapped log");

        // (2) give the victim's account the attacker's secret key AND credential.
        let keys_chirho = root_chirho.join("identity-keys-chirho");
        let attacker_file_chirho = std::fs::read_to_string(
            keys_chirho.join(format!("{}.json", attacker_chirho.replace('/', "__"))),
        )
        .expect("attacker key file");
        let forged_chirho = attacker_file_chirho.replace(&attacker_chirho, &victim_chirho);
        assert_ne!(
            forged_chirho, attacker_file_chirho,
            "arming: the principal rewrite must actually change the copied key file"
        );
        std::fs::write(
            keys_chirho.join(format!("{}.json", victim_chirho.replace('/', "__"))),
            &forged_chirho,
        )
        .expect("overwrite victim key file");

        // (3) the server mints the session, so `sig_chirho` is legitimately root-signed.
        let token_chirho = try_login_chirho(addr_chirho, &victim_chirho, CREDENTIAL_CHIRHO)
            .expect("recorded: the composition logs in as the victim owner");

        // (4) THE DECIDING QUESTION — does the verified check refuse this principal?
        let verified_chirho =
            cairn_chirho::app_chirho::ensure_owner_principal_chirho(root_chirho, &victim_chirho);
        assert!(
            verified_chirho.is_err(),
            "NO FALSE CLOSURE ONLY IF THIS HOLDS: the verified check must refuse a principal whose \
             row was edited to carry the attacker's key. If this ever passes, the kind-swap repair \
             is insufficient and the session road needs its own treatment."
        );

        // (5) and the unrepaired road, for the record: it admits the forged principal.
        let response_chirho = promote_chirho(addr_chirho, &victim_chirho, &token_chirho);
        let body_chirho = String::from_utf8_lossy(&response_chirho.body_chirho).to_string();
        // RETARGETED, same reason as above: the forged principal no longer reaches promote.
        assert!(
            !body_chirho.contains("not in store"),
            "the forged principal must not reach promote; status={} body={body_chirho}",
            response_chirho.status_chirho
        );
    });
}

/// gpt #19779 named this as the PASS boundary of `50a7f7dd` and it was correct: nothing in the suite
/// pinned IMPERSONATION BY NAMING — a caller holding a VALID session for principal A naming a
/// DIFFERENT, REAL, Owner principal B in the path. Every existing arm reaches the gate either by
/// tampering the identity log or by naming a principal that does not exist, so none of them
/// exercises the caller composition where both principals are legitimate and only the BINDING
/// between session and named principal is at stake.
///
/// This is the case a real attacker has without touching the host: an ordinary signed-up user, a
/// browser, and the name of an owner. It needs no filesystem access at all, which makes it a
/// strictly cheaper attack than everything else in this file.
#[test]
fn a_valid_user_session_cannot_name_a_real_owner_chirho() {
    with_server_chirho("road-impersonate", |root_chirho, addr_chirho| {
        let attacker_chirho = register_user_chirho(addr_chirho);
        let attacker_token_chirho = login_token_chirho(addr_chirho, &attacker_chirho);
        let victim_owner_chirho = register_owner_chirho(root_chirho);
        assert_ne!(
            attacker_chirho, victim_owner_chirho,
            "arming: the two principals must differ or this arm tests nothing"
        );

        // Arming, both halves. The attacker's session must be GENUINELY VALID — otherwise the
        // refusal below would come from a dead session rather than from the binding under test.
        let own_chirho = promote_chirho(addr_chirho, &attacker_chirho, &attacker_token_chirho);
        assert_eq!(
            own_chirho.status_chirho, 403,
            "arming: the attacker's own session must reach the OWNER gate (403), proving it is live"
        );
        assert!(
            String::from_utf8_lossy(&own_chirho.body_chirho).contains(GATE_REFUSAL_CHIRHO),
            "arming: reaching the owner gate is what makes the session demonstrably valid"
        );
        // And the named owner must be a REAL owner who really can pass that gate, or "refused"
        // would prove nothing about naming.
        let victim_token_chirho = login_token_chirho(addr_chirho, &victim_owner_chirho);
        let victim_chirho = promote_chirho(addr_chirho, &victim_owner_chirho, &victim_token_chirho);
        assert!(
            String::from_utf8_lossy(&victim_chirho.body_chirho).contains("not in store"),
            "arming: the named principal must be an owner who genuinely passes the gate"
        );

        // THE MEASUREMENT: attacker's valid token, victim owner's principal in the path.
        let response_chirho =
            promote_chirho(addr_chirho, &victim_owner_chirho, &attacker_token_chirho);
        let body_chirho = String::from_utf8_lossy(&response_chirho.body_chirho).to_string();
        assert!(
            !body_chirho.contains("not in store"),
            "IMPERSONATION BY NAMING: a user session reached owner business logic by naming an \
             owner; status={} body={body_chirho}",
            response_chirho.status_chirho
        );
        assert!(
            !body_chirho.contains(GATE_REFUSAL_CHIRHO),
            "assert the REASON: this must be refused by the SESSION binding, not by the owner-kind \
             gate. Reaching the kind gate would mean the session bound to the wrong principal and \
             was saved only by the named principal happening to be checked; body={body_chirho}"
        );
        assert_eq!(
            response_chirho.status_chirho, 403,
            "the session binding refuses with the existing forbidden status; body={body_chirho}"
        );
    });
}

fn register_owner_with_chirho(root_chirho: &Path, credential_chirho: &str) -> String {
    identity_chirho::register_identity_with_credential_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        credential_chirho,
    )
    .expect("owner registration")
    .principal_chirho
}

/// Login that reports failure instead of panicking, so an arm can assert a login MUST NOT succeed.
fn try_login_chirho(
    addr_chirho: &str,
    principal_chirho: &str,
    credential_chirho: &str,
) -> Option<String> {
    let body_chirho =
        format!("principal_chirho={principal_chirho}&credential_chirho={credential_chirho}");
    let response_chirho = http_post_chirho(
        addr_chirho,
        "/auth-chirho/login-chirho",
        "application/x-www-form-urlencoded",
        &body_chirho,
        None,
    );
    let cookie_chirho = response_chirho
        .headers_chirho
        .iter()
        .find(|line_chirho| line_chirho.to_ascii_lowercase().starts_with("set-cookie:"))?;
    let value_chirho = between_chirho(cookie_chirho, "cairn_session_chirho=", ";");
    if value_chirho.is_empty() {
        return None;
    }
    Some(
        value_chirho
            .split_once(':')
            .map(|(_, t_chirho)| t_chirho.to_string())
            .unwrap_or(value_chirho),
    )
}

/// gpt DM #495 requires proof that the authority repair changes NO response bytes on a healthy log.
/// Asserts the exact serialized body, not a substring: a substring check would pass against a body
/// that had gained an interpolated principal name, which is precisely the regression claude_chirho
/// measured in the `ensure_owner_principal_chirho` shape this repair deliberately avoids.
#[test]
fn the_ordinary_non_owner_refusal_bytes_are_unchanged_chirho() {
    with_server_chirho("road-bytes", |_root_chirho, addr_chirho| {
        let user_chirho = register_user_chirho(addr_chirho);
        let token_chirho = login_token_chirho(addr_chirho, &user_chirho);
        let response_chirho = promote_chirho(addr_chirho, &user_chirho, &token_chirho);
        let body_chirho = String::from_utf8_lossy(&response_chirho.body_chirho).to_string();
        assert_eq!(
            response_chirho.status_chirho, 403,
            "status class must not move"
        );
        assert_eq!(
            body_chirho.trim(),
            "{\"error_chirho\":\"support console requires an owner principal\",\"ok_chirho\":false}",
            "the non-owner refusal must be byte-identical to the pre-repair body"
        );
        assert!(
            !body_chirho.contains(&user_chirho),
            "the refusal must never name the principal"
        );
    });
}

/// The other half of gpt's byte requirement — and it returns a finding rather than a confirmation.
///
/// The gate's `None` arm emits "unknown owner principal", the existence oracle PFE claude_chirho and
/// claude_chirho ruled should be collapsed. Measured: it is NOT REACHABLE on this road.
/// `require_principal_session_chirho` runs FIRST, and an unknown principal has no session, so the
/// request dies before any kind lookup. That was true before the repair too.
/// Recording it because it PRICES the deferred privacy change: on this road the collapse is
/// defence-in-depth over an unreachable arm, not the closing of a live oracle.
#[test]
fn an_unknown_principal_dies_at_the_session_gate_not_the_owner_gate_chirho() {
    with_server_chirho("road-unknown", |_root_chirho, addr_chirho| {
        let real_chirho = register_user_chirho(addr_chirho);
        let token_chirho = login_token_chirho(addr_chirho, &real_chirho);
        let ghost_chirho = "user/definitely-not-a-principal-chirho";
        let response_chirho = promote_chirho(addr_chirho, ghost_chirho, &token_chirho);
        let body_chirho = String::from_utf8_lossy(&response_chirho.body_chirho).to_string();
        assert!(
            !body_chirho.contains("unknown owner principal"),
            "if this fires, the owner gate's None arm IS reachable and the deferred privacy \
             collapse closes a LIVE oracle rather than dead code; body={body_chirho}"
        );
        assert!(
            (401..=403).contains(&response_chirho.status_chirho),
            "an unknown principal must be refused before the kind lookup; status={} body={body_chirho}",
            response_chirho.status_chirho
        );
    });
}

/// THE AVAILABILITY TRADE, recorded as gpt required rather than papered over.
///
/// The verified map loads WHOLE: one unverifiable row fails the entire load, so the gate's Err arm
/// denies EVERY principal across all twelve callers, not merely the tampered one. That is the
/// correct fail-closed direction for an authority boundary AND a real operational cost — identity-log
/// corruption becomes a total support-console outage rather than a per-principal denial. An operator
/// meeting a 400 here should look for log corruption, not for a permissions problem.
#[test]
fn one_unverifiable_row_denies_every_owner_chirho() {
    with_server_chirho("road-availability", |root_chirho, addr_chirho| {
        // CREDENTIAL_CHIRHO, not VICTIM_CREDENTIAL_CHIRHO: `login_token_chirho` uses the former, and
        // the mismatch made login return no cookie — a fixture fault, caught by its own `expect`.
        let owner_chirho = register_owner_chirho(root_chirho);
        let token_chirho = login_token_chirho(addr_chirho, &owner_chirho);
        let before_chirho = promote_chirho(addr_chirho, &owner_chirho, &token_chirho);
        assert!(
            String::from_utf8_lossy(&before_chirho.body_chirho).contains("not in store"),
            "arming: the owner must pass the gate before any unrelated tamper"
        );

        // Tamper a DIFFERENT principal's row. The owner's own row is never touched.
        let _bystander_chirho = register_user_chirho(addr_chirho);
        let log_chirho = root_chirho.join("identities-chirho.jsonl");
        let text_chirho = std::fs::read_to_string(&log_chirho).expect("identity log");
        let tampered_chirho = text_chirho.replace(
            "\"kind_chirho\":\"UserChirho\"",
            "\"kind_chirho\":\"OwnerChirho\"",
        );
        assert_ne!(
            tampered_chirho, text_chirho,
            "arming: the tamper must change the log"
        );
        std::fs::write(&log_chirho, &tampered_chirho).expect("write tampered log");

        let after_chirho = promote_chirho(addr_chirho, &owner_chirho, &token_chirho);
        let body_chirho = String::from_utf8_lossy(&after_chirho.body_chirho).to_string();
        assert!(
            !body_chirho.contains("not in store"),
            "RECORDED TRADE: an untouched owner is denied because SOMEONE ELSE's row is \
             unverifiable; status={} body={body_chirho}",
            after_chirho.status_chirho
        );
    });
}

fn promote_chirho(
    addr_chirho: &str,
    principal_chirho: &str,
    token_chirho: &str,
) -> HttpResponseChirho {
    // The path principal must equal the session principal: the handler rebuilds `kind/id` from the
    // path and requires a session for exactly it.
    let (kind_chirho, id_chirho) = principal_chirho
        .split_once('/')
        .expect("principal is kind/id");
    let path_chirho = format!(
        "/app-review-chirho/{kind_chirho}/{id_chirho}/owner-road-app-chirho/promote-chirho"
    );
    // A well-formed form is REQUIRED: axum's Form extractor runs before the handler body, so a
    // missing field would 422 without ever reaching the gate and every arm would agree for the
    // wrong reason.
    let body_chirho = format!(
        "candidate_chirho={}&source_review_report_chirho={}",
        "0".repeat(64),
        "1".repeat(64)
    );
    http_post_chirho(
        addr_chirho,
        &path_chirho,
        "application/x-www-form-urlencoded",
        &body_chirho,
        Some(token_chirho),
    )
}

fn with_server_chirho(tag_chirho: &str, body_chirho: impl FnOnce(&Path, &str)) {
    let root_chirho = temp_root_chirho(tag_chirho);
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_quiet_with_registration_token_chirho(
                &root_for_server_chirho,
                port_chirho,
                8,
                PUBLISH_TOKEN_CHIRHO.to_string(),
                REG_TOKEN_CHIRHO.to_string(),
            )
            .await
        });
        wait_for_serve_chirho(&addr_chirho);
        body_chirho(&root_chirho, &addr_chirho);
        server_chirho.abort();
    });
}

fn register_user_chirho(addr_chirho: &str) -> String {
    let page_chirho = http_get_chirho(addr_chirho, "/auth-chirho/register-chirho");
    let html_chirho = String::from_utf8(page_chirho.body_chirho).unwrap();
    let token_chirho = between_chirho(
        &html_chirho,
        "name=\"human_check_token_chirho\" value=\"",
        "\"",
    );
    let answer_chirho: u32 = html_chirho
        .split("<label>")
        .filter_map(|segment_chirho| segment_chirho.split(" =").next())
        .find_map(|candidate_chirho| {
            let (left_chirho, right_chirho) = candidate_chirho.trim().split_once(" + ")?;
            Some(
                left_chirho.trim().parse::<u32>().ok()?
                    + right_chirho.trim().parse::<u32>().ok()?,
            )
        })
        .expect("the register page must present a solvable arithmetic challenge");
    let body_chirho = format!(
        "kind_chirho=user&registration_token_chirho={REG_TOKEN_CHIRHO}&credential_chirho={CREDENTIAL_CHIRHO}\
         &human_check_token_chirho={token_chirho}&human_check_chirho={answer_chirho}"
    );
    let response_chirho = http_post_chirho(
        addr_chirho,
        "/auth-chirho/register-chirho",
        "application/x-www-form-urlencoded",
        &body_chirho,
        None,
    );
    let text_chirho = String::from_utf8_lossy(&response_chirho.body_chirho).to_string();
    principal_in_chirho(&text_chirho, "user/").unwrap_or_else(|| {
        panic!(
            "registration must mint a user principal; status={} body={text_chirho}",
            response_chirho.status_chirho
        )
    })
}

fn register_owner_chirho(root_chirho: &Path) -> String {
    identity_chirho::register_identity_with_credential_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        CREDENTIAL_CHIRHO,
    )
    .expect("owner registration")
    .principal_chirho
}

fn login_token_chirho(addr_chirho: &str, principal_chirho: &str) -> String {
    let body_chirho =
        format!("principal_chirho={principal_chirho}&credential_chirho={CREDENTIAL_CHIRHO}");
    let response_chirho = http_post_chirho(
        addr_chirho,
        "/auth-chirho/login-chirho",
        "application/x-www-form-urlencoded",
        &body_chirho,
        None,
    );
    let cookie_chirho = response_chirho
        .headers_chirho
        .iter()
        .find(|line_chirho| line_chirho.to_ascii_lowercase().starts_with("set-cookie:"))
        .expect("login must set a session cookie");
    // The cookie is `principal:token`; validate_session_token_chirho hashes the TOKEN ALONE.
    let value_chirho = between_chirho(cookie_chirho, "cairn_session_chirho=", ";");
    value_chirho
        .split_once(':')
        .map(|(_, t_chirho)| t_chirho.to_string())
        .unwrap_or(value_chirho)
}

fn between_chirho(haystack_chirho: &str, start_chirho: &str, end_chirho: &str) -> String {
    let rest_chirho = match haystack_chirho.split_once(start_chirho) {
        Some((_, rest_chirho)) => rest_chirho,
        None => return String::new(),
    };
    rest_chirho
        .split_once(end_chirho)
        .map(|(value_chirho, _)| value_chirho.to_string())
        .unwrap_or_else(|| rest_chirho.to_string())
}

fn principal_in_chirho(text_chirho: &str, prefix_chirho: &str) -> Option<String> {
    let start_chirho = text_chirho.find(prefix_chirho)?;
    let tail_chirho = &text_chirho[start_chirho..];
    let end_chirho = tail_chirho
        .find(|c_chirho: char| {
            !(c_chirho.is_ascii_alphanumeric() || c_chirho == '/' || c_chirho == '-')
        })
        .unwrap_or(tail_chirho.len());
    Some(tail_chirho[..end_chirho].to_string())
}

fn temp_root_chirho(tag_chirho: &str) -> PathBuf {
    let base_chirho = std::env::temp_dir().join(format!(
        "cairn-owner-road-{tag_chirho}-{}-{:?}-chirho",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base_chirho).expect("create temp root");
    base_chirho
}

fn unused_local_port_chirho() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

fn wait_for_serve_chirho(addr_chirho: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr_chirho).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    panic!("server did not come up at {addr_chirho}");
}

fn http_get_chirho(addr_chirho: &str, path_chirho: &str) -> HttpResponseChirho {
    let mut stream_chirho = TcpStream::connect(addr_chirho).expect("connect");
    let request_chirho =
        format!("GET {path_chirho} HTTP/1.1\r\nHost: {addr_chirho}\r\nConnection: close\r\n\r\n");
    stream_chirho.write_all(request_chirho.as_bytes()).unwrap();
    read_response_chirho(stream_chirho)
}

fn http_post_chirho(
    addr_chirho: &str,
    path_chirho: &str,
    content_type_chirho: &str,
    body_chirho: &str,
    bearer_chirho: Option<&str>,
) -> HttpResponseChirho {
    let mut stream_chirho = TcpStream::connect(addr_chirho).expect("connect");
    let auth_chirho = bearer_chirho
        .map(|token_chirho| format!("Authorization: Bearer {token_chirho}\r\n"))
        .unwrap_or_default();
    let request_chirho = format!(
        "POST {path_chirho} HTTP/1.1\r\nHost: {addr_chirho}\r\nContent-Type: {content_type_chirho}\r\n\
         Content-Length: {}\r\n{auth_chirho}Connection: close\r\n\r\n{body_chirho}",
        body_chirho.len()
    );
    stream_chirho.write_all(request_chirho.as_bytes()).unwrap();
    read_response_chirho(stream_chirho)
}

fn read_response_chirho(mut stream_chirho: TcpStream) -> HttpResponseChirho {
    let mut bytes_chirho = Vec::new();
    let _ = stream_chirho.read_to_end(&mut bytes_chirho);
    let text_chirho = String::from_utf8_lossy(&bytes_chirho).to_string();
    let (head_chirho, body_chirho) = text_chirho
        .split_once("\r\n\r\n")
        .unwrap_or((&text_chirho, ""));
    let mut lines_chirho = head_chirho.lines();
    let status_chirho = lines_chirho
        .next()
        .and_then(|line_chirho| line_chirho.split_whitespace().nth(1))
        .and_then(|code_chirho| code_chirho.parse().ok())
        .unwrap_or(0);
    HttpResponseChirho {
        status_chirho,
        headers_chirho: lines_chirho.map(str::to_string).collect(),
        body_chirho: body_chirho.as_bytes().to_vec(),
    }
}

struct HttpResponseChirho {
    status_chirho: u16,
    headers_chirho: Vec<String>,
    body_chirho: Vec<u8>,
}
