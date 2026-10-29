// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::family_chirho::{LedgerMirrorJournalVerifierBindingChirho, LedgerMirrorRecordChirho};
use crate::recovery_chirho::{
    exact_prefix_refusal_identity_chirho, LedgerMirrorOrdinaryTermAcceptanceRequestChirho,
    LedgerMirrorRecoveryHeadRefusalChirho, LedgerMirrorRecoveryHeadRequestChirho,
    LedgerMirrorVerifiedPrefixManifestChirho, LedgerMirrorVerifiedPrefixPageChirho,
};
use crate::store_chirho::{LedgerMirrorLeaderPendingChirho, LedgerMirrorLeaderStoreChirho};
use crate::{
    LEDGER_MIRROR_FINALIZE_PATH_CHIRHO, LEDGER_MIRROR_ORDINARY_TERM_ACCEPTANCE_PATH_CHIRHO,
    LEDGER_MIRROR_PREFIX_BEGIN_PATH_CHIRHO, LEDGER_MIRROR_PREFIX_PAGE_PATH_CHIRHO,
    LEDGER_MIRROR_PREFIX_SEAL_PATH_CHIRHO, LEDGER_MIRROR_PREPARE_PATH_CHIRHO,
    LEDGER_MIRROR_RECOVERY_HEAD_PATH_CHIRHO,
};
use anyhow::{bail, Result};
use cairn_ledger_log_chirho::append_mirror_chirho::{
    LedgerAppendMirrorCandidateChirho, LedgerAppendMirrorPortChirho,
    LedgerAppendMirrorPortErrorChirho, LedgerAppendMirrorTailChirho,
};
use cairn_mirror_chirho::{
    decode_and_verify_mirror_receipt_chirho, join_mirror_view_chirho,
    FinalizeMirrorReceiptFrameInputChirho, FinalizeMirrorReceiptFrameV1Chirho,
    JoinedMirrorViewChirho, MirrorClosureManifestChirho, MirrorClosureManifestInputChirho,
    MirrorDurableCommitClassChirho, MirrorHolderFailureChirho, MirrorHolderPortChirho,
    MirrorHolderSetChirho, MirrorLeadershipViewChirho, MirrorReceiptChirho,
    MirrorReceiptStageChirho, MirrorRefusalIdentityChirho, MirrorResidencyPolicyChirho,
    MirrorTransportFailureChirho, PrepareMirrorClosureFrameInputChirho,
    PrepareMirrorClosureFrameV1Chirho, PreparedFinalizeMirrorReceiptFrameChirho,
    PreparedPrepareMirrorClosureFrameChirho, MIRROR_RECEIPT_WIRE_MAX_BYTES_CHIRHO,
};
use cairn_tenant_placement_authority_chirho::VerifiedTenantPlacementChirho;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/
// cf8-canary-window-loss-sequence-chirho.md. Bound peer connection establishment and exact signed
// term convergence at warm open without changing the request authority carried across attempts.
pub(crate) const RECOVERY_HEAD_READ_ATTEMPT_LIMIT_CHIRHO: usize = 8;
const RECOVERY_HEAD_RETRY_DELAY_CHIRHO: Duration = Duration::from_millis(500);

#[derive(Clone)]
pub(crate) struct LedgerMirrorDirectoryChirho {
    by_node_chirho: BTreeMap<String, String>,
}

impl LedgerMirrorDirectoryChirho {
    pub(crate) fn new_chirho(by_node_chirho: BTreeMap<String, String>) -> Self {
        Self { by_node_chirho }
    }

    fn holder_chirho(
        &self,
        node_id_chirho: &str,
        agent_chirho: &ureq::Agent,
    ) -> Result<HttpMirrorHolderChirho> {
        Ok(HttpMirrorHolderChirho {
            node_id_chirho: node_id_chirho.to_string(),
            endpoint_chirho: self
                .by_node_chirho
                .get(node_id_chirho)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPeerEndpointUnavailableChirho"))?,
            agent_chirho: agent_chirho.clone(),
            refusal_log_sink_chirho: MirrorLeaderRefusalLogSinkChirho::StderrChirho,
        })
    }

    pub(crate) fn read_recovery_head_chirho(
        &self,
        node_id_chirho: &str,
        request_chirho: &LedgerMirrorRecoveryHeadRequestChirho,
        agent_chirho: &ureq::Agent,
    ) -> Result<Option<Vec<u8>>> {
        self.read_recovery_head_with_retry_wait_chirho(
            node_id_chirho,
            request_chirho,
            agent_chirho,
            || std::thread::sleep(RECOVERY_HEAD_RETRY_DELAY_CHIRHO),
        )
    }

    fn read_recovery_head_with_retry_wait_chirho<RetryWaitChirho>(
        &self,
        node_id_chirho: &str,
        request_chirho: &LedgerMirrorRecoveryHeadRequestChirho,
        agent_chirho: &ureq::Agent,
        mut retry_wait_chirho: RetryWaitChirho,
    ) -> Result<Option<Vec<u8>>>
    where
        RetryWaitChirho: FnMut(),
    {
        let endpoint_chirho = self
            .by_node_chirho
            .get(node_id_chirho)
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPeerEndpointUnavailableChirho"))?;
        // The caller signs from one pre-read authority view. Serialize once and transmit these exact
        // bytes on every retry so a remote with newer authority cannot be accepted by chasing its term.
        let request_bytes_chirho = request_chirho.to_wire_bytes_chirho()?;
        let mut response_chirho = None;
        for attempt_chirho in 1..=RECOVERY_HEAD_READ_ATTEMPT_LIMIT_CHIRHO {
            match agent_chirho
                .post(&format!(
                    "{endpoint_chirho}{LEDGER_MIRROR_RECOVERY_HEAD_PATH_CHIRHO}"
                ))
                .set("content-type", "application/octet-stream")
                .send_bytes(&request_bytes_chirho)
            {
                Ok(success_chirho) => {
                    response_chirho = Some(success_chirho);
                    break;
                }
                Err(ureq::Error::Status(status_chirho, refusal_response_chirho)) => {
                    let mut refusal_bytes_chirho = Vec::new();
                    refusal_response_chirho
                        .into_reader()
                        .take(128)
                        .read_to_end(&mut refusal_bytes_chirho)
                        .map_err(|_| {
                            anyhow::anyhow!("LedgerMirrorRecoveryHeadReadRefusedChirho")
                        })?;
                    if status_chirho != 409 {
                        bail!("LedgerMirrorRecoveryHeadResponseRefusedChirho");
                    }
                    let Some(refusal_chirho) =
                        LedgerMirrorRecoveryHeadRefusalChirho::from_wire_bytes_chirho(
                            &refusal_bytes_chirho,
                        )
                    else {
                        bail!("LedgerMirrorRecoveryHeadResponseRefusedChirho");
                    };
                    if refusal_chirho == LedgerMirrorRecoveryHeadRefusalChirho::UNAVAILABLE_CHIRHO {
                        return Ok(None);
                    }
                    if refusal_chirho == LedgerMirrorRecoveryHeadRefusalChirho::TERM_MISMATCH_CHIRHO
                        && attempt_chirho < RECOVERY_HEAD_READ_ATTEMPT_LIMIT_CHIRHO
                    {
                        retry_wait_chirho();
                        continue;
                    }
                    bail!("{}", refusal_chirho.as_str_chirho());
                }
                Err(ureq::Error::Transport(transport_chirho))
                    if transport_chirho.kind() == ureq::ErrorKind::ConnectionFailed
                        && attempt_chirho < RECOVERY_HEAD_READ_ATTEMPT_LIMIT_CHIRHO =>
                {
                    retry_wait_chirho();
                }
                Err(ureq::Error::Transport(_)) => {
                    bail!("LedgerMirrorRecoveryHeadTransportRefusedChirho");
                }
            }
        }
        let response_chirho = response_chirho
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorRecoveryHeadTransportRefusedChirho"))?;
        if response_chirho.status() != 200 {
            bail!("LedgerMirrorRecoveryHeadResponseRefusedChirho");
        }
        let mut bytes_chirho = Vec::new();
        response_chirho
            .into_reader()
            .take(crate::recovery_chirho::RECOVERY_HEAD_MAX_BYTES_CHIRHO as u64 + 1)
            .read_to_end(&mut bytes_chirho)
            .map_err(|_| anyhow::anyhow!("LedgerMirrorRecoveryHeadReadRefusedChirho"))?;
        if bytes_chirho.len() > crate::recovery_chirho::RECOVERY_HEAD_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorRecoveryHeadTooLargeChirho");
        }
        Ok(Some(bytes_chirho))
    }

    #[cfg(test)]
    pub(crate) fn read_recovery_head_with_retry_wait_for_test_chirho<RetryWaitChirho>(
        &self,
        node_id_chirho: &str,
        request_chirho: &LedgerMirrorRecoveryHeadRequestChirho,
        agent_chirho: &ureq::Agent,
        retry_wait_chirho: RetryWaitChirho,
    ) -> Result<Option<Vec<u8>>>
    where
        RetryWaitChirho: FnMut(),
    {
        self.read_recovery_head_with_retry_wait_chirho(
            node_id_chirho,
            request_chirho,
            agent_chirho,
            retry_wait_chirho,
        )
    }

    pub(crate) fn read_ordinary_term_acceptance_receipt_chirho(
        &self,
        node_id_chirho: &str,
        request_chirho: &LedgerMirrorOrdinaryTermAcceptanceRequestChirho,
        agent_chirho: &ureq::Agent,
    ) -> Result<Vec<u8>> {
        let endpoint_chirho = self
            .by_node_chirho
            .get(node_id_chirho)
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPeerEndpointUnavailableChirho"))?;
        let response_chirho = match agent_chirho
            .post(&format!(
                "{endpoint_chirho}{LEDGER_MIRROR_ORDINARY_TERM_ACCEPTANCE_PATH_CHIRHO}"
            ))
            .set("content-type", "application/octet-stream")
            .send_bytes(&request_chirho.to_wire_bytes_chirho()?)
        {
            Ok(response_chirho) => response_chirho,
            Err(ureq::Error::Status(_, response_chirho)) => {
                let mut refusal_bytes_chirho = Vec::new();
                response_chirho
                    .into_reader()
                    .take(128)
                    .read_to_end(&mut refusal_bytes_chirho)
                    .map_err(|_| {
                        anyhow::anyhow!("LedgerMirrorOrdinaryTermAcceptanceReadRefusedChirho")
                    })?;
                let refusal_chirho = std::str::from_utf8(&refusal_bytes_chirho).unwrap_or("");
                if [
                    "LedgerMirrorOrdinaryTermRequestAuthorityRefusedChirho",
                    "LedgerMirrorReceiverHolderSelectionRefusedChirho",
                    "LedgerMirrorOrdinaryTermLiveHighWaterUnavailableChirho",
                    "LedgerMirrorOrdinaryTermLiveHighWaterBindingRefusedChirho",
                    "LedgerMirrorOrdinaryTermAuthorityChangedAfterHighWaterReadChirho",
                ]
                .contains(&refusal_chirho)
                {
                    bail!(refusal_chirho.to_owned());
                }
                bail!("LedgerMirrorOrdinaryTermAcceptanceResponseRefusedChirho");
            }
            Err(_) => bail!("LedgerMirrorOrdinaryTermAcceptanceTransportRefusedChirho"),
        };
        if response_chirho.status() != 200 {
            bail!("LedgerMirrorOrdinaryTermAcceptanceResponseRefusedChirho");
        }
        let mut bytes_chirho = Vec::new();
        response_chirho
            .into_reader()
            .take(
                cairn_ledger_log_chirho::recovery_mirror_chirho::ORDINARY_TERM_ACCEPTANCE_RECEIPT_MAX_BYTES_CHIRHO
                    as u64
                    + 1,
            )
            .read_to_end(&mut bytes_chirho)
            .map_err(|_| {
                anyhow::anyhow!("LedgerMirrorOrdinaryTermAcceptanceReadRefusedChirho")
            })?;
        if bytes_chirho.len()
            > cairn_ledger_log_chirho::recovery_mirror_chirho::ORDINARY_TERM_ACCEPTANCE_RECEIPT_MAX_BYTES_CHIRHO
        {
            bail!("LedgerMirrorOrdinaryTermAcceptanceReceiptTooLargeChirho");
        }
        Ok(bytes_chirho)
    }

    pub(crate) fn begin_verified_prefix_chirho(
        &self,
        node_id_chirho: &str,
        manifest_chirho: &LedgerMirrorVerifiedPrefixManifestChirho,
        agent_chirho: &ureq::Agent,
    ) -> Result<bool> {
        let response_chirho = self.send_recovery_bytes_chirho(
            node_id_chirho,
            LEDGER_MIRROR_PREFIX_BEGIN_PATH_CHIRHO,
            &manifest_chirho.to_wire_bytes_chirho()?,
            agent_chirho,
            "LedgerMirrorPrefixBeginTransportRefusedChirho",
        )?;
        match response_chirho.as_slice() {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => bail!("LedgerMirrorPrefixBeginResponseRefusedChirho"),
        }
    }

    pub(crate) fn send_verified_prefix_page_chirho(
        &self,
        node_id_chirho: &str,
        page_chirho: &LedgerMirrorVerifiedPrefixPageChirho,
        agent_chirho: &ureq::Agent,
    ) -> Result<()> {
        let response_chirho = self.send_recovery_bytes_chirho(
            node_id_chirho,
            LEDGER_MIRROR_PREFIX_PAGE_PATH_CHIRHO,
            &page_chirho.to_wire_bytes_chirho()?,
            agent_chirho,
            "LedgerMirrorPrefixPageTransportRefusedChirho",
        )?;
        if !response_chirho.is_empty() {
            bail!("LedgerMirrorPrefixPageResponseRefusedChirho");
        }
        Ok(())
    }

    pub(crate) fn seal_verified_prefix_chirho(
        &self,
        node_id_chirho: &str,
        manifest_chirho: &LedgerMirrorVerifiedPrefixManifestChirho,
        agent_chirho: &ureq::Agent,
    ) -> Result<()> {
        let response_chirho = self.send_recovery_bytes_chirho(
            node_id_chirho,
            LEDGER_MIRROR_PREFIX_SEAL_PATH_CHIRHO,
            &manifest_chirho.to_wire_bytes_chirho()?,
            agent_chirho,
            "LedgerMirrorPrefixSealTransportRefusedChirho",
        )?;
        if !response_chirho.is_empty() {
            bail!("LedgerMirrorPrefixSealResponseRefusedChirho");
        }
        Ok(())
    }

    fn send_recovery_bytes_chirho(
        &self,
        node_id_chirho: &str,
        path_chirho: &str,
        body_chirho: &[u8],
        agent_chirho: &ureq::Agent,
        transport_refusal_chirho: &'static str,
    ) -> Result<Vec<u8>> {
        let endpoint_chirho = self
            .by_node_chirho
            .get(node_id_chirho)
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPeerEndpointUnavailableChirho"))?;
        let response_chirho = match agent_chirho
            .post(&format!("{endpoint_chirho}{path_chirho}"))
            .set("content-type", "application/octet-stream")
            .send_bytes(body_chirho)
        {
            Ok(response_chirho) => response_chirho,
            Err(ureq::Error::Status(_, response_chirho)) => {
                let mut refusal_bytes_chirho = Vec::new();
                response_chirho
                    .into_reader()
                    .take(128)
                    .read_to_end(&mut refusal_bytes_chirho)
                    .map_err(|_| anyhow::anyhow!("LedgerMirrorPrefixResponseReadRefusedChirho"))?;
                let identity_chirho = std::str::from_utf8(&refusal_bytes_chirho)
                    .ok()
                    .and_then(exact_prefix_refusal_identity_chirho);
                if let Some(identity_chirho) = identity_chirho {
                    bail!(identity_chirho.to_string());
                }
                bail!("LedgerMirrorPrefixResponseRefusedChirho");
            }
            Err(_) => bail!(transport_refusal_chirho),
        };
        if response_chirho.status() != 200 {
            bail!("LedgerMirrorPrefixResponseRefusedChirho");
        }
        let mut bytes_chirho = Vec::new();
        response_chirho
            .into_reader()
            .take(crate::recovery_chirho::RECOVERY_HEAD_MAX_BYTES_CHIRHO as u64 + 1)
            .read_to_end(&mut bytes_chirho)
            .map_err(|_| anyhow::anyhow!("LedgerMirrorPrefixResponseReadRefusedChirho"))?;
        if bytes_chirho.len() > crate::recovery_chirho::RECOVERY_HEAD_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorPrefixResponseTooLargeChirho");
        }
        Ok(bytes_chirho)
    }
}

/// Private-mesh transport adapter for the ONE generic mirror holder port.
enum MirrorLeaderRefusalLogSinkChirho {
    StderrChirho,
    #[cfg(test)]
    CaptureChirho(Arc<Mutex<Vec<String>>>),
}

impl MirrorLeaderRefusalLogSinkChirho {
    fn emit_chirho(&self, line_chirho: String) {
        match self {
            Self::StderrChirho => eprintln!("{line_chirho}"),
            #[cfg(test)]
            Self::CaptureChirho(lines_chirho) => lines_chirho
                .lock()
                .expect("capture leader mirror refusal")
                .push(line_chirho),
        }
    }
}

pub(crate) struct HttpMirrorHolderChirho {
    node_id_chirho: String,
    endpoint_chirho: String,
    agent_chirho: ureq::Agent,
    refusal_log_sink_chirho: MirrorLeaderRefusalLogSinkChirho,
}

impl HttpMirrorHolderChirho {
    #[cfg(test)]
    pub(crate) fn new_chirho(node_id_chirho: String, endpoint_chirho: String) -> Self {
        Self {
            node_id_chirho,
            endpoint_chirho,
            agent_chirho: private_mesh_agent_chirho(),
            refusal_log_sink_chirho: MirrorLeaderRefusalLogSinkChirho::StderrChirho,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_refusal_log_capture_chirho(
        mut self,
        lines_chirho: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        self.refusal_log_sink_chirho =
            MirrorLeaderRefusalLogSinkChirho::CaptureChirho(lines_chirho);
        self
    }

    fn record_leader_refusal_chirho(
        &self,
        stage_chirho: MirrorReceiptStageChirho,
        error_chirho: &MirrorHolderFailureChirho,
    ) {
        let prefix_chirho = match stage_chirho {
            MirrorReceiptStageChirho::PreparedChirho => "LedgerMirrorLeaderPrepareRefusalChirho",
            MirrorReceiptStageChirho::FinalizedChirho => "LedgerMirrorLeaderFinalizeRefusalChirho",
        };
        // The target node id is appended because WITHOUT IT this line says a holder refused but not
        // which one. A hosted Phase C investigation had to derive the refusing node by entailment --
        // the refusal identity is only reachable by a holder with no head, and only one assigned node
        // could be headless -- which happens to be sound here and is not a substitute for a field.
        // Appended rather than inserted so the existing `prefix:identity` prefix keeps matching for
        // anything that already reads this line.
        self.refusal_log_sink_chirho.emit_chirho(format!(
            "{prefix_chirho}:{}:target={}",
            error_chirho.identity_chirho().as_str_chirho(),
            self.node_id_chirho
        ));
    }

    fn send_chirho(
        &self,
        path_chirho: &str,
        body_chirho: &[u8],
    ) -> Result<Vec<u8>, MirrorHolderFailureChirho> {
        let response_chirho = match self
            .agent_chirho
            .post(&format!("{}{}", self.endpoint_chirho, path_chirho))
            .set("content-type", "application/octet-stream")
            .send_bytes(body_chirho)
        {
            Ok(response_chirho) => response_chirho,
            Err(ureq::Error::Status(status_chirho, response_chirho)) => {
                if status_chirho != 409 {
                    return Err(
                        MirrorTransportFailureChirho::outcome_ambiguous_after_store_chirho().into(),
                    );
                }
                let mut refusal_bytes_chirho = Vec::new();
                response_chirho
                    .into_reader()
                    .take(129)
                    .read_to_end(&mut refusal_bytes_chirho)
                    .map_err(|_| {
                        MirrorTransportFailureChirho::outcome_ambiguous_after_store_chirho()
                    })?;
                if refusal_bytes_chirho.len() > 128 {
                    return Err(
                        MirrorTransportFailureChirho::outcome_ambiguous_after_store_chirho().into(),
                    );
                }
                let Some(identity_chirho) = std::str::from_utf8(&refusal_bytes_chirho)
                    .ok()
                    .and_then(MirrorRefusalIdentityChirho::from_str_chirho)
                else {
                    return Err(
                        MirrorTransportFailureChirho::outcome_ambiguous_after_store_chirho().into(),
                    );
                };
                return Err(
                    cairn_mirror_chirho::MirrorContractErrorChirho::from_fixed_wire_identity_chirho(
                        identity_chirho,
                    )
                    .into(),
                );
            }
            Err(_) => {
                return Err(
                    MirrorTransportFailureChirho::outcome_ambiguous_after_store_chirho().into(),
                )
            }
        };
        if response_chirho.status() != 200 {
            return Err(
                cairn_mirror_chirho::MirrorContractErrorChirho::closure_unverified_chirho().into(),
            );
        }
        let mut bytes_chirho = Vec::new();
        response_chirho
            .into_reader()
            .take(MIRROR_RECEIPT_WIRE_MAX_BYTES_CHIRHO as u64 + 1)
            .read_to_end(&mut bytes_chirho)
            .map_err(|_| MirrorTransportFailureChirho::outcome_ambiguous_after_store_chirho())?;
        if bytes_chirho.len() > MIRROR_RECEIPT_WIRE_MAX_BYTES_CHIRHO {
            return Err(
                MirrorTransportFailureChirho::outcome_ambiguous_after_store_chirho().into(),
            );
        }
        Ok(bytes_chirho)
    }

    fn verify_receipt_chirho(
        &self,
        wire_chirho: &[u8],
        prepare_digest_chirho: &str,
        caller_digest_chirho: &str,
        group_digest_chirho: &str,
        closure_id_chirho: &str,
        expected_stage_chirho: MirrorReceiptStageChirho,
    ) -> Result<MirrorReceiptChirho, MirrorHolderFailureChirho> {
        let verified_chirho = decode_and_verify_mirror_receipt_chirho(
            wire_chirho,
            prepare_digest_chirho,
            caller_digest_chirho,
            group_digest_chirho,
            &self.node_id_chirho,
            closure_id_chirho,
        )
        .map_err(|error_chirho| error_chirho.after_prepare_may_be_durable_chirho())?;
        if verified_chirho.stage_chirho() != expected_stage_chirho
            || verified_chirho.durable_commit_class_chirho()
                != MirrorDurableCommitClassChirho::SignedLedgerRecordNativeDurableChirho
        {
            return Err(
                cairn_mirror_chirho::MirrorContractErrorChirho::closure_unverified_chirho()
                    .after_prepare_may_be_durable_chirho()
                    .into(),
            );
        }
        Ok(verified_chirho.into_receipt_chirho())
    }
}

impl MirrorHolderPortChirho for HttpMirrorHolderChirho {
    fn prepare_durably_chirho(
        &self,
        frame_chirho: &PrepareMirrorClosureFrameV1Chirho,
    ) -> Result<MirrorReceiptChirho, MirrorHolderFailureChirho> {
        let result_chirho = (|| {
            if frame_chirho.target_node_id_chirho() != self.node_id_chirho {
                return Err(
                    cairn_mirror_chirho::MirrorContractErrorChirho::receiver_unrostered_chirho()
                        .into(),
                );
            }
            let response_chirho = self.send_chirho(
                LEDGER_MIRROR_PREPARE_PATH_CHIRHO,
                &frame_chirho.to_wire_bytes_chirho()?,
            )?;
            self.verify_receipt_chirho(
                &response_chirho,
                frame_chirho.prepare_frame_digest_chirho(),
                frame_chirho.caller_idempotency_key_digest_chirho(),
                frame_chirho.consistency_group_digest_chirho(),
                frame_chirho.mirror_closure_id_chirho(),
                MirrorReceiptStageChirho::PreparedChirho,
            )
        })();
        if let Err(error_chirho) = &result_chirho {
            self.record_leader_refusal_chirho(
                MirrorReceiptStageChirho::PreparedChirho,
                error_chirho,
            );
        }
        result_chirho
    }

    fn finalize_chirho(
        &self,
        frame_chirho: &FinalizeMirrorReceiptFrameV1Chirho,
    ) -> Result<MirrorReceiptChirho, MirrorHolderFailureChirho> {
        let result_chirho = (|| {
            if frame_chirho.target_node_id_chirho() != self.node_id_chirho {
                return Err(
                    cairn_mirror_chirho::MirrorContractErrorChirho::receiver_unrostered_chirho()
                        .into(),
                );
            }
            let response_chirho = self.send_chirho(
                LEDGER_MIRROR_FINALIZE_PATH_CHIRHO,
                &frame_chirho.to_wire_bytes_chirho()?,
            )?;
            self.verify_receipt_chirho(
                &response_chirho,
                frame_chirho.prepare_frame_digest_chirho(),
                frame_chirho.caller_idempotency_key_digest_chirho(),
                frame_chirho.consistency_group_digest_chirho(),
                frame_chirho.mirror_closure_id_chirho(),
                MirrorReceiptStageChirho::FinalizedChirho,
            )
        })();
        if let Err(error_chirho) = &result_chirho {
            self.record_leader_refusal_chirho(
                MirrorReceiptStageChirho::FinalizedChirho,
                error_chirho,
            );
        }
        result_chirho
    }
}

pub(crate) struct ProductionLedgerAppendMirrorPortChirho {
    local_node_id_chirho: String,
    sign_root_chirho: PathBuf,
    placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    election_view_chirho: Arc<dyn MirrorLeadershipViewChirho>,
    residency_chirho: MirrorResidencyPolicyChirho,
    directory_chirho: LedgerMirrorDirectoryChirho,
    leader_store_chirho: LedgerMirrorLeaderStoreChirho,
    journal_verifier_chirho: Arc<LedgerMirrorJournalVerifierBindingChirho>,
    agent_chirho: ureq::Agent,
    operation_lock_chirho: Mutex<()>,
}

pub(crate) struct ProductionLedgerAppendMirrorInputChirho {
    pub local_node_id_chirho: String,
    pub sign_root_chirho: PathBuf,
    pub placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    pub election_view_chirho: Arc<dyn MirrorLeadershipViewChirho>,
    pub residency_chirho: MirrorResidencyPolicyChirho,
    pub directory_chirho: LedgerMirrorDirectoryChirho,
    pub leader_store_chirho: LedgerMirrorLeaderStoreChirho,
    pub journal_verifier_chirho: Arc<LedgerMirrorJournalVerifierBindingChirho>,
}

impl ProductionLedgerAppendMirrorPortChirho {
    pub(crate) fn new_chirho(input_chirho: ProductionLedgerAppendMirrorInputChirho) -> Self {
        let agent_chirho = private_mesh_agent_chirho();
        Self {
            local_node_id_chirho: input_chirho.local_node_id_chirho,
            sign_root_chirho: input_chirho.sign_root_chirho,
            placement_chirho: input_chirho.placement_chirho,
            election_view_chirho: input_chirho.election_view_chirho,
            residency_chirho: input_chirho.residency_chirho,
            directory_chirho: input_chirho.directory_chirho,
            leader_store_chirho: input_chirho.leader_store_chirho,
            journal_verifier_chirho: input_chirho.journal_verifier_chirho,
            agent_chirho,
            operation_lock_chirho: Mutex::new(()),
        }
    }

    fn current_leader_view_chirho(&self) -> Result<JoinedMirrorViewChirho> {
        require_current_leader_view_chirho(
            &self.local_node_id_chirho,
            &self.placement_chirho,
            self.election_view_chirho.as_ref(),
            &self.residency_chirho,
        )
    }

    fn sign_digest_chirho(&self, digest_chirho: &[u8; 32]) -> Result<String> {
        let possession_chirho =
            cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
                &self.sign_root_chirho,
                digest_chirho,
            )?;
        if possession_chirho.key_id_chirho() != self.local_node_id_chirho {
            bail!("LedgerMirrorSignerIdentityChangedChirho");
        }
        Ok(possession_chirho.into_signature_hex_chirho())
    }

    fn prepare_locked_chirho(
        &self,
        candidate_chirho: &LedgerAppendMirrorCandidateChirho,
    ) -> Result<()> {
        if self.leader_store_chirho.load_pending_chirho()?.is_some() {
            bail!("LedgerMirrorUnreconciledPendingAppendChirho");
        }
        let joined_chirho = self.current_leader_view_chirho()?;
        let holder_set_chirho = MirrorHolderSetChirho::select_chirho(
            joined_chirho.view_chirho(),
            &self.local_node_id_chirho,
            &self.residency_chirho,
        )?;
        let candidate_record_chirho =
            LedgerMirrorRecordChirho::from_candidate_chirho(candidate_chirho);
        candidate_record_chirho.verify_with_journal_chirho(&self.journal_verifier_chirho)?;
        let manifest_chirho =
            MirrorClosureManifestChirho::new_chirho(MirrorClosureManifestInputChirho {
                consistency_group_digest_chirho: joined_chirho
                    .view_chirho()
                    .consistency_group_digest_chirho()
                    .to_string(),
                caller_idempotency_key_digest_chirho: candidate_chirho
                    .caller_idempotency_key_digest_chirho()
                    .to_string(),
                members_chirho: vec![candidate_record_chirho.into_member_chirho()],
            })?;
        let mut prepare_frames_chirho = Vec::with_capacity(2);
        for holder_chirho in holder_set_chirho.mirror_holders_chirho() {
            let prepared_chirho = PreparedPrepareMirrorClosureFrameChirho::new_chirho(
                PrepareMirrorClosureFrameInputChirho {
                    origin_node_id_chirho: self.local_node_id_chirho.clone(),
                    target_node_id_chirho: holder_chirho.node_id_chirho().to_string(),
                    consistency_group_digest_chirho: joined_chirho
                        .view_chirho()
                        .consistency_group_digest_chirho()
                        .to_string(),
                    expected_term_chirho: joined_chirho.term_chirho(),
                    membership_view_digest_chirho: joined_chirho.view_chirho().view_digest_chirho(),
                    leader_lease_remaining_millis_chirho: joined_chirho
                        .leader_lease_remaining_millis_chirho(),
                    caller_idempotency_key_digest_chirho: candidate_chirho
                        .caller_idempotency_key_digest_chirho()
                        .to_string(),
                    manifest_chirho: manifest_chirho.clone(),
                    inline_sealed_payloads_chirho: Vec::new(),
                },
            )?;
            let signature_chirho =
                self.sign_digest_chirho(&prepared_chirho.signing_digest_chirho())?;
            prepare_frames_chirho.push(prepared_chirho.into_signed_chirho(signature_chirho)?);
        }
        let pending_chirho = LedgerMirrorLeaderPendingChirho {
            prepare_frames_chirho: prepare_frames_chirho
                .try_into()
                .map_err(|_| anyhow::anyhow!("LedgerMirrorPeerPopulationRefusedChirho"))?,
        };
        self.leader_store_chirho
            .write_pending_chirho(&pending_chirho)?;
        for frame_chirho in &pending_chirho.prepare_frames_chirho {
            self.directory_chirho
                .holder_chirho(frame_chirho.target_node_id_chirho(), &self.agent_chirho)?
                .prepare_durably_chirho(frame_chirho)?;
        }
        let after_chirho = self.current_leader_view_chirho()?;
        if after_chirho.view_chirho().view_digest_chirho()
            != joined_chirho.view_chirho().view_digest_chirho()
            || after_chirho.term_chirho() != joined_chirho.term_chirho()
        {
            bail!("LedgerMirrorAuthorityChangedAfterPrepareChirho");
        }
        Ok(())
    }

    fn finalize_pending_chirho(
        &self,
        pending_chirho: &LedgerMirrorLeaderPendingChirho,
    ) -> Result<()> {
        let joined_chirho = self.current_leader_view_chirho()?;
        let prepare_view_digest_chirho =
            pending_chirho.prepare_frames_chirho[0].membership_view_digest_chirho();
        if joined_chirho.view_chirho().view_digest_chirho() != prepare_view_digest_chirho
            || pending_chirho
                .prepare_frames_chirho
                .iter()
                .any(|frame_chirho| {
                    frame_chirho.membership_view_digest_chirho() != prepare_view_digest_chirho
                })
        {
            bail!("LedgerMirrorFinalizeViewChangedChirho");
        }
        let candidate_chirho = Self::pending_candidate_chirho(pending_chirho)?;
        for prepare_chirho in &pending_chirho.prepare_frames_chirho {
            let prepared_finalize_chirho = PreparedFinalizeMirrorReceiptFrameChirho::new_chirho(
                FinalizeMirrorReceiptFrameInputChirho {
                    origin_node_id_chirho: self.local_node_id_chirho.clone(),
                    target_node_id_chirho: prepare_chirho.target_node_id_chirho().to_string(),
                    consistency_group_digest_chirho: prepare_chirho
                        .consistency_group_digest_chirho()
                        .to_string(),
                    expected_term_chirho: joined_chirho.term_chirho(),
                    membership_view_digest_chirho: prepare_view_digest_chirho.to_string(),
                    leader_lease_remaining_millis_chirho: joined_chirho
                        .leader_lease_remaining_millis_chirho(),
                    caller_idempotency_key_digest_chirho: prepare_chirho
                        .caller_idempotency_key_digest_chirho()
                        .to_string(),
                    mirror_closure_id_chirho: prepare_chirho.mirror_closure_id_chirho().to_string(),
                    prepare_frame_digest_chirho: prepare_chirho
                        .prepare_frame_digest_chirho()
                        .to_string(),
                    local_commit_binding_chirho: candidate_chirho.record_digest_chirho.clone(),
                },
            )?;
            let signature_chirho =
                self.sign_digest_chirho(&prepared_finalize_chirho.signing_digest_chirho())?;
            let finalize_chirho = prepared_finalize_chirho.into_signed_chirho(signature_chirho)?;
            self.directory_chirho
                .holder_chirho(finalize_chirho.target_node_id_chirho(), &self.agent_chirho)?
                .finalize_chirho(&finalize_chirho)?;
        }
        self.leader_store_chirho.clear_pending_chirho()
    }

    fn pending_candidate_chirho(
        pending_chirho: &LedgerMirrorLeaderPendingChirho,
    ) -> Result<LedgerMirrorRecordChirho> {
        let candidate_chirho = LedgerMirrorRecordChirho::from_manifest_chirho(
            pending_chirho.prepare_frames_chirho[0].manifest_chirho(),
        )?;
        let second_chirho = LedgerMirrorRecordChirho::from_manifest_chirho(
            pending_chirho.prepare_frames_chirho[1].manifest_chirho(),
        )?;
        if candidate_chirho != second_chirho {
            bail!("LedgerMirrorPendingCandidateDivergenceChirho");
        }
        Ok(candidate_chirho)
    }
}

pub(crate) fn require_current_leader_view_chirho(
    local_node_id_chirho: &str,
    placement_chirho: &VerifiedTenantPlacementChirho,
    election_view_chirho: &dyn MirrorLeadershipViewChirho,
    residency_chirho: &MirrorResidencyPolicyChirho,
) -> Result<JoinedMirrorViewChirho> {
    let joined_chirho = join_mirror_view_chirho(placement_chirho, election_view_chirho)?;
    if !joined_chirho.local_sender_is_elected_leader_chirho(local_node_id_chirho) {
        bail!("LedgerMirrorLocalLeaderAuthorityRefusedChirho");
    }
    MirrorHolderSetChirho::select_chirho(
        joined_chirho.view_chirho(),
        local_node_id_chirho,
        residency_chirho,
    )?;
    Ok(joined_chirho)
}

pub(crate) fn private_mesh_agent_chirho() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .redirects(0)
        .max_idle_connections(0)
        .timeout_connect(Duration::from_millis(750))
        .timeout_read(Duration::from_secs(5))
        .timeout_write(Duration::from_secs(5))
        .timeout(Duration::from_secs(8))
        .build()
}

impl LedgerAppendMirrorPortChirho for ProductionLedgerAppendMirrorPortChirho {
    fn require_no_unreconciled_pending_append_chirho(
        &self,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| mirror_error_chirho("LedgerMirrorLeaderStorePoisonedChirho"))?;
        if self
            .leader_store_chirho
            .load_pending_chirho()
            .map_err(port_error_chirho)?
            .is_some()
        {
            return Err(mirror_error_chirho(
                "LedgerMirrorPendingSourceFenceRefusedChirho",
            ));
        }
        Ok(())
    }

    fn reconcile_before_append_chirho(
        &self,
        local_tail_chirho: &LedgerAppendMirrorTailChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| mirror_error_chirho("LedgerMirrorLeaderStorePoisonedChirho"))?;
        let Some(pending_chirho) = self
            .leader_store_chirho
            .load_pending_chirho()
            .map_err(port_error_chirho)?
        else {
            return Ok(());
        };
        let candidate_chirho =
            Self::pending_candidate_chirho(&pending_chirho).map_err(port_error_chirho)?;
        if local_tail_chirho.cluster_id_chirho().0 != candidate_chirho.cluster_id_chirho
            || local_tail_chirho.journal_genesis_digest_chirho().0
                != candidate_chirho.journal_genesis_digest_chirho
        {
            return Err(mirror_error_chirho(
                "LedgerMirrorLocalJournalBindingRefusedChirho",
            ));
        }
        if local_tail_chirho.tail_seq_chirho() == candidate_chirho.record_seq_chirho
            && local_tail_chirho.tail_record_digest_chirho().0
                == candidate_chirho.record_digest_chirho
        {
            return self
                .finalize_pending_chirho(&pending_chirho)
                .map_err(port_error_chirho);
        }
        if local_tail_chirho.tail_seq_chirho() == candidate_chirho.predecessor_seq_chirho
            && local_tail_chirho.tail_record_digest_chirho().0
                == candidate_chirho.predecessor_digest_chirho
        {
            return self
                .leader_store_chirho
                .clear_pending_chirho()
                .map_err(port_error_chirho);
        }
        Err(mirror_error_chirho(
            "LedgerMirrorLocalTailReconciliationRefusedChirho",
        ))
    }

    fn prepare_append_chirho(
        &self,
        candidate_chirho: &LedgerAppendMirrorCandidateChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| mirror_error_chirho("LedgerMirrorLeaderStorePoisonedChirho"))?;
        self.prepare_locked_chirho(candidate_chirho)
            .map_err(port_error_chirho)
    }

    fn finalize_append_chirho(
        &self,
        committed_candidate_chirho: &LedgerAppendMirrorCandidateChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| mirror_error_chirho("LedgerMirrorLeaderStorePoisonedChirho"))?;
        let pending_chirho = self
            .leader_store_chirho
            .load_pending_chirho()
            .map_err(port_error_chirho)?
            .ok_or_else(|| mirror_error_chirho("LedgerMirrorPendingAppendUnavailableChirho"))?;
        let candidate_chirho =
            Self::pending_candidate_chirho(&pending_chirho).map_err(port_error_chirho)?;
        if candidate_chirho
            != LedgerMirrorRecordChirho::from_candidate_chirho(committed_candidate_chirho)
        {
            return Err(mirror_error_chirho(
                "LedgerMirrorCommittedCandidateMismatchChirho",
            ));
        }
        self.finalize_pending_chirho(&pending_chirho)
            .map_err(port_error_chirho)
    }
}

fn port_error_chirho(error_chirho: impl std::fmt::Display) -> LedgerAppendMirrorPortErrorChirho {
    LedgerAppendMirrorPortErrorChirho::new_chirho(error_chirho.to_string())
}

fn mirror_error_chirho(detail_chirho: &str) -> LedgerAppendMirrorPortErrorChirho {
    LedgerAppendMirrorPortErrorChirho::new_chirho(detail_chirho)
}
