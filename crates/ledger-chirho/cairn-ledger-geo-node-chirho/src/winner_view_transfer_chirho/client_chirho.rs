// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

pub(crate) fn call_winner_view_transfer_chirho(
    context_chirho: Gd7WinnerViewTransferCallContextChirho<'_>,
    operation_chirho: Gd7WinnerViewTransferOperationChirho,
) -> Result<Gd7WinnerViewTransferReplyChirho> {
    let Gd7WinnerViewTransferCallContextChirho {
        agent_chirho,
        base_url_chirho,
        consistency_group_digest_chirho,
        sender_signer_chirho,
        winner_node_chirho,
        transfer_identity_digest_chirho,
        expected_raft_term_chirho,
        request_nonce_chirho,
    } = context_chirho;
    validate_winner_view_transfer_base_url_chirho(base_url_chirho)?;
    if !is_lower_hex_64_chirho(request_nonce_chirho) {
        bail!("winner-view transfer request nonce is not canonical lower hex");
    }
    if !is_lower_hex_64_chirho(transfer_identity_digest_chirho) {
        bail!("winner-view transfer identity digest is not canonical lower hex");
    }
    let mut request_chirho = Gd7WinnerViewTransferRequestChirho {
        schema_chirho: GD7_WINNER_VIEW_TRANSFER_REQUEST_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: consistency_group_digest_chirho.to_owned(),
        sender_node_chirho: sender_signer_chirho.node_id_chirho().0.clone(),
        recipient_node_chirho: winner_node_chirho.0.clone(),
        transfer_identity_digest_chirho: transfer_identity_digest_chirho.to_owned(),
        expected_raft_term_chirho,
        nonce_chirho: request_nonce_chirho.to_owned(),
        operation_chirho,
        key_id_chirho: sender_signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    validate_operation_shape_chirho(&request_chirho.operation_chirho).map_err(|code_chirho| {
        anyhow!("invalid winner-view transfer operation: {code_chirho:?}")
    })?;
    validate_operation_binding_chirho(
        &request_chirho.operation_chirho,
        &request_chirho.consistency_group_digest_chirho,
        &request_chirho.sender_node_chirho,
        &request_chirho.recipient_node_chirho,
        &request_chirho.transfer_identity_digest_chirho,
        request_chirho.expected_raft_term_chirho,
    )
    .map_err(|code_chirho| {
        anyhow!("invalid winner-view transfer operation binding: {code_chirho:?}")
    })?;
    let unsigned_bytes_chirho = canonical_json_chirho(&request_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| anyhow!("winner-view transfer request is not UTF-8"))?;
    request_chirho.sig_chirho = sender_signer_chirho.sign_chirho(unsigned_line_chirho)?;
    let request_bytes_chirho = canonical_json_chirho(&request_chirho)?;
    if request_bytes_chirho.len() > MAX_GD7_WINNER_VIEW_TRANSFER_REQUEST_BYTES_CHIRHO {
        bail!("winner-view transfer request exceeds its fixed bound");
    }
    let request_digest_chirho = digest_bytes_chirho(&request_bytes_chirho);
    let url_chirho = format!(
        "{}{}",
        base_url_chirho.trim_end_matches('/'),
        GD7_WINNER_VIEW_TRANSFER_PATH_CHIRHO
    );
    let response_chirho = agent_chirho
        .post(&url_chirho)
        .set("content-type", "application/json")
        .send_bytes(&request_bytes_chirho)
        .with_context(|| format!("post winner-view transfer request to {url_chirho}"))?;
    if response_chirho.status() != 200 {
        bail!(
            "winner-view transfer endpoint returned HTTP {}",
            response_chirho.status()
        );
    }
    let mut response_bytes_chirho = Vec::new();
    response_chirho
        .into_reader()
        .take(
            u64::try_from(MAX_GD7_WINNER_VIEW_TRANSFER_RESPONSE_BYTES_CHIRHO)
                .expect("response cap fits u64")
                + 1,
        )
        .read_to_end(&mut response_bytes_chirho)
        .context("read bounded winner-view transfer response")?;
    if response_bytes_chirho.len() > MAX_GD7_WINNER_VIEW_TRANSFER_RESPONSE_BYTES_CHIRHO {
        bail!("winner-view transfer response exceeds its fixed bound");
    }
    let (header_chirho, payload_chirho) = decode_frame_chirho(&response_bytes_chirho)?;
    let winner_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(winner_node_chirho.clone())?;
    verify_response_chirho(
        &header_chirho,
        payload_chirho,
        consistency_group_digest_chirho,
        &request_digest_chirho,
        winner_node_chirho,
        expected_raft_term_chirho,
        &winner_verifier_chirho,
    )?;
    Ok(Gd7WinnerViewTransferReplyChirho {
        result_chirho: header_chirho.result_chirho,
        canonical_page_bytes_chirho: payload_chirho.to_vec(),
    })
}
