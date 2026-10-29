// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Verified, write-free request-input adapter for transient app execution.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/pure-app-read-chirho.md`.

use super::ServedRuntimeRootChirho;
use anyhow::{anyhow, Result};
use axum::http::{header::CONTENT_TYPE, HeaderMap};
use cairn_chirho::app_chirho;
use cairn_core_chirho::model_chirho::RequestContextChirho;
use cairn_model_app_chirho::{
    app_request_input_chirho::{
        allows_transient_request_user_input_chirho, app_plain_input_with_verified_context_chirho,
        request_input_is_form_urlencoded_chirho,
    },
    AppInputModeChirho,
};

impl ServedRuntimeRootChirho {
    fn read_verified_app_input_mode_chirho(
        &self,
        app_chirho: &str,
        route_chirho: &str,
        context_chirho: Option<&RequestContextChirho>,
    ) -> Result<(String, AppInputModeChirho)> {
        let owner_chirho = match context_chirho {
            Some(context_chirho) => context_chirho.owner_principal_chirho.clone(),
            None => app_chirho::verified_app_owner_chirho(&self.root_chirho, app_chirho)?
                .ok_or_else(|| anyhow!("app '{app_chirho}' has no signed owner record"))?,
        };
        let mode_chirho = app_chirho::app_input_mode_chirho(
            &self.root_chirho,
            app_chirho,
            Some(route_chirho),
            &owner_chirho,
        )?;
        Ok((owner_chirho, mode_chirho))
    }

    pub(in crate::serve_chirho) fn pure_app_read_input_chirho(
        &self,
        app_chirho: &str,
        route_chirho: &str,
        context_chirho: Option<&RequestContextChirho>,
        headers_chirho: &HeaderMap,
    ) -> Result<Vec<u8>> {
        let (owner_chirho, mode_chirho) =
            self.read_verified_app_input_mode_chirho(app_chirho, route_chirho, context_chirho)?;
        match mode_chirho {
            AppInputModeChirho::PlainChirho => {}
            AppInputModeChirho::PrivateBlobRefChirho { .. } => return Ok(Vec::new()),
        }
        let params_chirho = app_chirho::app_params_chirho(
            &self.root_chirho,
            app_chirho,
            Some(route_chirho),
            &owner_chirho,
        )?;
        // The normal form decoder yields an empty object for an empty urlencoded body.
        let input_chirho = if request_input_is_form_urlencoded_chirho(
            headers_chirho
                .get(CONTENT_TYPE)
                .and_then(|value_chirho| value_chirho.to_str().ok()),
        ) {
            b"{}".to_vec()
        } else {
            Vec::new()
        };
        app_plain_input_with_verified_context_chirho(
            input_chirho,
            context_chirho.map(|context_chirho| context_chirho.user_principal_chirho.as_str()),
            params_chirho
                .as_ref()
                .map(|params_chirho| &params_chirho.value_chirho),
        )
    }

    pub(in crate::serve_chirho) fn pure_app_body_input_chirho(
        &self,
        app_chirho: &str,
        route_chirho: &str,
        context_chirho: Option<&RequestContextChirho>,
        body_chirho: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        let Some(context_chirho) = context_chirho else {
            return Ok(None);
        };
        let (_, mode_chirho) = self.read_verified_app_input_mode_chirho(
            app_chirho,
            route_chirho,
            Some(context_chirho),
        )?;
        // Decide on this one verified policy. No normal assembler or sealer can re-read another one.
        Ok(allows_transient_request_user_input_chirho(&mode_chirho).then_some(body_chirho))
    }
}
