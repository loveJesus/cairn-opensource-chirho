// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Verified root adapter for the pure subscription-view review service.

use super::*;
use cairn_subscription_view_review_chirho::{
    self as subscription_view_review_chirho, SubscriptionViewReviewEvidencePortChirho,
    VerifiedSubscriptionViewModuleEvidenceChirho,
};

pub(super) struct RootSubscriptionViewReviewPortChirho<'a>(pub(super) &'a Path);

impl SubscriptionViewReviewEvidencePortChirho for RootSubscriptionViewReviewPortChirho<'_> {
    fn store_declaration_chirho(
        &self,
        declaration_chirho: &SubscriptionViewDeclarationChirho,
    ) -> Result<HashChirho> {
        store_chirho::put_object_chirho(self.0, declaration_chirho)
    }

    fn load_effective_manifest_chirho(
        &self,
        effective_manifest_chirho: &HashChirho,
    ) -> Result<AppSourceManifestChirho> {
        require_app_source_manifest_v1_chirho(
            store_chirho::get_object_chirho(self.0, effective_manifest_chirho)
                .context("load typed effective source manifest for subscription view binding")?,
        )
    }

    fn load_declaration_chirho(
        &self,
        declaration_chirho: &HashChirho,
    ) -> Result<SubscriptionViewDeclarationChirho> {
        store_chirho::get_object_chirho(self.0, declaration_chirho)
            .context("load content-addressed subscription view declaration")
    }

    fn verified_module_evidence_chirho(
        &self,
        module_chirho: &HashChirho,
    ) -> Result<VerifiedSubscriptionViewModuleEvidenceChirho> {
        let stored_module_chirho =
            dag_module_chirho::validate_stored_dag_module_chirho(self.0, module_chirho)?;
        Ok(VerifiedSubscriptionViewModuleEvidenceChirho {
            module_chirho: module_chirho.clone(),
            dag_chirho: stored_module_chirho.dag_chirho,
            input_names_chirho: stored_module_chirho
                .inputs_chirho
                .into_iter()
                .map(|binding_chirho| binding_chirho.public_port_chirho.name_chirho)
                .collect(),
        })
    }
}

pub fn validate_app_source_review_declaration_binding_chirho(
    root_chirho: &Path,
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<()> {
    subscription_view_review_chirho::validate_app_source_review_declaration_binding_chirho(
        &RootSubscriptionViewReviewPortChirho(root_chirho),
        report_chirho,
    )
}
