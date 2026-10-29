// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure policy for binding reviewed subscription-view declarations to app source evidence.

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_app_chirho::{
    lower_app_source_deploy_manifest_chirho, validate_app_source_id_chirho,
    AppDeployDagSourceChirho, AppDeployManifestChirho, AppSourceCandidateReportChirho,
    AppSourceManifestChirho, AppSourceModuleManifestChirho, AppSourceModuleReportChirho,
    AppSourceReviewReportChirho, SubscriptionViewDeclarationChirho,
    SubscriptionViewDeclarationReportChirho, SubscriptionViewScopeChirho,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSubscriptionViewModuleEvidenceChirho {
    pub module_chirho: HashChirho,
    pub dag_chirho: HashChirho,
    pub input_names_chirho: BTreeSet<String>,
}

pub trait SubscriptionViewReviewEvidencePortChirho {
    fn store_declaration_chirho(
        &self,
        declaration_chirho: &SubscriptionViewDeclarationChirho,
    ) -> Result<HashChirho>;

    fn load_effective_manifest_chirho(
        &self,
        effective_manifest_chirho: &HashChirho,
    ) -> Result<AppSourceManifestChirho>;

    fn load_declaration_chirho(
        &self,
        declaration_chirho: &HashChirho,
    ) -> Result<SubscriptionViewDeclarationChirho>;

    fn verified_module_evidence_chirho(
        &self,
        module_chirho: &HashChirho,
    ) -> Result<VerifiedSubscriptionViewModuleEvidenceChirho>;
}

pub fn build_subscription_view_reports_chirho<PortChirho>(
    port_chirho: &PortChirho,
    module_chirho: &AppSourceModuleManifestChirho,
    view_ids_chirho: &mut BTreeSet<String>,
) -> Result<Vec<SubscriptionViewDeclarationReportChirho>>
where
    PortChirho: SubscriptionViewReviewEvidencePortChirho + ?Sized,
{
    validate_subscription_view_module_inputs_chirho(module_chirho)?;
    module_chirho
        .subscription_views_chirho
        .iter()
        .map(|declaration_chirho| {
            validate_app_source_id_chirho("subscription view id", &declaration_chirho.view_chirho)?;
            if !view_ids_chirho.insert(declaration_chirho.view_chirho.clone()) {
                bail!(
                    "duplicate subscription view id '{}'",
                    declaration_chirho.view_chirho
                );
            }
            let declaration_hash_chirho =
                port_chirho.store_declaration_chirho(declaration_chirho)?;
            Ok(subscription_view_report_with_hash_chirho(
                declaration_chirho,
                declaration_hash_chirho,
            ))
        })
        .collect()
}

fn validate_subscription_view_module_inputs_chirho(
    module_chirho: &AppSourceModuleManifestChirho,
) -> Result<()> {
    let mut module_inputs_chirho = BTreeSet::new();
    for binding_chirho in &module_chirho.input_bindings_chirho {
        if !module_inputs_chirho.insert(binding_chirho.public_name_chirho.as_str()) {
            bail!(
                "duplicate module input binding '{}'",
                binding_chirho.public_name_chirho
            );
        }
    }
    for declaration_chirho in &module_chirho.subscription_views_chirho {
        if declaration_chirho.dependencies_chirho.is_empty() {
            bail!(
                "subscription view '{}' needs at least one dependency",
                declaration_chirho.view_chirho
            );
        }
        let mut dependency_inputs_chirho = BTreeSet::new();
        let mut dependency_groups_chirho = BTreeSet::new();
        for dependency_chirho in &declaration_chirho.dependencies_chirho {
            if !module_inputs_chirho.contains(dependency_chirho.module_input_chirho.as_str()) {
                bail!(
                    "subscription view '{}' dependency '{}' is not a module input binding",
                    declaration_chirho.view_chirho,
                    dependency_chirho.module_input_chirho
                );
            }
            if !dependency_inputs_chirho.insert(dependency_chirho.module_input_chirho.as_str()) {
                bail!(
                    "subscription view '{}' repeats module input '{}'",
                    declaration_chirho.view_chirho,
                    dependency_chirho.module_input_chirho
                );
            }
            if !dependency_groups_chirho.insert(&dependency_chirho.group_chirho) {
                bail!(
                    "subscription view '{}' repeats dependency group {:?}",
                    declaration_chirho.view_chirho,
                    dependency_chirho.group_chirho
                );
            }
        }
    }
    Ok(())
}

fn subscription_view_report_with_hash_chirho(
    declaration_chirho: &SubscriptionViewDeclarationChirho,
    declaration_hash_chirho: HashChirho,
) -> SubscriptionViewDeclarationReportChirho {
    SubscriptionViewDeclarationReportChirho {
        declaration_chirho: declaration_hash_chirho,
        view_chirho: declaration_chirho.view_chirho.clone(),
        scope_chirho: declaration_chirho.scope_chirho.clone(),
        authorization_chirho: declaration_chirho.authorization_chirho.clone(),
        dependencies_chirho: declaration_chirho.dependencies_chirho.clone(),
    }
}

pub fn validate_candidate_subscription_view_scopes_chirho(
    candidate_chirho: &AppSourceCandidateReportChirho,
) -> Result<()> {
    let mut route_dags_chirho = BTreeMap::new();
    for route_chirho in &candidate_chirho.routes_chirho {
        if route_dags_chirho
            .insert(
                route_chirho.route_chirho.clone(),
                route_chirho.dag_chirho.clone(),
            )
            .is_some()
        {
            bail!(
                "duplicate subscription view route '{}'",
                route_chirho.route_chirho
            );
        }
    }
    validate_subscription_view_scopes_chirho(
        &candidate_chirho.root_dag_chirho,
        &route_dags_chirho,
        &candidate_chirho.modules_chirho,
    )
}

pub fn validate_deploy_subscription_view_scopes_chirho<ResolveChirho>(
    manifest_chirho: &AppDeployManifestChirho,
    modules_chirho: &[AppSourceModuleReportChirho],
    mut resolve_chirho: ResolveChirho,
) -> Result<()>
where
    ResolveChirho: FnMut(&AppDeployDagSourceChirho) -> Result<HashChirho>,
{
    if modules_chirho
        .iter()
        .all(|module_chirho| module_chirho.subscription_views_chirho.is_empty())
    {
        return Ok(());
    }
    let root_source_chirho = manifest_chirho
        .root_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("subscription view source manifest needs a root_chirho"))?;
    let root_dag_chirho = resolve_chirho(root_source_chirho)?;
    let mut route_dags_chirho = BTreeMap::new();
    for route_chirho in &manifest_chirho.routes_chirho {
        let route_dag_chirho = resolve_chirho(&route_chirho.source_chirho)?;
        if route_dags_chirho
            .insert(route_chirho.route_chirho.clone(), route_dag_chirho)
            .is_some()
        {
            bail!(
                "duplicate subscription view route '{}'",
                route_chirho.route_chirho
            );
        }
    }
    validate_subscription_view_scopes_chirho(&root_dag_chirho, &route_dags_chirho, modules_chirho)
}

pub fn validate_subscription_view_scopes_chirho(
    root_dag_chirho: &HashChirho,
    route_dags_chirho: &BTreeMap<String, HashChirho>,
    modules_chirho: &[AppSourceModuleReportChirho],
) -> Result<()> {
    let mut module_ids_chirho = BTreeSet::new();
    let mut view_ids_chirho = BTreeSet::new();
    for module_chirho in modules_chirho {
        if !module_ids_chirho.insert(module_chirho.id_chirho.as_str()) {
            bail!(
                "duplicate subscription view candidate module '{}'",
                module_chirho.id_chirho
            );
        }
        for declaration_chirho in &module_chirho.subscription_views_chirho {
            if !view_ids_chirho.insert(declaration_chirho.view_chirho.as_str()) {
                bail!(
                    "duplicate subscription view id '{}' in candidate report",
                    declaration_chirho.view_chirho
                );
            }
            match &declaration_chirho.scope_chirho {
                SubscriptionViewScopeChirho::AppRootChirho => {
                    if module_chirho.dag_chirho != *root_dag_chirho {
                        bail!(
                            "subscription view '{}' app-root scope does not match module DAG",
                            declaration_chirho.view_chirho
                        );
                    }
                }
                SubscriptionViewScopeChirho::RouteChirho { route_chirho } => {
                    let route_dag_chirho =
                        route_dags_chirho.get(route_chirho).ok_or_else(|| {
                            anyhow!(
                                "subscription view '{}' route '{}' does not exist",
                                declaration_chirho.view_chirho,
                                route_chirho
                            )
                        })?;
                    if module_chirho.dag_chirho != *route_dag_chirho {
                        bail!(
                            "subscription view '{}' route '{}' does not resolve to module DAG",
                            declaration_chirho.view_chirho,
                            route_chirho
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn validate_reviewed_source_report_request_chirho(
    app_chirho: &str,
    owner_chirho: &str,
    report_chirho: &AppSourceReviewReportChirho,
    candidate_chirho: Option<&HashChirho>,
) -> Result<()> {
    if report_chirho.candidate_chirho.app_chirho != app_chirho
        || report_chirho.review_chirho.app_chirho != app_chirho
    {
        bail!("source review report app does not match request path");
    }
    if report_chirho.candidate_chirho.owner_chirho != owner_chirho {
        bail!("source review report owner does not match authenticated owner");
    }
    if report_chirho.candidate_chirho.root_dag_chirho
        != report_chirho.review_chirho.candidate_chirho
    {
        bail!("source review report candidate root does not match review surface");
    }
    if candidate_chirho.is_some_and(|candidate_chirho| {
        report_chirho.candidate_chirho.root_dag_chirho != *candidate_chirho
    }) {
        bail!("source review report candidate does not match submitted candidate");
    }
    if !report_chirho.non_authoritative_chirho {
        bail!("source review report must be non-authoritative before promote");
    }
    Ok(())
}

pub fn validate_app_source_review_declaration_binding_chirho<PortChirho>(
    port_chirho: &PortChirho,
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<()>
where
    PortChirho: SubscriptionViewReviewEvidencePortChirho + ?Sized,
{
    let candidate_chirho = &report_chirho.candidate_chirho;
    let candidate_has_views_chirho = candidate_chirho
        .modules_chirho
        .iter()
        .any(|module_chirho| !module_chirho.subscription_views_chirho.is_empty());
    let Some(source_evidence_chirho) = candidate_chirho.source_manifest_chirho.as_ref() else {
        if candidate_has_views_chirho {
            bail!(
                "subscription view declarations require bound effective source manifest evidence"
            );
        }
        return Ok(());
    };
    let manifest_chirho = port_chirho
        .load_effective_manifest_chirho(&source_evidence_chirho.effective_manifest_hash_chirho)?;
    if manifest_chirho.app_chirho != candidate_chirho.app_chirho
        || manifest_chirho.owner_chirho != candidate_chirho.owner_chirho
    {
        bail!("effective source manifest app or owner does not match candidate report");
    }

    let candidate_modules_chirho = candidate_chirho
        .modules_chirho
        .iter()
        .map(|module_chirho| (module_chirho.id_chirho.as_str(), module_chirho))
        .collect::<BTreeMap<_, _>>();
    let mut manifest_modules_chirho = BTreeMap::new();
    let mut manifest_view_ids_chirho = BTreeSet::new();
    for module_chirho in &manifest_chirho.modules_chirho {
        if manifest_modules_chirho
            .insert(module_chirho.id_chirho.as_str(), module_chirho)
            .is_some()
        {
            bail!(
                "effective source manifest repeats module '{}'",
                module_chirho.id_chirho
            );
        }
        for view_chirho in &module_chirho.subscription_views_chirho {
            validate_app_source_id_chirho("subscription view id", &view_chirho.view_chirho)?;
            if !manifest_view_ids_chirho.insert(view_chirho.view_chirho.as_str()) {
                bail!(
                    "effective source manifest repeats subscription view '{}'",
                    view_chirho.view_chirho
                );
            }
        }
    }

    for module_chirho in &manifest_chirho.modules_chirho {
        let actual_module_chirho = candidate_modules_chirho.get(module_chirho.id_chirho.as_str());
        if module_chirho.subscription_views_chirho.is_empty() {
            if actual_module_chirho.is_some_and(|actual_module_chirho| {
                !actual_module_chirho.subscription_views_chirho.is_empty()
            }) {
                bail!(
                    "subscription view declarations for module '{}' do not match effective source manifest",
                    module_chirho.id_chirho
                );
            }
            continue;
        }
        let actual_module_chirho = actual_module_chirho.ok_or_else(|| {
            anyhow!(
                "subscription view module '{}' is missing from candidate report",
                module_chirho.id_chirho
            )
        })?;
        if actual_module_chirho.subscription_views_chirho.len()
            != module_chirho.subscription_views_chirho.len()
        {
            bail!(
                "subscription view declarations for module '{}' do not match effective source manifest",
                module_chirho.id_chirho
            );
        }
        for (manifest_view_chirho, report_view_chirho) in module_chirho
            .subscription_views_chirho
            .iter()
            .zip(&actual_module_chirho.subscription_views_chirho)
        {
            let stored_declaration_chirho =
                port_chirho.load_declaration_chirho(&report_view_chirho.declaration_chirho)?;
            if stored_declaration_chirho != *manifest_view_chirho
                || report_view_chirho.reviewed_declaration_chirho() != *manifest_view_chirho
            {
                bail!(
                    "subscription view declarations for module '{}' do not match effective source manifest",
                    module_chirho.id_chirho
                );
            }
        }
        validate_subscription_view_module_inputs_chirho(module_chirho)?;
        let verified_module_chirho =
            port_chirho.verified_module_evidence_chirho(&actual_module_chirho.module_chirho)?;
        if verified_module_chirho.module_chirho != actual_module_chirho.module_chirho
            || verified_module_chirho.dag_chirho != actual_module_chirho.dag_chirho
        {
            bail!(
                "subscription view module '{}' does not match verified stored module",
                module_chirho.id_chirho
            );
        }
        let manifest_inputs_chirho = module_chirho
            .input_bindings_chirho
            .iter()
            .map(|binding_chirho| binding_chirho.public_name_chirho.clone())
            .collect::<BTreeSet<_>>();
        if manifest_inputs_chirho != verified_module_chirho.input_names_chirho {
            bail!(
                "subscription view module '{}' inputs do not match verified stored module",
                module_chirho.id_chirho
            );
        }
    }
    for module_chirho in &candidate_chirho.modules_chirho {
        if !module_chirho.subscription_views_chirho.is_empty()
            && !manifest_modules_chirho.contains_key(module_chirho.id_chirho.as_str())
        {
            bail!(
                "candidate report contains subscription views for unknown manifest module '{}'",
                module_chirho.id_chirho
            );
        }
    }
    validate_candidate_subscription_view_scopes_chirho(candidate_chirho)?;

    let mut candidate_dags_chirho = BTreeMap::new();
    for dag_chirho in &candidate_chirho.dags_chirho {
        if candidate_dags_chirho
            .insert(dag_chirho.id_chirho.clone(), dag_chirho.dag_chirho.clone())
            .is_some()
        {
            bail!(
                "duplicate subscription view candidate DAG '{}'",
                dag_chirho.id_chirho
            );
        }
    }
    let mut candidate_module_hashes_chirho = BTreeMap::new();
    for module_chirho in &candidate_chirho.modules_chirho {
        if candidate_module_hashes_chirho
            .insert(
                module_chirho.id_chirho.clone(),
                module_chirho.module_chirho.clone(),
            )
            .is_some()
        {
            bail!(
                "duplicate subscription view candidate module '{}'",
                module_chirho.id_chirho
            );
        }
    }
    let deploy_manifest_chirho = lower_app_source_deploy_manifest_chirho(
        &manifest_chirho,
        &candidate_dags_chirho,
        &candidate_module_hashes_chirho,
    )?;
    validate_deploy_subscription_view_scopes_chirho(
        &deploy_manifest_chirho,
        &candidate_chirho.modules_chirho,
        |source_chirho| match source_chirho {
            AppDeployDagSourceChirho::DagChirho { hash_chirho } => Ok(hash_chirho.clone()),
            AppDeployDagSourceChirho::ModuleChirho { hash_chirho } => port_chirho
                .verified_module_evidence_chirho(hash_chirho)
                .map(|module_chirho| module_chirho.dag_chirho),
            AppDeployDagSourceChirho::CompositionChirho { .. } => bail!(
                "composition-sourced deploy cannot authorize a module-nested subscription view"
            ),
        },
    )
}

#[cfg(test)]
#[path = "tests_chirho.rs"]
mod tests_chirho;
