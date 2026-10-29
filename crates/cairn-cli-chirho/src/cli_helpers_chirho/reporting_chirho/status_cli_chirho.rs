// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Status and review report printing helpers for CLI commands.
use crate::args_chirho::CommandChirho;
use cairn_chirho::legacy_billing_evidence_chirho;
use cairn_chirho::migration_completeness_chirho::RootSurfaceEnumeratorChirho;
use cairn_chirho::{
    app_chirho, app_descriptor_chirho, app_docs_chirho, app_source_manifest_chirho,
    capability_plain_chirho, dag_capability_scan_chirho, effect_pricing_chirho,
    migration_completeness_chirho, onboarding_chirho, ops_custody_chirho, ops_restore_drill_chirho,
    platform_mcp_chirho, refs_chirho, review_chirho, root_surfaces_chirho, self_containment_chirho,
    single_customer_app_chirho, surface_disposition_chirho,
};
use cairn_launch_readiness_chirho as launch_readiness_chirho;
use cairn_status_command_chirho::{
    app_source_undo_plan_review_body_chirho, print_app_source_candidate_chirho,
    print_app_source_review_chirho, print_ops_custody_inventory_chirho,
    print_ops_restore_drill_chirho,
};
use std::path::Path;

/// Above this many absent-but-declared surfaces, print the count only.
///
/// Absence is routine and enumerating it competes with the refusals for the reader's attention. The
/// threshold is small on purpose: a handful of absences is worth reading item by item, and anything
/// larger is a shape you read as a number.
const ABSENT_SURFACE_LIST_LIMIT_CHIRHO: usize = 8;
pub(crate) fn handle_app_status_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::TenantAppVerifyChirho => {
            // G1: a tenant root is the atomic unit of placement, authority, and migration, so it
            // holds at most one customer app. NOT a capacity limit -- many tenant roots per shard
            // is the expected growth path.
            //
            // The app set passed here must be COMPLETE, and applied refs are not complete. An app
            // head is written in two phases: the signed deploy record is appended FIRST, the
            // `app/{name}` ref moves SECOND. So an app with a verified record and no ref yet is a
            // real, already-authorized app that `recover_app_head_chirho` will finish from
            // (root, app) alone. Reading the records is the only way to see it, and only this
            // layer can.
            let record_apps_chirho = app_chirho::verified_app_owners_chirho(root_chirho)?;
            let record_names_chirho = record_apps_chirho
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            // The verifier returns the applied heads it judged, so reporting what was examined
            // costs no second refs load -- and a pass cannot be read as a pass over nothing.
            let applied_chirho =
                single_customer_app_chirho::verify_single_customer_app_root_at_path_chirho(
                    root_chirho,
                    &record_names_chirho,
                )?;
            println!(
                "G1 OK: at most one customer app in this root — {} applied head(s), {} verified \
                 deploy record(s) examined",
                applied_chirho.len(),
                record_names_chirho.len()
            );
            Ok(true)
        }
        CommandChirho::TenantMigrationVerifyChirho => {
            // CF8 clause 5, composed over a REAL root, in three questions that are not the same
            // question. Completeness: was I shown everything. Self-containment: does what I was
            // shown resolve HERE. Disposition: has anything decided what happens to each one.
            // Any subset is a half-proof, and the most convincing subset is the most misleading —
            // a self-containment green over a short reference list means "nothing I was shown
            // dangles", not "this root is self-contained", and passing both of the first two still
            // says nothing about a signing key nobody has decided how to move. Only all three make
            // a successful precheck, which is why its type cannot be constructed from a subset.
            let snapshot_chirho =
                root_surfaces_chirho::RootSurfaceSnapshotChirho::open_chirho(root_chirho)?;
            let completeness_chirho =
                migration_completeness_chirho::verify_migration_completeness_chirho(
                    &migration_completeness_chirho::declared_root_surfaces_chirho(),
                    &snapshot_chirho,
                );
            let references_chirho =
                root_surfaces_chirho::tenant_log_references_chirho(root_chirho)?;
            let containment_chirho = self_containment_chirho::verify_tenant_self_containment_chirho(
                &references_chirho,
                &root_surfaces_chirho::TenantScopedArtifactResolverChirho::for_root_chirho(
                    root_chirho,
                ),
            );

            println!(
                "surfaces observed: {}   log references checked: {}",
                completeness_chirho.observed_count_chirho,
                containment_chirho.references_checked_chirho
            );
            // Print the findings BEFORE any refusal. An operator running this to learn what a root
            // contains needs the list even — especially — when the answer is "not movable yet".
            for refusal_chirho in &completeness_chirho.refusals_chirho {
                let migration_completeness_chirho::CompletenessRefusalChirho::UnknownSurfaceChirho {
                    surface_chirho,
                } = refusal_chirho;
                println!("UNDECLARED SURFACE: {surface_chirho}");
            }
            // Absence is NOT a refusal — a root need not use every surface the platform defines —
            // so it is summarised rather than enumerated. Listing all of them buries the actual
            // refusals: on a freshly created root this printed 93 routine lines above one real
            // finding, and a report whose signal is drowned is a report operators stop reading.
            // The COUNT keeps the only signal absence really carries: a near-total absence usually
            // means you are pointed at the wrong root, not that the root is empty.
            let absent_count_chirho = completeness_chirho.declared_but_absent_chirho.len();
            if absent_count_chirho > 0 {
                println!(
                    "declared but absent here: {absent_count_chirho} surface(s) — routine unless \
                     nearly all of them, which usually means the wrong root"
                );
                if absent_count_chirho <= ABSENT_SURFACE_LIST_LIMIT_CHIRHO {
                    for absent_chirho in &completeness_chirho.declared_but_absent_chirho {
                        println!("  absent: {absent_chirho}");
                    }
                }
            }
            for refusal_chirho in &containment_chirho.refusals_chirho {
                match refusal_chirho {
                    self_containment_chirho::SelfContainmentRefusalChirho::DanglingReferenceChirho {
                        log_name_chirho,
                        seq_chirho,
                        hash_chirho,
                    } => println!(
                        "UNRESOLVED REFERENCE: {log_name_chirho} line {seq_chirho} -> {hash_chirho}"
                    ),
                    // This report compares against no source root, so it cannot produce this
                    // variant. Named rather than wildcarded: if a future caller does supply a
                    // source, the operator must be told the difference, because "lost against the
                    // source" is a certainty where "unresolved" is an upper bound.
                    self_containment_chirho::SelfContainmentRefusalChirho::LostAgainstSourceChirho {
                        log_name_chirho,
                        seq_chirho,
                        hash_chirho,
                    } => println!(
                        "LOST AGAINST SOURCE: {log_name_chirho} line {seq_chirho} -> {hash_chirho} \
                         — this object exists at the source and not here"
                    ),
                }
            }
            if !containment_chirho.refusals_chirho.is_empty() {
                // Say what the number is an upper bound ON. The scanner takes any maximal run of
                // exactly 64 hex chars, so a digest that names something other than a stored object
                // — a run key, a coordinate digest, a seal — has no CAS object behind it and lands
                // here. Unresolved is a CEILING on dangling references, never a count of them.
                println!(
                    "note: unresolved counts are an UPPER BOUND — a 64-hex digest that names \
                     something other than a stored object also lands here"
                );
            }

            // The third half: what a migration DOES with each surface. A root can pass the other two
            // — fully shown, everything resolving locally — and still hold a private signing key
            // nobody has decided how to move.
            // `None`, and the operator must be told what that costs. The CONFIGURED ledger storage
            // namespace is a root-level directory whose name the operator chose, and it is readable
            // only from that root's ledger config, which this report does not take. So a configured
            // namespace shows up here as UNDECLARED / NO DISPOSITION while the resident activation
            // path — which does read the config — accounts for it. Reporting that difference is
            // better than guessing a name: a guessed literal would silently accept a directory this
            // root never configured.
            let disposition_chirho = surface_disposition_chirho::verify_surface_dispositions_chirho(
                &snapshot_chirho.observed_surfaces_chirho(),
                None,
            );
            println!(
                "disposition_population_digest_chirho={}",
                disposition_chirho
                    .disposition_population_digest_chirho
                    .as_str_chirho()
            );
            println!(
                "note: the disposition digest covers semantic classification, not the caller's \
                 observed-surface enumeration"
            );
            for refusal_chirho in &disposition_chirho.refusals_chirho {
                match refusal_chirho {
                    surface_disposition_chirho::DispositionRefusalChirho::UndisposedSurfaceChirho {
                        surface_chirho,
                    } => println!("NO DISPOSITION: {surface_chirho}"),
                    surface_disposition_chirho::DispositionRefusalChirho::CustodyTransferNotMechanisedChirho {
                        surface_chirho,
                    } => println!(
                        "CUSTODY REFUSED: {surface_chirho} — this is the root's signing identity. \
                         Moving it is a security design question (the private half must not be \
                         copied; the public half decides who the target claims to BE), and this \
                         slice deliberately has no transfer mechanism"
                    ),
                    surface_disposition_chirho::DispositionRefusalChirho::NotAMigrationUnitChirho {
                        surface_chirho,
                    } => println!(
                        "NOT A MIGRATION UNIT: {surface_chirho} — the tenant root is the \
                         placement/authority/migration unit (G1), not the platform root"
                    ),
                }
            }

            // `None`: this report has ONE root and the fourth half compares a target against its
            // source. There is nothing here for a surface to be missing FROM, so the half is not
            // skipped for convenience — it is undefined without a second root, and the migration
            // path that does have one always supplies it.
            match migration_completeness_chirho::preliminary_migration_check_chirho(
                &completeness_chirho,
                &containment_chirho,
                &disposition_chirho,
                None,
                None,
            ) {
                Ok(preliminary_check_chirho) => {
                    println!(
                        "PRELIMINARY MIGRATION CHECK: target preparation is presently eligible — \
                         {} surfaces observed, {} references resolved locally. This is not handoff \
                         authority; activation requires a real source-append fence and a fresh \
                         target verification bound to that exact fenced ledger cut",
                        preliminary_check_chirho.surfaces_observed_chirho(),
                        preliminary_check_chirho.references_checked_chirho()
                    );
                    Ok(true)
                }
                Err(failed_halves_chirho) => {
                    let detail_chirho = failed_halves_chirho
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" and ");
                    anyhow::bail!(
                        "PRELIMINARY MIGRATION CHECK REFUSED: {detail_chirho} failed. Installing a \
                         source append fence for this target now would risk an outage for a move \
                         that cannot finish. If the only findings name this root's CONFIGURED \
                         ledger storage namespace, this report cannot see that name (it reads no \
                         ledger config) and the resident activation path can"
                    )
                }
            }
        }
        CommandChirho::AppsChirho => {
            let apps_chirho = app_chirho::verified_deployed_apps_chirho(root_chirho)?;
            if apps_chirho.is_empty() {
                println!("(no deployed apps)");
            }
            for app_record_chirho in &apps_chirho {
                let Some(dag_chirho) = &app_record_chirho.dag_chirho else {
                    continue;
                };
                let owner_chirho = app_record_chirho
                    .owner_principal_chirho
                    .as_deref()
                    .unwrap_or("(unowned)");
                let name_chirho = &app_record_chirho.app_chirho;
                println!(
                    "{}\t{}\towner={}  (/app-chirho/{})",
                    name_chirho, dag_chirho.0, owner_chirho, name_chirho
                );
            }
            Ok(true)
        }
        CommandChirho::AppStatusChirho { name_chirho } => {
            let status_chirho = app_chirho::app_status_chirho(root_chirho, name_chirho)?;
            match &status_chirho.dag_chirho {
                Some(hash_chirho) => println!("app '{name_chirho}' -> dag {}", hash_chirho.0),
                None => println!("no deployed app '{name_chirho}'"),
            }
            if let Some(owner_chirho) = &status_chirho.owner_principal_chirho {
                println!("  owner: {owner_chirho}");
            }
            println!("  ownership records: {}", status_chirho.records_chirho);
            match effect_pricing_chirho::current_price_book_chirho(root_chirho, name_chirho)? {
                Some((hash_chirho, book_chirho)) => {
                    println!("  price book: {}", hash_chirho.0);
                    if let Some(price_chirho) = book_chirho.price_per_request_chirho {
                        println!("    request price: {price_chirho} token");
                    }
                    if !book_chirho.effect_prices_chirho.is_empty() {
                        for (effect_chirho, price_chirho) in &book_chirho.effect_prices_chirho {
                            println!("    {effect_chirho}: {price_chirho} token");
                        }
                    }
                    println!(
                        "    external markup (reserved): {} bps",
                        book_chirho.external_markup_bps_chirho
                    );
                }
                None => println!("  price book: (none)"),
            }
            match legacy_billing_evidence_chirho::current_billing_policy_single_road_chirho(
                root_chirho,
                name_chirho,
            )? {
                Some((hash_chirho, policy_chirho)) => {
                    println!("  billing policy: {}", hash_chirho.0);
                    println!(
                        "    default: {}",
                        policy_chirho.default_chirho.label_chirho()
                    );
                    for (effect_chirho, mode_chirho) in &policy_chirho.effect_overrides_chirho {
                        println!("    {effect_chirho}: {}", mode_chirho.label_chirho());
                    }
                }
                None => println!("  billing policy: user-pays (implicit)"),
            }
            match onboarding_chirho::current_onboarding_hash_chirho(root_chirho, name_chirho)? {
                Some(hash_chirho) => println!("  onboarding guide: {}", hash_chirho.0),
                None => println!("  onboarding guide: (none)"),
            }
            if status_chirho.routes_chirho.is_empty() {
                println!("  route DAG modules: (none)");
            } else {
                println!("  route DAG modules:");
                for (route_chirho, hash_chirho) in &status_chirho.routes_chirho {
                    println!("    {route_chirho}: {}", hash_chirho.0);
                }
            }
            if status_chirho.active_chirho {
                println!(
                    "  routes: /app-chirho/{name_chirho} , /ssr-chirho/{name_chirho} , POST /invoke-chirho",
                );
                let route_chirho = format!("app/{name_chirho}");
                let changes_chirho = refs_chirho::reflog_chirho(root_chirho)?
                    .into_iter()
                    .filter(|e_chirho| e_chirho.branch_chirho == route_chirho)
                    .count();
                println!("  {changes_chirho} ref change(s); roll back with: rollback {route_chirho} <hash>");
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub(crate) fn handle_app_info_status_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::AppDescriptorChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::AppDescriptorArgsChirho {
                app_chirho,
                json_chirho,
            } = args_chirho;
            match app_descriptor_chirho::app_descriptor_chirho(root_chirho, app_chirho)? {
                Some(descriptor_chirho) => {
                    if *json_chirho {
                        println!("{}", serde_json::to_string_pretty(&descriptor_chirho)?);
                    } else {
                        println!(
                            "app '{}' ({} route(s)):",
                            descriptor_chirho.app_chirho, descriptor_chirho.route_count_chirho
                        );
                        for route_chirho in &descriptor_chirho.routes_chirho {
                            println!(
                                "  {} [input: {}]{}",
                                route_chirho.path_chirho,
                                route_chirho.input_mode_chirho,
                                route_chirho
                                    .response_content_type_chirho
                                    .as_ref()
                                    .map(|c_chirho| format!(" [responds: {c_chirho}]"))
                                    .unwrap_or_default()
                            );
                            println!(
                                "    {}",
                                route_chirho.capability_summary_chirho.sentence_chirho
                            );
                        }
                    }
                }
                None => {
                    if *json_chirho {
                        println!("null");
                    } else {
                        println!("app '{app_chirho}' is not deployed");
                    }
                }
            }
            Ok(true)
        }
        CommandChirho::PlatformMcpChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::PlatformMcpArgsChirho { json_chirho } =
                args_chirho;
            let manifest_chirho = platform_mcp_chirho::platform_mcp_manifest_chirho();
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&manifest_chirho)?);
            } else {
                println!(
                    "platform MCP catalog: {} tools ({} read, {} gated-action)",
                    manifest_chirho.tool_count_chirho,
                    manifest_chirho.read_tool_count_chirho,
                    manifest_chirho.gated_action_count_chirho
                );
                for tool_chirho in &manifest_chirho.tools_chirho {
                    let mark_chirho = if tool_chirho.gated_chirho {
                        "[gated]"
                    } else {
                        "[read]"
                    };
                    println!(
                        "  {} {} -> {}",
                        mark_chirho, tool_chirho.name_chirho, tool_chirho.command_chirho
                    );
                }
            }
            Ok(true)
        }
        CommandChirho::AppDocsChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::AppDocsArgsChirho {
                app_chirho,
                mcp_chirho,
            } = args_chirho;
            match app_descriptor_chirho::app_descriptor_chirho(root_chirho, app_chirho)? {
                Some(descriptor_chirho) => {
                    if *mcp_chirho {
                        let manifest_chirho =
                            app_docs_chirho::app_mcp_manifest_chirho(&descriptor_chirho);
                        println!("{}", serde_json::to_string_pretty(&manifest_chirho)?);
                    } else {
                        print!(
                            "{}",
                            app_docs_chirho::app_docs_markdown_chirho(&descriptor_chirho)
                        );
                    }
                }
                None => {
                    eprintln!("app '{app_chirho}' is not deployed");
                    std::process::exit(1);
                }
            }
            Ok(true)
        }
        CommandChirho::AppCapabilitiesChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::AppCapabilitiesArgsChirho {
                app_chirho,
                json_chirho,
            } = args_chirho;
            match review_chirho::app_capability_summary_chirho(root_chirho, app_chirho)? {
                Some(summary_chirho) => {
                    if *json_chirho {
                        println!("{}", serde_json::to_string_pretty(&summary_chirho)?);
                    } else {
                        println!("{}", summary_chirho.sentence_chirho);
                        for line_chirho in &summary_chirho.lines_chirho {
                            println!("  - {}", line_chirho.plain_chirho);
                        }
                    }
                }
                None => {
                    if *json_chirho {
                        println!("null");
                    } else {
                        println!("app '{app_chirho}' is not deployed");
                    }
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}
pub(crate) fn handle_app_source_status_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::AppSourceCandidateChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::AppSourceCandidateArgsChirho {
                manifest_chirho,
                owner_chirho,
                json_chirho,
            } = args_chirho;
            let report_chirho = if let Some(owner_chirho) = owner_chirho {
                app_source_manifest_chirho::build_app_source_candidate_from_path_for_owner_chirho(
                    root_chirho,
                    manifest_chirho,
                    owner_chirho,
                )?
            } else {
                app_source_manifest_chirho::build_app_source_candidate_from_path_chirho(
                    root_chirho,
                    manifest_chirho,
                )?
            };
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&report_chirho)?);
            } else {
                print_app_source_candidate_chirho(&report_chirho);
            }
            Ok(true)
        }
        CommandChirho::AppSourceReviewChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::AppSourceReviewArgsChirho {
                manifest_chirho,
                owner_chirho,
                json_chirho,
                steward_view_chirho,
            } = args_chirho;
            let report_chirho = if let Some(owner_chirho) = owner_chirho {
                app_source_manifest_chirho::build_app_source_review_from_path_for_owner_chirho(
                    root_chirho,
                    manifest_chirho,
                    owner_chirho,
                )?
            } else {
                app_source_manifest_chirho::build_app_source_review_from_path_chirho(
                    root_chirho,
                    manifest_chirho,
                )?
            };
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&report_chirho)?);
            } else {
                let undo_plan_reviews_chirho =
                    app_source_manifest_chirho::load_verified_app_source_undo_plan_reviews_chirho(
                        root_chirho,
                        &report_chirho.candidate_chirho,
                    )?;
                if *steward_view_chirho {
                    let body_chirho =
                        cairn_review_policy_chirho::app_source_review_steward_body_chirho(
                            &report_chirho,
                        )?;
                    println!("{body_chirho}");
                    println!(
                        "{}",
                        app_source_undo_plan_review_body_chirho(&undo_plan_reviews_chirho, false)
                    );
                } else {
                    print_app_source_review_chirho(&report_chirho);
                    println!(
                        "{}",
                        app_source_undo_plan_review_body_chirho(&undo_plan_reviews_chirho, true)
                    );
                    if let Ok(capabilities_chirho) =
                        dag_capability_scan_chirho::collect_dag_capabilities_chirho(
                            root_chirho,
                            &report_chirho.candidate_chirho.root_dag_chirho,
                        )
                    {
                        let summary_chirho = capability_plain_chirho::summarize_capabilities_chirho(
                            &capabilities_chirho,
                        );
                        println!("what this candidate can do (plain language):");
                        println!("  {}", summary_chirho.sentence_chirho);
                    }
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}
pub(crate) fn handle_ops_status_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::LaunchReadinessChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::LaunchReadinessArgsChirho {
                manifest_chirho,
                json_chirho,
                fail_on_production_blockers_chirho,
            } = args_chirho;
            let manifest_chirho = manifest_chirho.clone().unwrap_or_else(
                launch_readiness_chirho::default_launch_readiness_manifest_path_chirho,
            );
            let report_chirho = launch_readiness_chirho::run_launch_readiness_chirho(
                root_chirho,
                &manifest_chirho,
            )?;
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&report_chirho)?);
            } else {
                print!(
                    "{}",
                    launch_readiness_chirho::launch_readiness_text_chirho(&report_chirho)
                );
            }
            if *fail_on_production_blockers_chirho
                && launch_readiness_chirho::has_production_blockers_chirho(&report_chirho)
            {
                anyhow::bail!(
                    "launch readiness has {} production blocker(s); local_candidate_ready={} production_ready={}",
                    report_chirho.blockers_chirho.len(),
                    report_chirho.local_candidate_ready_chirho,
                    report_chirho.production_ready_chirho
                );
            }
            Ok(true)
        }
        CommandChirho::OpsRestoreDrillChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::OpsRestoreDrillArgsChirho {
                json_chirho,
                fail_on_restore_blockers_chirho,
            } = args_chirho;
            let report_chirho =
                ops_restore_drill_chirho::run_ops_restore_drill_chirho(root_chirho)?;
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&report_chirho)?);
            } else {
                print_ops_restore_drill_chirho(&report_chirho);
            }
            if *fail_on_restore_blockers_chirho && !report_chirho.restore_verified_chirho {
                anyhow::bail!(
                    "ops restore drill did not verify cleanly; hosted_ops_blocker_closed={}",
                    report_chirho.hosted_ops_blocker_closed_chirho
                );
            }
            Ok(true)
        }
        CommandChirho::OpsCustodyInventoryChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::OpsCustodyInventoryArgsChirho {
                json_chirho,
                config_chirho,
                env_file_chirho,
                fail_on_custody_blockers_chirho,
            } = args_chirho;
            let report_chirho = ops_custody_chirho::run_ops_custody_inventory_chirho(
                root_chirho,
                config_chirho.as_deref(),
                env_file_chirho.as_deref(),
            )?;
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&report_chirho)?);
            } else {
                print_ops_custody_inventory_chirho(&report_chirho);
            }
            if *fail_on_custody_blockers_chirho {
                ops_custody_chirho::ensure_ops_custody_ready_chirho(&report_chirho)?;
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}
