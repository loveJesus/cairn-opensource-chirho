// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Plain-language capability summaries: translate an app's typed capability set into "this app can save encrypted submissions, send email through your account — and nothing else" for owner review.
//!
//! Pure and side-effect-free over [`CapabilityChirho`] (the honest source of truth for everything
//! an app can do to the world), so the same summary backs the review UI, the owner API, and MCP.
//! Capabilities an app does NOT hold simply do not appear — there is no way to under-report.

use cairn_core_chirho::model_chirho::CapabilityChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::capability_dictionary_chirho::{capability_form_for_spec_chirho, CapabilityFormChirho};

/// One capability rendered for a non-technical owner: a plain sentence plus the few booleans a
/// review surface highlights (money, messaging, network, private-data access).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityPlainChirho {
    pub plain_chirho: String,
    pub category_chirho: String,
    pub touches_money_chirho: bool,
    pub sends_messages_chirho: bool,
    pub reaches_network_chirho: bool,
    pub writes_data_chirho: bool,
    pub reads_data_chirho: bool,
}

/// The owner-facing summary of an app's whole capability set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySummaryChirho {
    /// One human sentence: "This app can: …, … — and nothing else." (or the pure-app sentence).
    pub sentence_chirho: String,
    pub capability_count_chirho: usize,
    pub is_pure_chirho: bool,
    pub can_spend_money_chirho: bool,
    pub can_send_messages_chirho: bool,
    pub can_reach_network_chirho: bool,
    pub can_write_data_chirho: bool,
    pub can_read_data_chirho: bool,
    pub lines_chirho: Vec<CapabilityPlainChirho>,
}

/// One capability rendered through the machine-readable dictionary template.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDictionaryPlainChirho {
    pub spec_chirho: String,
    pub form_id_chirho: String,
    pub category_chirho: String,
    pub shape_chirho: String,
    pub plain_chirho: String,
}

/// One generic learner catalog card. Product-specific card sets live outside Cairn; these three
/// cards are fixture/runtime teaching shapes used to prove steward rendering and envelope refs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnerCatalogCardChirho {
    pub id_chirho: String,
    pub title_chirho: String,
    pub contract_ref_chirho: String,
    pub capability_label_chirho: String,
    pub power_body_chirho: String,
}

pub fn learner_catalog_cards_chirho() -> Vec<LearnerCatalogCardChirho> {
    vec![
        learner_catalog_card_chirho(
            "classroom-write-prefix-chirho",
            "Classroom-scoped write prefix",
            "blessed-contract:614d12abeb18b308dd4ad0c9d4464d5d9112dc6efef2af2e3ee14e86d692b735",
            "WriteStoreChirho(prefix=classroom-submissions-chirho)",
        ),
        learner_catalog_card_chirho(
            "bounded-query-chirho",
            "Bounded classroom query",
            "blessed-contract:cf4c4c06d5e5918b71cbb19cc18f2fa4d2925a3eddbbbc0adf7a7cfddbc71158",
            "QueryChirho(prefix=classroom-submissions-chirho,caller=owner/classroom-steward-chirho,max_rows=25)",
        ),
        learner_catalog_card_chirho(
            "stub-llm-chirho",
            "Stub LLM effect",
            "blessed-contract:ef3cb8e43acc061f5d76196060ecd6eeaf7921d312fc00577e5eea15297b8742",
            "PaidEffectChirho(effect=llm_chirho,caller=owner/classroom-steward-chirho)",
        ),
    ]
}

fn learner_catalog_card_chirho(
    id_chirho: &str,
    title_chirho: &str,
    contract_ref_chirho: &str,
    capability_label_chirho: &str,
) -> LearnerCatalogCardChirho {
    LearnerCatalogCardChirho {
        id_chirho: id_chirho.to_string(),
        title_chirho: title_chirho.to_string(),
        contract_ref_chirho: contract_ref_chirho.to_string(),
        capability_label_chirho: capability_label_chirho.to_string(),
        power_body_chirho: review_capability_power_body_chirho(capability_label_chirho),
    }
}

fn paid_effect_is_messaging_chirho(effect_chirho: &str) -> bool {
    let lower_chirho = effect_chirho.to_ascii_lowercase();
    lower_chirho.contains("email") || lower_chirho.contains("sms") || lower_chirho.contains("mail")
}

/// Render one typed capability through the checked-in capability dictionary template.
pub fn describe_capability_with_dictionary_chirho(
    capability_chirho: &CapabilityChirho,
) -> Option<CapabilityDictionaryPlainChirho> {
    let spec_chirho = capability_to_compact_spec_chirho(capability_chirho)?;
    let form_chirho = capability_form_for_spec_chirho(&spec_chirho)?;
    let fields_chirho = capability_template_fields_chirho(capability_chirho)?;
    Some(render_capability_template_chirho(
        &spec_chirho,
        form_chirho,
        &fields_chirho,
    ))
}

/// Render a stable review-diff capability label through the dictionary when it is a compact
/// manifest capability form.
pub fn describe_review_capability_label_with_dictionary_chirho(
    label_chirho: &str,
) -> Option<CapabilityDictionaryPlainChirho> {
    let capability_chirho = review_label_to_capability_chirho(label_chirho)?;
    describe_capability_with_dictionary_chirho(&capability_chirho)
}

/// Format the stable body used by review text output for a capability power line.
pub fn review_capability_power_body_chirho(label_chirho: &str) -> String {
    match describe_review_capability_label_with_dictionary_chirho(label_chirho) {
        Some(line_chirho) => format!(
            "form={}\tcategory={}\tplain={}",
            line_chirho.form_id_chirho, line_chirho.category_chirho, line_chirho.plain_chirho
        ),
        None => format!(
            "form=(missing)\tcategory=(unknown)\tplain=(no dictionary template for {label_chirho})"
        ),
    }
}

/// Translate one capability into a plain owner-readable line.
pub fn describe_capability_chirho(capability_chirho: &CapabilityChirho) -> CapabilityPlainChirho {
    let mut line_chirho = CapabilityPlainChirho {
        plain_chirho: String::new(),
        category_chirho: "other".to_string(),
        touches_money_chirho: false,
        sends_messages_chirho: false,
        reaches_network_chirho: false,
        writes_data_chirho: false,
        reads_data_chirho: false,
    };
    match capability_chirho {
        CapabilityChirho::ReadStoreChirho { prefix_chirho } => {
            line_chirho.plain_chirho = format!("Read your saved data under \"{prefix_chirho}\".");
            line_chirho.category_chirho = "data".to_string();
            line_chirho.reads_data_chirho = true;
        }
        CapabilityChirho::QueryChirho { prefix_chirho, .. } => {
            line_chirho.plain_chirho =
                format!("Look up your saved data under \"{prefix_chirho}\".");
            line_chirho.category_chirho = "data".to_string();
            line_chirho.reads_data_chirho = true;
        }
        CapabilityChirho::WriteStoreChirho { prefix_chirho } => {
            line_chirho.plain_chirho =
                format!("Save data under \"{prefix_chirho}\" (encrypted; you can roll it back).");
            line_chirho.category_chirho = "data".to_string();
            line_chirho.writes_data_chirho = true;
        }
        CapabilityChirho::PaidEffectChirho { effect_chirho, .. } => {
            if paid_effect_is_messaging_chirho(effect_chirho) {
                line_chirho.plain_chirho = format!(
                    "Send messages through your account using \"{effect_chirho}\" (billed to you)."
                );
                line_chirho.sends_messages_chirho = true;
                line_chirho.category_chirho = "messaging".to_string();
            } else {
                line_chirho.plain_chirho =
                    format!("Use the paid service \"{effect_chirho}\" (billed to your account).");
                line_chirho.category_chirho = "money".to_string();
            }
            line_chirho.touches_money_chirho = true;
        }
        CapabilityChirho::NetChirho { allowlist_chirho } => {
            let hosts_chirho = if allowlist_chirho.is_empty() {
                "(no hosts listed)".to_string()
            } else {
                allowlist_chirho.join(", ")
            };
            line_chirho.plain_chirho =
                format!("Reach these outside services over the network: {hosts_chirho}.");
            line_chirho.category_chirho = "network".to_string();
            line_chirho.reaches_network_chirho = true;
        }
        CapabilityChirho::SecretRefChirho { name_chirho } => {
            line_chirho.plain_chirho =
                format!("Use the stored secret \"{name_chirho}\" (its value is never shown).");
            line_chirho.category_chirho = "secret".to_string();
        }
        CapabilityChirho::RealtimeSessionChirho { .. } => {
            line_chirho.plain_chirho =
                "Open a live realtime (voice) session (billed to your account).".to_string();
            line_chirho.category_chirho = "realtime".to_string();
            line_chirho.touches_money_chirho = true;
        }
        CapabilityChirho::UserIdentityChirho { .. } => {
            line_chirho.plain_chirho = "Act on behalf of a signed-in user of your app.".to_string();
            line_chirho.category_chirho = "identity".to_string();
        }
        CapabilityChirho::AppContextChirho { .. } => {
            line_chirho.plain_chirho =
                "Run inside your app's billing and pricing context.".to_string();
            line_chirho.category_chirho = "identity".to_string();
        }
        CapabilityChirho::SupportIssueChirho { .. } => {
            line_chirho.plain_chirho = "Act on a support issue for your app.".to_string();
            line_chirho.category_chirho = "support".to_string();
        }
        CapabilityChirho::CausalReversionChirho { branch_chirho } => {
            line_chirho.plain_chirho =
                format!("Roll back history on the \"{branch_chirho}\" branch.");
            line_chirho.category_chirho = "rollback".to_string();
        }
        CapabilityChirho::ClockChirho => {
            line_chirho.plain_chirho = "Read the current time.".to_string();
            line_chirho.category_chirho = "environment".to_string();
        }
        CapabilityChirho::RandomChirho => {
            line_chirho.plain_chirho =
                "Use randomness (for example, to make unique ids).".to_string();
            line_chirho.category_chirho = "environment".to_string();
        }
        CapabilityChirho::InvokeChirho { .. } => {
            line_chirho.plain_chirho = "Call another approved step in your app.".to_string();
            line_chirho.category_chirho = "internal".to_string();
        }
        CapabilityChirho::TemplateAppDeployChirho { template_id_chirho } => {
            line_chirho.plain_chirho =
                format!("Deploy a new app from the reviewed \"{template_id_chirho}\" template.");
            line_chirho.category_chirho = "app-deploy".to_string();
            line_chirho.writes_data_chirho = true;
        }
    }
    line_chirho
}

fn capability_to_compact_spec_chirho(capability_chirho: &CapabilityChirho) -> Option<String> {
    match capability_chirho {
        CapabilityChirho::ClockChirho => Some("clock".to_string()),
        CapabilityChirho::RandomChirho => Some("random".to_string()),
        CapabilityChirho::ReadStoreChirho { prefix_chirho } => {
            Some(format!("read-store:{prefix_chirho}"))
        }
        CapabilityChirho::WriteStoreChirho { prefix_chirho } => {
            Some(format!("write-store:{prefix_chirho}"))
        }
        CapabilityChirho::PaidEffectChirho {
            effect_chirho,
            caller_chirho,
        } => Some(format!("paid:{effect_chirho}:{caller_chirho}")),
        CapabilityChirho::UserIdentityChirho {
            principal_chirho,
            client_id_chirho,
            token_hash_chirho,
        } => Some(format!(
            "identity:{principal_chirho}:{client_id_chirho}:{token_hash_chirho}"
        )),
        CapabilityChirho::AppContextChirho {
            app_chirho,
            owner_principal_chirho,
            ..
        } => Some(format!("app:{app_chirho}:{owner_principal_chirho}")),
        CapabilityChirho::SecretRefChirho { name_chirho } => Some(format!("secret:{name_chirho}")),
        CapabilityChirho::NetChirho { allowlist_chirho } => {
            Some(format!("net:{}", allowlist_chirho.join("|")))
        }
        CapabilityChirho::QueryChirho {
            prefix_chirho,
            caller_chirho,
            max_rows_chirho,
        } => Some(format!(
            "query:{prefix_chirho}:{caller_chirho}:{max_rows_chirho}"
        )),
        CapabilityChirho::InvokeChirho { node_chirho } => Some(format!("invoke:{}", node_chirho.0)),
        CapabilityChirho::TemplateAppDeployChirho { template_id_chirho } => {
            Some(format!("template-app-deploy:{template_id_chirho}"))
        }
        CapabilityChirho::RealtimeSessionChirho { .. }
        | CapabilityChirho::SupportIssueChirho { .. }
        | CapabilityChirho::CausalReversionChirho { .. } => None,
    }
}

fn capability_template_fields_chirho(
    capability_chirho: &CapabilityChirho,
) -> Option<BTreeMap<&'static str, String>> {
    let mut fields_chirho = BTreeMap::new();
    match capability_chirho {
        CapabilityChirho::ClockChirho | CapabilityChirho::RandomChirho => {}
        CapabilityChirho::ReadStoreChirho { prefix_chirho }
        | CapabilityChirho::WriteStoreChirho { prefix_chirho } => {
            fields_chirho.insert("prefix_chirho", prefix_chirho.clone());
        }
        CapabilityChirho::PaidEffectChirho {
            effect_chirho,
            caller_chirho,
        } => {
            fields_chirho.insert("effect_chirho", effect_chirho.clone());
            fields_chirho.insert("caller_chirho", caller_chirho.clone());
        }
        CapabilityChirho::UserIdentityChirho {
            principal_chirho,
            client_id_chirho,
            token_hash_chirho,
        } => {
            fields_chirho.insert("principal_chirho", principal_chirho.clone());
            fields_chirho.insert("client_id_chirho", client_id_chirho.clone());
            fields_chirho.insert("token_hash_chirho", token_hash_chirho.clone());
        }
        CapabilityChirho::AppContextChirho {
            app_chirho,
            owner_principal_chirho,
            ..
        } => {
            fields_chirho.insert("app_chirho", app_chirho.clone());
            fields_chirho.insert("owner_principal_chirho", owner_principal_chirho.clone());
        }
        CapabilityChirho::SecretRefChirho { name_chirho } => {
            fields_chirho.insert("name_chirho", name_chirho.clone());
        }
        CapabilityChirho::NetChirho { allowlist_chirho } => {
            fields_chirho.insert("allowlist_chirho", allowlist_chirho.join("|"));
        }
        CapabilityChirho::QueryChirho {
            prefix_chirho,
            caller_chirho,
            max_rows_chirho,
        } => {
            fields_chirho.insert("prefix_chirho", prefix_chirho.clone());
            fields_chirho.insert("caller_chirho", caller_chirho.clone());
            fields_chirho.insert("max_rows_chirho", max_rows_chirho.to_string());
        }
        CapabilityChirho::InvokeChirho { node_chirho } => {
            fields_chirho.insert("node_chirho", node_chirho.0.clone());
        }
        CapabilityChirho::TemplateAppDeployChirho { template_id_chirho } => {
            fields_chirho.insert("template_id_chirho", template_id_chirho.clone());
        }
        CapabilityChirho::RealtimeSessionChirho { .. }
        | CapabilityChirho::SupportIssueChirho { .. }
        | CapabilityChirho::CausalReversionChirho { .. } => return None,
    }
    Some(fields_chirho)
}

fn render_capability_template_chirho(
    spec_chirho: &str,
    form_chirho: &CapabilityFormChirho,
    fields_chirho: &BTreeMap<&'static str, String>,
) -> CapabilityDictionaryPlainChirho {
    let mut plain_chirho = form_chirho.plain_template_chirho.to_string();
    for field_chirho in form_chirho.fields_chirho {
        let value_chirho = fields_chirho
            .get(field_chirho.name_chirho)
            .cloned()
            .unwrap_or_default();
        plain_chirho =
            plain_chirho.replace(&format!("{{{}}}", field_chirho.name_chirho), &value_chirho);
    }
    CapabilityDictionaryPlainChirho {
        spec_chirho: spec_chirho.to_string(),
        form_id_chirho: form_chirho.id_chirho.to_string(),
        category_chirho: form_chirho.category_chirho.to_string(),
        shape_chirho: form_chirho.shape_chirho.to_string(),
        plain_chirho,
    }
}

fn review_label_to_capability_chirho(label_chirho: &str) -> Option<CapabilityChirho> {
    if label_chirho == "ClockChirho" {
        return Some(CapabilityChirho::ClockChirho);
    }
    if label_chirho == "RandomChirho" {
        return Some(CapabilityChirho::RandomChirho);
    }
    let open_chirho = label_chirho.find('(')?;
    let close_chirho = label_chirho.strip_suffix(')')?;
    let kind_chirho = &label_chirho[..open_chirho];
    let fields_chirho = review_label_fields_chirho(kind_chirho, &close_chirho[open_chirho + 1..]);

    if !validate_review_label_fields_chirho(kind_chirho, &fields_chirho) {
        return None;
    }

    match kind_chirho {
        "ReadStoreChirho" => Some(CapabilityChirho::ReadStoreChirho {
            prefix_chirho: fields_chirho.get("prefix").cloned()?,
        }),
        "WriteStoreChirho" => Some(CapabilityChirho::WriteStoreChirho {
            prefix_chirho: fields_chirho.get("prefix").cloned()?,
        }),
        "PaidEffectChirho" => Some(CapabilityChirho::PaidEffectChirho {
            effect_chirho: fields_chirho.get("effect").cloned()?,
            caller_chirho: fields_chirho.get("caller").cloned()?,
        }),
        "UserIdentityChirho" => Some(CapabilityChirho::UserIdentityChirho {
            principal_chirho: fields_chirho.get("principal").cloned()?,
            client_id_chirho: fields_chirho.get("client").cloned()?,
            token_hash_chirho: fields_chirho.get("token").cloned()?,
        }),
        "AppContextChirho" => Some(CapabilityChirho::AppContextChirho {
            app_chirho: fields_chirho.get("app").cloned()?,
            owner_principal_chirho: fields_chirho.get("owner").cloned()?,
            price_book_chirho: None,
            billing_policy_chirho: None,
        }),
        "SecretRefChirho" => Some(CapabilityChirho::SecretRefChirho {
            name_chirho: fields_chirho.get("name").cloned()?,
        }),
        "NetChirho" => Some(CapabilityChirho::NetChirho {
            allowlist_chirho: fields_chirho
                .get("allowlist")?
                .split(',')
                .filter(|value_chirho| !value_chirho.trim().is_empty())
                .map(|value_chirho| value_chirho.trim().to_string())
                .collect(),
        }),
        "QueryChirho" => Some(CapabilityChirho::QueryChirho {
            prefix_chirho: fields_chirho.get("prefix").cloned()?,
            caller_chirho: fields_chirho.get("caller").cloned()?,
            max_rows_chirho: fields_chirho.get("max_rows")?.parse().ok()?,
        }),
        "InvokeChirho" => Some(CapabilityChirho::InvokeChirho {
            node_chirho: cairn_core_chirho::model_chirho::HashChirho(
                fields_chirho.get("node").cloned()?,
            ),
        }),
        "TemplateAppDeployChirho" => Some(CapabilityChirho::TemplateAppDeployChirho {
            template_id_chirho: fields_chirho.get("template").cloned()?,
        }),
        "RealtimeSessionChirho" => Some(CapabilityChirho::RealtimeSessionChirho {
            app_chirho: fields_chirho.get("app").cloned()?,
            caller_chirho: fields_chirho.get("caller").cloned()?,
        }),
        "SupportIssueChirho" => Some(CapabilityChirho::SupportIssueChirho {
            issue_chirho: fields_chirho.get("issue").cloned()?,
            actions_chirho: fields_chirho
                .get("actions")?
                .split(',')
                .filter(|val_chirho| !val_chirho.trim().is_empty())
                .map(|val_chirho| val_chirho.trim().to_string())
                .collect(),
        }),
        "CausalReversionChirho" => Some(CapabilityChirho::CausalReversionChirho {
            branch_chirho: fields_chirho.get("branch").cloned()?,
        }),
        _ => None,
    }
}

fn validate_review_label_fields_chirho(
    kind_chirho: &str,
    fields_chirho: &BTreeMap<String, String>,
) -> bool {
    let expected_keys_chirho: &[&str] = match kind_chirho {
        "ReadStoreChirho" | "WriteStoreChirho" => &["prefix"],
        "PaidEffectChirho" => &["effect", "caller"],
        "UserIdentityChirho" => &["principal", "client", "token"],
        "AppContextChirho" => &["app", "owner", "pricebook", "billing"],
        "SecretRefChirho" => &["name"],
        "RealtimeSessionChirho" => &["app", "caller"],
        "SupportIssueChirho" => &["issue", "actions"],
        "CausalReversionChirho" => &["branch"],
        "NetChirho" => &["allowlist"],
        "QueryChirho" => &["prefix", "caller", "max_rows"],
        "InvokeChirho" => &["node"],
        "TemplateAppDeployChirho" => &["template"],
        _ => return false,
    };
    if fields_chirho.len() != expected_keys_chirho.len() {
        return false;
    }
    for key_chirho in expected_keys_chirho {
        if !fields_chirho.contains_key(*key_chirho) {
            return false;
        }
    }
    true
}

fn review_label_fields_chirho(
    kind_chirho: &str,
    label_body_chirho: &str,
) -> BTreeMap<String, String> {
    let mut fields_chirho = BTreeMap::new();
    let mut last_key_chirho: Option<String> = None;
    for part_chirho in label_body_chirho.split(',') {
        if let Some((key_chirho, value_chirho)) = part_chirho.split_once('=') {
            let k_chirho = key_chirho.trim().to_string();
            let value_chirho = value_chirho.trim();
            if k_chirho.is_empty()
                || value_chirho.is_empty()
                || value_chirho.contains('=')
                || fields_chirho.contains_key(&k_chirho)
            {
                return BTreeMap::new();
            }
            fields_chirho.insert(k_chirho.clone(), value_chirho.to_string());
            last_key_chirho = Some(k_chirho);
        } else if let Some(k_chirho) = &last_key_chirho {
            if !review_label_field_allows_comma_continuation_chirho(kind_chirho, k_chirho) {
                return BTreeMap::new();
            }
            if let Some(existing_val_chirho) = fields_chirho.get_mut(k_chirho) {
                let part_chirho = part_chirho.trim();
                if part_chirho.is_empty() {
                    return BTreeMap::new();
                }
                existing_val_chirho.push(',');
                existing_val_chirho.push_str(part_chirho);
            }
        } else {
            return BTreeMap::new();
        }
    }
    fields_chirho
}

fn review_label_field_allows_comma_continuation_chirho(
    kind_chirho: &str,
    key_chirho: &str,
) -> bool {
    matches!(
        (kind_chirho, key_chirho),
        ("NetChirho", "allowlist") | ("SupportIssueChirho", "actions")
    )
}

/// Summarize a whole capability set into an owner-readable sentence and the highlight booleans.
pub fn summarize_capabilities_chirho(
    capabilities_chirho: &[CapabilityChirho],
) -> CapabilitySummaryChirho {
    let lines_chirho: Vec<CapabilityPlainChirho> = capabilities_chirho
        .iter()
        .map(describe_capability_chirho)
        .collect();

    let can_spend_money_chirho = lines_chirho
        .iter()
        .any(|l_chirho| l_chirho.touches_money_chirho);
    let can_send_messages_chirho = lines_chirho
        .iter()
        .any(|l_chirho| l_chirho.sends_messages_chirho);
    let can_reach_network_chirho = lines_chirho
        .iter()
        .any(|l_chirho| l_chirho.reaches_network_chirho);
    let can_write_data_chirho = lines_chirho
        .iter()
        .any(|l_chirho| l_chirho.writes_data_chirho);
    let can_read_data_chirho = lines_chirho
        .iter()
        .any(|l_chirho| l_chirho.reads_data_chirho);
    let is_pure_chirho = lines_chirho.is_empty();

    let sentence_chirho = if is_pure_chirho {
        "This app is pure: it cannot touch the outside world at all — no saving data, no network, no money."
            .to_string()
    } else {
        // Lowercase each line's leading verb so they read as a list inside one sentence.
        let mut clauses_chirho: Vec<String> = lines_chirho
            .iter()
            .map(|l_chirho| {
                let trimmed_chirho = l_chirho.plain_chirho.trim_end_matches('.');
                let mut chars_chirho = trimmed_chirho.chars();
                match chars_chirho.next() {
                    Some(first_chirho) => {
                        first_chirho.to_ascii_lowercase().to_string() + chars_chirho.as_str()
                    }
                    None => String::new(),
                }
            })
            .collect();
        clauses_chirho.retain(|c_chirho| !c_chirho.is_empty());
        format!(
            "This app can: {} — and nothing else.",
            clauses_chirho.join("; ")
        )
    };

    CapabilitySummaryChirho {
        sentence_chirho,
        capability_count_chirho: lines_chirho.len(),
        is_pure_chirho,
        can_spend_money_chirho,
        can_send_messages_chirho,
        can_reach_network_chirho,
        can_write_data_chirho,
        can_read_data_chirho,
        lines_chirho,
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn pure_app_says_it_cannot_touch_the_world_chirho() {
        let summary_chirho = summarize_capabilities_chirho(&[]);
        assert!(summary_chirho.is_pure_chirho);
        assert_eq!(summary_chirho.capability_count_chirho, 0);
        assert!(!summary_chirho.can_spend_money_chirho);
        assert!(!summary_chirho.can_write_data_chirho);
        assert!(summary_chirho.sentence_chirho.contains("pure"));
        assert!(summary_chirho
            .sentence_chirho
            .contains("cannot touch the outside world"));
    }

    #[test]
    fn write_store_reads_as_save_encrypted_chirho() {
        let line_chirho = describe_capability_chirho(&CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "contact/".to_string(),
        });
        assert!(line_chirho.writes_data_chirho);
        assert!(!line_chirho.touches_money_chirho);
        assert_eq!(line_chirho.category_chirho, "data");
        assert!(line_chirho.plain_chirho.contains("contact/"));
        assert!(line_chirho.plain_chirho.contains("encrypted"));
    }

    #[test]
    fn dictionary_render_uses_declared_form_structure_chirho() {
        let line_chirho =
            describe_capability_with_dictionary_chirho(&CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "contact/".to_string(),
            })
            .unwrap();
        assert_eq!(line_chirho.form_id_chirho, "write_store_chirho");
        assert_eq!(line_chirho.category_chirho, "data");
        assert_eq!(line_chirho.shape_chirho, "write-store:<prefix_chirho>");
        assert_eq!(line_chirho.spec_chirho, "write-store:contact/");
        assert!(line_chirho.plain_chirho.contains("contact/"));
    }

    #[test]
    fn review_label_renders_through_dictionary_chirho() {
        let line_chirho = describe_review_capability_label_with_dictionary_chirho(
            "QueryChirho(prefix=contacts,caller=owner/demo,max_rows=10)",
        )
        .unwrap();
        assert_eq!(line_chirho.form_id_chirho, "query_chirho");
        assert_eq!(line_chirho.spec_chirho, "query:contacts:owner/demo:10");
        assert_eq!(
            line_chirho.shape_chirho,
            "query:<prefix_chirho>:<caller_chirho>:<max_rows_chirho>"
        );
        assert!(line_chirho.plain_chirho.contains("contacts"));
        assert!(line_chirho.plain_chirho.contains("owner/demo"));
    }

    #[test]
    fn learner_catalog_has_exact_three_dictionary_cards_chirho() {
        let cards_chirho = learner_catalog_cards_chirho();
        assert_eq!(cards_chirho.len(), 3);
        assert_eq!(
            cards_chirho
                .iter()
                .map(|card_chirho| card_chirho.id_chirho.as_str())
                .collect::<Vec<_>>(),
            vec![
                "classroom-write-prefix-chirho",
                "bounded-query-chirho",
                "stub-llm-chirho"
            ]
        );
        for card_chirho in cards_chirho {
            assert!(card_chirho
                .contract_ref_chirho
                .starts_with("blessed-contract:"));
            assert!(card_chirho.power_body_chirho.contains("\tplain="));
            assert!(
                !card_chirho.power_body_chirho.contains("form=(missing)"),
                "learner cards must be backed by SP2 dictionary templates"
            );
        }
    }

    #[test]
    fn review_power_body_pins_output_structure_chirho() {
        let line_chirho =
            review_capability_power_body_chirho("WriteStoreChirho(prefix=contacts-chirho)");
        assert!(line_chirho.starts_with("form=write_store_chirho\t"));
        assert!(line_chirho.contains("\tcategory=data\t"));
        assert!(line_chirho.contains("\tplain="));

        let spoof_line_chirho =
            review_capability_power_body_chirho("WriteStoreChirho(prefix=public,x=victim)");
        assert!(spoof_line_chirho.starts_with("form=(missing)\t"));
        assert!(!spoof_line_chirho.contains("Save data under"));
    }

    #[test]
    fn review_label_injection_prevention_chirho() {
        // Valid
        let valid_store_chirho =
            review_label_to_capability_chirho("WriteStoreChirho(prefix=public)").unwrap();
        assert_eq!(
            valid_store_chirho,
            CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "public".to_string()
            }
        );

        // Injection of extra fields fails
        assert!(review_label_to_capability_chirho(
            "WriteStoreChirho(prefix=public,x=victim-secrets)"
        )
        .is_none());

        // Scalar comma continuations fail instead of truncating or hiding the extra segment.
        assert!(review_label_to_capability_chirho(
            "WriteStoreChirho(prefix=public,victim-secrets)"
        )
        .is_none());

        // Duplicate keys fail
        assert!(
            review_label_to_capability_chirho("WriteStoreChirho(prefix=public,prefix=evil)")
                .is_none()
        );

        // Embedded field separators inside values fail closed.
        assert!(review_label_to_capability_chirho(
            "PaidEffectChirho(effect=innocent=caller=owner,caller=attacker)"
        )
        .is_none());

        // Nested lists in NetChirho and SupportIssueChirho parse correctly
        let valid_net_chirho =
            review_label_to_capability_chirho("NetChirho(allowlist=a,b)").unwrap();
        assert_eq!(
            valid_net_chirho,
            CapabilityChirho::NetChirho {
                allowlist_chirho: vec!["a".to_string(), "b".to_string()]
            }
        );

        let valid_support_chirho =
            review_label_to_capability_chirho("SupportIssueChirho(issue=123,actions=read,write)")
                .unwrap();
        assert_eq!(
            valid_support_chirho,
            CapabilityChirho::SupportIssueChirho {
                issue_chirho: "123".to_string(),
                actions_chirho: vec!["read".to_string(), "write".to_string()]
            }
        );
    }

    #[test]
    fn unsupported_review_label_stays_explicitly_unrendered_chirho() {
        assert!(describe_review_capability_label_with_dictionary_chirho(
            "RealtimeSessionChirho(app=demo,caller=owner)"
        )
        .is_none());
        let line_chirho =
            review_capability_power_body_chirho("RealtimeSessionChirho(app=demo,caller=owner)");
        assert!(line_chirho.starts_with("form=(missing)\t"));
    }

    #[test]
    fn email_paid_effect_is_messaging_and_money_chirho() {
        let line_chirho = describe_capability_chirho(&CapabilityChirho::PaidEffectChirho {
            effect_chirho: "send_crm_email_chirho".to_string(),
            caller_chirho: "owner/x".to_string(),
        });
        assert!(line_chirho.sends_messages_chirho);
        assert!(line_chirho.touches_money_chirho);
        assert_eq!(line_chirho.category_chirho, "messaging");
        assert!(line_chirho.plain_chirho.contains("Send messages"));
    }

    #[test]
    fn non_email_paid_effect_is_money_not_messaging_chirho() {
        let line_chirho = describe_capability_chirho(&CapabilityChirho::PaidEffectChirho {
            effect_chirho: "image_generate_chirho".to_string(),
            caller_chirho: "owner/x".to_string(),
        });
        assert!(line_chirho.touches_money_chirho);
        assert!(!line_chirho.sends_messages_chirho);
        assert_eq!(line_chirho.category_chirho, "money");
    }

    #[test]
    fn net_capability_lists_hosts_chirho() {
        let line_chirho = describe_capability_chirho(&CapabilityChirho::NetChirho {
            allowlist_chirho: vec!["api.example.com".to_string()],
        });
        assert!(line_chirho.reaches_network_chirho);
        assert!(line_chirho.plain_chirho.contains("api.example.com"));
    }

    #[test]
    fn secret_ref_never_promises_to_show_value_chirho() {
        let line_chirho = describe_capability_chirho(&CapabilityChirho::SecretRefChirho {
            name_chirho: "stripe_key_chirho".to_string(),
        });
        assert!(line_chirho.plain_chirho.contains("never shown"));
    }

    #[test]
    fn full_summary_sentence_and_flags_chirho() {
        let summary_chirho = summarize_capabilities_chirho(&[
            CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "contact/".to_string(),
            },
            CapabilityChirho::PaidEffectChirho {
                effect_chirho: "send_crm_email_chirho".to_string(),
                caller_chirho: "owner/x".to_string(),
            },
        ]);
        assert_eq!(summary_chirho.capability_count_chirho, 2);
        assert!(!summary_chirho.is_pure_chirho);
        assert!(summary_chirho.can_write_data_chirho);
        assert!(summary_chirho.can_send_messages_chirho);
        assert!(summary_chirho.can_spend_money_chirho);
        assert!(summary_chirho.sentence_chirho.starts_with("This app can: "));
        assert!(summary_chirho
            .sentence_chirho
            .ends_with(" — and nothing else."));
        assert!(summary_chirho
            .sentence_chirho
            .contains("save data under \"contact/\""));
    }
}
