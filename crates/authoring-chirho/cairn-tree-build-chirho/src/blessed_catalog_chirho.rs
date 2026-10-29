// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The published blessed-contract catalog: the small, fixed set of effect doors an app may request.
//! A role card names a contract and pins the catalog entry's canonical BLAKE3 ref, so the checker
//! and emitter fail closed if an app tries to mint or drift impurity. This is the local registry
//! hardening step before the registry records themselves become signed engine objects.

use cairn_undo_plan_chirho::canonical_chirho::reversion_contract_digest_chirho;
use cairn_undo_plan_chirho::contract_chirho::canonical_authoring_reversion_contract_set_chirho;

pub const BLESSED_CARD_SCHEMA_V2_CHIRHO: &str = "blessed-card-v2-chirho";
pub const BLESSED_CONTRACT_REGISTRY_ENTRY_SCHEMA_V2_CHIRHO: &str =
    "blessed-contract-registry-entry-v2-chirho";

/// The synthetic identity a manifest-baked query runs as. A real authenticated query caller (a
/// registered principal with a real client + token) is a future concern; v0 queries run as this
/// fixed source-manifest identity, mirroring the proven contact/perffection query nodes.
const SOURCE_MANIFEST_CLIENT_CHIRHO: &str = "source-manifest-client-chirho";
const SOURCE_MANIFEST_TOKEN_CHIRHO: &str = "source-manifest-token-chirho";

/// The blessed card params a role declares (in `blessed-contract-chirho.toml`). `scope_chirho` is
/// required for every contract; `caller_chirho`/`max_rows_chirho` are required by `query`;
/// `caller_chirho`/`max_tokens_chirho`/`max_price_per_token_chirho` are required by `llm`; and
/// `caller_chirho` is required by `postgres-reversible`. Each contract ignores fields it does not
/// name (e.g. `write-store` uses only `scope_chirho`).
pub struct BlessedCardParamsChirho<'a> {
    pub scope_chirho: &'a str,
    pub caller_chirho: Option<&'a str>,
    pub max_rows_chirho: Option<u64>,
    pub max_tokens_chirho: Option<u64>,
    pub max_price_per_token_chirho: Option<i64>,
}

/// One catalogued blessed effect door: how a role naming it lowers to an engine reify node.
pub struct BlessedContractEntryChirho {
    /// The catalog name an app role binds (e.g. `write-store`, `query`).
    pub contract_chirho: &'static str,
    /// Owner-facing source descriptor used by generation context packs.
    pub owner_what_it_does_chirho: &'static str,
    /// Owner-facing plain power line; skins should not translate this from jargon.
    pub owner_power_chirho: &'static str,
    /// The reify node entry export (the shared inert template's entry).
    pub entry_chirho: &'static str,
    /// Fuel for the reify node (0 — the effect layer, not the wasm, does the work).
    pub fuel_chirho: u64,
    /// The shared inert template path as pinned in the catalog descriptor. Emit lowers blessed
    /// roles to the runtime's `builtin-node-template-chirho` source kind instead of exposing this
    /// path as deploy-time filesystem input.
    pub template_wat_chirho: &'static str,
}

impl BlessedContractEntryChirho {
    pub fn reversion_contract_key_chirho(&self) -> String {
        match self.contract_chirho {
            "template-app-deploy" => "template-app-deploy-chirho".to_string(),
            other_chirho => format!("{other_chirho}-chirho"),
        }
    }

    pub fn reversion_contract_digest_chirho(&self) -> String {
        let key_chirho = self.reversion_contract_key_chirho();
        let set_chirho = canonical_authoring_reversion_contract_set_chirho();
        let contract_chirho = set_chirho
            .contracts_chirho
            .iter()
            .find(|contract_chirho| contract_chirho.contract_key_chirho.0 == key_chirho)
            .expect("every static blessed catalog entry has one canonical reversion contract");
        reversion_contract_digest_chirho(contract_chirho)
            .expect("the static canonical reversion contract is valid")
            .0
    }

    /// Canonical registry bytes for the contract itself. Runtime card params such as scope/caller
    /// are intentionally excluded: the ref pins the blessed door's semantics, not a particular app
    /// placement.
    fn canonical_descriptor_chirho(&self) -> String {
        let reversion_contract_digest_chirho = self.reversion_contract_digest_chirho();
        match self.contract_chirho {
            "read-store" => format!(
                "schema_chirho={BLESSED_CONTRACT_REGISTRY_ENTRY_SCHEMA_V2_CHIRHO}\ncontract_chirho={}\nreversion_contract_digest_chirho={reversion_contract_digest_chirho}\nentry_chirho={}\nfuel_chirho={}\ntemplate_wat_chirho={}\nrequired_params_chirho=scope_chirho\ncapability_template_chirho=read-store:{{scope_chirho}}\n",
                self.contract_chirho,
                self.entry_chirho,
                self.fuel_chirho,
                self.template_wat_chirho
            ),
            "write-store" => format!(
                "schema_chirho={BLESSED_CONTRACT_REGISTRY_ENTRY_SCHEMA_V2_CHIRHO}\ncontract_chirho={}\nreversion_contract_digest_chirho={reversion_contract_digest_chirho}\nentry_chirho={}\nfuel_chirho={}\ntemplate_wat_chirho={}\nrequired_params_chirho=scope_chirho\ncapability_template_chirho=write-store:{{scope_chirho}}\n",
                self.contract_chirho,
                self.entry_chirho,
                self.fuel_chirho,
                self.template_wat_chirho
            ),
            "query" => format!(
                "schema_chirho={BLESSED_CONTRACT_REGISTRY_ENTRY_SCHEMA_V2_CHIRHO}\ncontract_chirho={}\nreversion_contract_digest_chirho={reversion_contract_digest_chirho}\nentry_chirho={}\nfuel_chirho={}\ntemplate_wat_chirho={}\nrequired_params_chirho=scope_chirho,caller_chirho,max_rows_chirho\ncapability_template_chirho=query:{{scope_chirho}}:{{caller_chirho}}:{{max_rows_chirho}}\ncapability_template_chirho=identity:{{caller_chirho}}:{SOURCE_MANIFEST_CLIENT_CHIRHO}:{SOURCE_MANIFEST_TOKEN_CHIRHO}\n",
                self.contract_chirho,
                self.entry_chirho,
                self.fuel_chirho,
                self.template_wat_chirho
            ),
            "template-app-deploy" => format!(
                "schema_chirho={BLESSED_CONTRACT_REGISTRY_ENTRY_SCHEMA_V2_CHIRHO}\ncontract_chirho={}\nreversion_contract_digest_chirho={reversion_contract_digest_chirho}\nentry_chirho={}\nfuel_chirho={}\ntemplate_wat_chirho={}\nrequired_params_chirho=scope_chirho\ncapability_template_chirho=template-app-deploy:{{scope_chirho}}\n",
                self.contract_chirho,
                self.entry_chirho,
                self.fuel_chirho,
                self.template_wat_chirho
            ),
            "llm" => format!(
                "schema_chirho={BLESSED_CONTRACT_REGISTRY_ENTRY_SCHEMA_V2_CHIRHO}\ncontract_chirho={}\nreversion_contract_digest_chirho={reversion_contract_digest_chirho}\nentry_chirho={}\nfuel_chirho={}\ntemplate_wat_chirho={}\nrequired_params_chirho=scope_chirho,caller_chirho,max_tokens_chirho,max_price_per_token_chirho\ncapability_template_chirho=paid:llm_chirho:{{caller_chirho}}\n",
                self.contract_chirho,
                self.entry_chirho,
                self.fuel_chirho,
                self.template_wat_chirho
            ),
            "postgres-reversible" => format!(
                "schema_chirho={BLESSED_CONTRACT_REGISTRY_ENTRY_SCHEMA_V2_CHIRHO}\ncontract_chirho={}\nreversion_contract_digest_chirho={reversion_contract_digest_chirho}\nentry_chirho={}\nfuel_chirho={}\ntemplate_wat_chirho={}\nrequired_params_chirho=scope_chirho,caller_chirho\ncapability_template_chirho=paid:postgres_reversible_chirho:{{caller_chirho}}\n",
                self.contract_chirho,
                self.entry_chirho,
                self.fuel_chirho,
                self.template_wat_chirho
            ),
            other_chirho => format!(
                "schema_chirho={BLESSED_CONTRACT_REGISTRY_ENTRY_SCHEMA_V2_CHIRHO}\ncontract_chirho={other_chirho}\nreversion_contract_digest_chirho={reversion_contract_digest_chirho}\nentry_chirho={}\nfuel_chirho={}\ntemplate_wat_chirho={}\n",
                self.entry_chirho, self.fuel_chirho, self.template_wat_chirho
            ),
        }
    }

    /// Full canonical hex BLAKE3 ref for the blessed contract registry entry.
    pub fn contract_hash_chirho(&self) -> String {
        blake3::hash(self.canonical_descriptor_chirho().as_bytes())
            .to_hex()
            .to_string()
    }

    /// Verify the role card pins this exact catalog entry. Missing or mismatched refs fail closed.
    pub fn verify_contract_hash_chirho(
        &self,
        contract_hash_chirho: Option<&str>,
    ) -> Result<(), String> {
        let expected_chirho = self.contract_hash_chirho();
        let found_chirho = contract_hash_chirho
            .map(str::trim)
            .filter(|hash_chirho| !hash_chirho.is_empty())
            .ok_or_else(|| format!("missing contract_hash_chirho; expected {expected_chirho}"))?;
        if found_chirho != expected_chirho {
            return Err(format!(
                "contract_hash_chirho mismatch: expected {expected_chirho}, found {found_chirho}"
            ));
        }
        Ok(())
    }

    /// The engine capability string(s) this contract grants for the card params. Fails closed if a
    /// required param is missing (so the checker and the emitter reject an incomplete card the same
    /// way). `read-store` grants one store-read cap; `write-store` grants one store-write cap;
    /// `query` grants a metered-read cap plus the paired identity it runs as;
    /// `template-app-deploy` grants one template-deploy cap scoped to
    /// the template id; `llm` grants one paid-llm cap keyed by caller (its `max_tokens_chirho` /
    /// `max_price_per_token_chirho` are required on the card but enforced by the runtime, so they
    /// are not part of the capability string); `postgres-reversible` grants one paid coordinate
    /// whose signed contract fixes reconciliation, pricing, and cache behavior.
    pub fn capabilities_for_card_chirho(
        &self,
        params_chirho: &BlessedCardParamsChirho,
    ) -> Result<Vec<String>, String> {
        let scope_chirho = params_chirho.scope_chirho.trim();
        if scope_chirho.is_empty() {
            return Err("blessed card needs a non-empty scope_chirho".to_string());
        }
        match self.contract_chirho {
            "read-store" => Ok(vec![format!("read-store:{scope_chirho}")]),
            "write-store" => Ok(vec![format!("write-store:{scope_chirho}")]),
            "query" => {
                let caller_chirho = params_chirho
                    .caller_chirho
                    .map(str::trim)
                    .filter(|caller_chirho| !caller_chirho.is_empty())
                    .ok_or_else(|| "query contract needs a non-empty caller_chirho".to_string())?;
                let max_rows_chirho = params_chirho
                    .max_rows_chirho
                    .filter(|max_rows_chirho| *max_rows_chirho > 0)
                    .ok_or_else(|| "query contract needs a positive max_rows_chirho".to_string())?;
                Ok(vec![
                    format!("query:{scope_chirho}:{caller_chirho}:{max_rows_chirho}"),
                    format!(
                        "identity:{caller_chirho}:{SOURCE_MANIFEST_CLIENT_CHIRHO}:{SOURCE_MANIFEST_TOKEN_CHIRHO}"
                    ),
                ])
            }
            "template-app-deploy" => Ok(vec![format!("template-app-deploy:{scope_chirho}")]),
            "llm" => {
                let caller_chirho = params_chirho
                    .caller_chirho
                    .map(str::trim)
                    .filter(|caller_chirho| !caller_chirho.is_empty())
                    .ok_or_else(|| "llm contract needs a non-empty caller_chirho".to_string())?;
                let _max_tokens_chirho = params_chirho
                    .max_tokens_chirho
                    .filter(|max_tokens_chirho| *max_tokens_chirho > 0)
                    .ok_or_else(|| "llm contract needs a positive max_tokens_chirho".to_string())?;
                let _max_price_per_token_chirho = params_chirho
                    .max_price_per_token_chirho
                    .filter(|max_price_per_token_chirho| *max_price_per_token_chirho > 0)
                    .ok_or_else(|| {
                        "llm contract needs a positive max_price_per_token_chirho".to_string()
                    })?;
                Ok(vec![format!("paid:llm_chirho:{caller_chirho}")])
            }
            "postgres-reversible" => {
                let caller_chirho = params_chirho
                    .caller_chirho
                    .map(str::trim)
                    .filter(|caller_chirho| !caller_chirho.is_empty())
                    .ok_or_else(|| {
                        "postgres-reversible contract needs a non-empty caller_chirho".to_string()
                    })?;
                Ok(vec![format!(
                    "paid:postgres_reversible_chirho:{caller_chirho}"
                )])
            }
            other_chirho => Err(format!(
                "contract '{other_chirho}' has no capability lowering"
            )),
        }
    }
}

const CATALOG_CHIRHO: &[BlessedContractEntryChirho] = &[
    BlessedContractEntryChirho {
        contract_chirho: "read-store",
        owner_what_it_does_chirho: "Read current records from one approved app area.",
        owner_power_chirho:
            "This lets the app read only the approved area without granting write authority.",
        entry_chirho: "node_chirho",
        fuel_chirho: 0,
        template_wat_chirho: "../node-template-chirho.wat",
    },
    BlessedContractEntryChirho {
        contract_chirho: "write-store",
        owner_what_it_does_chirho: "Save approved business records for this app.",
        owner_power_chirho:
            "This lets the app save records only inside the approved business area.",
        entry_chirho: "node_chirho",
        fuel_chirho: 0,
        template_wat_chirho: "../node-template-chirho.wat",
    },
    BlessedContractEntryChirho {
        contract_chirho: "query",
        owner_what_it_does_chirho: "Look up a bounded list of saved business records.",
        owner_power_chirho:
            "This lets the app read only the approved business area, with a row limit.",
        entry_chirho: "node_chirho",
        fuel_chirho: 0,
        template_wat_chirho: "../node-template-chirho.wat",
    },
    BlessedContractEntryChirho {
        contract_chirho: "template-app-deploy",
        owner_what_it_does_chirho: "Publish a reviewed app or template package.",
        owner_power_chirho: "This lets the app publish only the reviewed package it was granted.",
        entry_chirho: "node_chirho",
        fuel_chirho: 0,
        template_wat_chirho: "../node-template-chirho.wat",
    },
    BlessedContractEntryChirho {
        contract_chirho: "llm",
        owner_what_it_does_chirho: "Ask a metered writing helper to draft text for review.",
        owner_power_chirho: "This lets the app spend from its approved writing-helper limit.",
        entry_chirho: "node_chirho",
        fuel_chirho: 0,
        template_wat_chirho: "../node-template-chirho.wat",
    },
    BlessedContractEntryChirho {
        contract_chirho: "postgres-reversible",
        owner_what_it_does_chirho:
            "Apply one reviewed, reversible PostgreSQL state transition and meter it once.",
        owner_power_chirho:
            "This lets the app request only the reviewed conditional database transition.",
        entry_chirho: "node_chirho",
        fuel_chirho: 0,
        template_wat_chirho: "../node-template-chirho.wat",
    },
];

pub fn blessed_catalog_entries_chirho() -> &'static [BlessedContractEntryChirho] {
    CATALOG_CHIRHO
}

/// Resolve a blessed contract by its catalog name. `None` = unknown (the checker fails closed).
pub fn lookup_blessed_contract_chirho(
    name_chirho: &str,
) -> Option<&'static BlessedContractEntryChirho> {
    CATALOG_CHIRHO
        .iter()
        .find(|entry_chirho| entry_chirho.contract_chirho == name_chirho)
}

pub fn validate_blessed_card_v2_envelope_chirho(
    schema_chirho: &str,
    intent_chirho: &str,
    parse_error_chirho: Option<&str>,
) -> Result<(), String> {
    if let Some(error_chirho) = parse_error_chirho {
        return Err(error_chirho.to_string());
    }
    if schema_chirho != BLESSED_CARD_SCHEMA_V2_CHIRHO {
        return Err(format!(
            "unsupported blessed card schema '{schema_chirho}'; expected {BLESSED_CARD_SCHEMA_V2_CHIRHO}"
        ));
    }
    if intent_chirho.trim().is_empty() {
        return Err("blessed card v2 needs a non-empty intent_chirho".to_string());
    }
    Ok(())
}

/// Resolve a card's named contract and verify its pinned registry ref.
pub fn resolve_blessed_contract_chirho(
    name_chirho: &str,
    contract_hash_chirho: Option<&str>,
) -> Result<&'static BlessedContractEntryChirho, String> {
    let entry_chirho = lookup_blessed_contract_chirho(name_chirho)
        .ok_or_else(|| format!("unknown blessed contract '{name_chirho}'"))?;
    entry_chirho.verify_contract_hash_chirho(contract_hash_chirho)?;
    Ok(entry_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn params_chirho<'a>(
        scope_chirho: &'a str,
        caller_chirho: Option<&'a str>,
        max_rows_chirho: Option<u64>,
    ) -> BlessedCardParamsChirho<'a> {
        BlessedCardParamsChirho {
            scope_chirho,
            caller_chirho,
            max_rows_chirho,
            max_tokens_chirho: None,
            max_price_per_token_chirho: None,
        }
    }

    /// `llm`-shaped card params: scope + caller + token budget + price-per-token ceiling.
    fn llm_params_chirho<'a>(
        scope_chirho: &'a str,
        caller_chirho: Option<&'a str>,
        max_tokens_chirho: Option<u64>,
        max_price_per_token_chirho: Option<i64>,
    ) -> BlessedCardParamsChirho<'a> {
        BlessedCardParamsChirho {
            scope_chirho,
            caller_chirho,
            max_rows_chirho: None,
            max_tokens_chirho,
            max_price_per_token_chirho,
        }
    }

    #[test]
    fn write_store_grants_one_cap_chirho() {
        let entry_chirho = lookup_blessed_contract_chirho("write-store").unwrap();
        assert_eq!(
            entry_chirho
                .capabilities_for_card_chirho(&params_chirho("orders-chirho", None, None))
                .unwrap(),
            vec!["write-store:orders-chirho".to_string()]
        );
        assert_eq!(entry_chirho.fuel_chirho, 0);
    }

    #[test]
    fn read_store_grants_one_read_only_cap_chirho() {
        let entry_chirho = lookup_blessed_contract_chirho("read-store").unwrap();
        assert_eq!(
            entry_chirho
                .capabilities_for_card_chirho(&params_chirho("viewer-state-chirho/", None, None,))
                .unwrap(),
            vec!["read-store:viewer-state-chirho/".to_string()]
        );
        assert_eq!(entry_chirho.fuel_chirho, 0);
    }

    #[test]
    fn query_grants_query_plus_identity_chirho() {
        let entry_chirho = lookup_blessed_contract_chirho("query").unwrap();
        let caps_chirho = entry_chirho
            .capabilities_for_card_chirho(&params_chirho(
                "orders-chirho",
                Some("order-query-caller"),
                Some(50),
            ))
            .unwrap();
        assert_eq!(
            caps_chirho,
            vec![
                "query:orders-chirho:order-query-caller:50".to_string(),
                "identity:order-query-caller:source-manifest-client-chirho:source-manifest-token-chirho"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn query_fails_closed_on_incomplete_card_chirho() {
        let entry_chirho = lookup_blessed_contract_chirho("query").unwrap();
        assert!(entry_chirho
            .capabilities_for_card_chirho(&params_chirho("orders-chirho", None, Some(50)))
            .is_err());
        assert!(entry_chirho
            .capabilities_for_card_chirho(&params_chirho("orders-chirho", Some("c"), None))
            .is_err());
        assert!(entry_chirho
            .capabilities_for_card_chirho(&params_chirho("orders-chirho", Some("c"), Some(0)))
            .is_err());
    }

    #[test]
    fn template_app_deploy_grants_one_cap_chirho() {
        let entry_chirho = lookup_blessed_contract_chirho("template-app-deploy").unwrap();
        assert_eq!(
            entry_chirho
                .capabilities_for_card_chirho(&params_chirho("blog-template-chirho", None, None))
                .unwrap(),
            vec!["template-app-deploy:blog-template-chirho".to_string()]
        );
        assert_eq!(entry_chirho.fuel_chirho, 0);
    }

    #[test]
    fn template_app_deploy_fails_closed_on_empty_scope_chirho() {
        let entry_chirho = lookup_blessed_contract_chirho("template-app-deploy").unwrap();
        assert!(entry_chirho
            .capabilities_for_card_chirho(&params_chirho("   ", None, None))
            .is_err());
    }

    #[test]
    fn llm_grants_paid_llm_cap_chirho() {
        let entry_chirho = lookup_blessed_contract_chirho("llm").unwrap();
        let caps_chirho = entry_chirho
            .capabilities_for_card_chirho(&llm_params_chirho(
                "summarize-chirho",
                Some("summary-caller-chirho"),
                Some(4096),
                Some(2),
            ))
            .unwrap();
        // max_tokens / max_price are required on the card but NOT in the capability string.
        assert_eq!(
            caps_chirho,
            vec!["paid:llm_chirho:summary-caller-chirho".to_string()]
        );
        assert_eq!(entry_chirho.fuel_chirho, 0);
    }

    #[test]
    fn llm_fails_closed_on_incomplete_card_chirho() {
        let entry_chirho = lookup_blessed_contract_chirho("llm").unwrap();
        // empty scope
        assert!(entry_chirho
            .capabilities_for_card_chirho(&llm_params_chirho("  ", Some("c"), Some(10), Some(2)))
            .is_err());
        // missing caller
        assert!(entry_chirho
            .capabilities_for_card_chirho(&llm_params_chirho(
                "summarize-chirho",
                None,
                Some(10),
                Some(2)
            ))
            .is_err());
        // missing max_tokens
        assert!(entry_chirho
            .capabilities_for_card_chirho(&llm_params_chirho(
                "summarize-chirho",
                Some("c"),
                None,
                Some(2)
            ))
            .is_err());
        // zero max_tokens
        assert!(entry_chirho
            .capabilities_for_card_chirho(&llm_params_chirho(
                "summarize-chirho",
                Some("c"),
                Some(0),
                Some(2)
            ))
            .is_err());
        // missing max_price_per_token
        assert!(entry_chirho
            .capabilities_for_card_chirho(&llm_params_chirho(
                "summarize-chirho",
                Some("c"),
                Some(10),
                None
            ))
            .is_err());
        // non-positive max_price_per_token
        assert!(entry_chirho
            .capabilities_for_card_chirho(&llm_params_chirho(
                "summarize-chirho",
                Some("c"),
                Some(10),
                Some(0)
            ))
            .is_err());
        assert!(entry_chirho
            .capabilities_for_card_chirho(&llm_params_chirho(
                "summarize-chirho",
                Some("c"),
                Some(10),
                Some(-5)
            ))
            .is_err());
    }

    #[test]
    fn empty_scope_and_unknown_contract_fail_closed_chirho() {
        let entry_chirho = lookup_blessed_contract_chirho("write-store").unwrap();
        assert!(entry_chirho
            .capabilities_for_card_chirho(&params_chirho("   ", None, None))
            .is_err());
        assert!(lookup_blessed_contract_chirho("rm-rf").is_none());
        assert!(lookup_blessed_contract_chirho("").is_none());
    }

    #[test]
    fn catalog_hashes_are_stable_chirho() {
        assert_eq!(
            lookup_blessed_contract_chirho("write-store")
                .unwrap()
                .contract_hash_chirho(),
            "614d12abeb18b308dd4ad0c9d4464d5d9112dc6efef2af2e3ee14e86d692b735"
        );
        assert_eq!(
            lookup_blessed_contract_chirho("query")
                .unwrap()
                .contract_hash_chirho(),
            "cf4c4c06d5e5918b71cbb19cc18f2fa4d2925a3eddbbbc0adf7a7cfddbc71158"
        );
        assert_eq!(
            lookup_blessed_contract_chirho("template-app-deploy")
                .unwrap()
                .contract_hash_chirho(),
            "6df0d0a4c8a1dc0002e9e6b69809b8350065aec6bac17d22b6ae8365ae861ce4"
        );
        assert_eq!(
            lookup_blessed_contract_chirho("llm")
                .unwrap()
                .contract_hash_chirho(),
            "ef3cb8e43acc061f5d76196060ecd6eeaf7921d312fc00577e5eea15297b8742"
        );
        assert_eq!(
            lookup_blessed_contract_chirho("postgres-reversible")
                .unwrap()
                .contract_hash_chirho(),
            "cbc5fa7bf6c7ee7b6399d8673d3f3e5e60e27dd54851c7dc998b47a0687790c2"
        );
    }

    #[test]
    fn contract_hash_must_match_catalog_entry_chirho() {
        let entry_chirho = lookup_blessed_contract_chirho("write-store").unwrap();
        let hash_chirho = entry_chirho.contract_hash_chirho();
        assert!(entry_chirho
            .verify_contract_hash_chirho(Some(&hash_chirho))
            .is_ok());
        assert!(entry_chirho.verify_contract_hash_chirho(None).is_err());
        assert!(entry_chirho
            .verify_contract_hash_chirho(Some("not-the-contract-hash"))
            .is_err());
        assert!(resolve_blessed_contract_chirho("rm-rf", Some(&hash_chirho)).is_err());
    }

    #[test]
    fn postgres_reversible_grants_only_the_fixed_paid_coordinate_chirho() {
        let entry_chirho = lookup_blessed_contract_chirho("postgres-reversible").unwrap();
        assert_eq!(
            entry_chirho
                .capabilities_for_card_chirho(&params_chirho(
                    "customer-profile-update-chirho",
                    Some("verified-app-caller-chirho"),
                    None,
                ))
                .unwrap(),
            vec!["paid:postgres_reversible_chirho:verified-app-caller-chirho".to_string()]
        );
        assert!(entry_chirho
            .capabilities_for_card_chirho(&params_chirho(
                "customer-profile-update-chirho",
                None,
                None,
            ))
            .is_err());
    }
}
