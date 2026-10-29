// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure pricebook policy and proposal helpers.

use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
pub use cairn_model_economic_chirho::billing_contract_chirho::validate_app_name_chirho;
use cairn_model_economic_chirho::{PriceBookChirho, PriceSourceChirho, ResolvedPriceChirho};
use std::collections::BTreeMap;

pub fn propose_price_book_chirho(
    app_chirho: &str,
    owner_principal_chirho: &str,
    price_per_request_chirho: Option<i64>,
    effect_prices_chirho: BTreeMap<String, i64>,
    external_markup_bps_chirho: i64,
    previous_chirho: Option<HashChirho>,
    at_ms_chirho: u64,
) -> Result<PriceBookChirho> {
    let book_chirho = PriceBookChirho {
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: owner_principal_chirho.to_string(),
        price_per_request_chirho,
        effect_prices_chirho,
        external_markup_bps_chirho,
        previous_chirho,
        at_ms_chirho,
    };
    validate_price_book_chirho(&book_chirho)?;
    Ok(book_chirho)
}

pub fn resolve_price_from_book_chirho(
    price_book_hash_chirho: HashChirho,
    book_chirho: &PriceBookChirho,
    effect_chirho: &str,
) -> Result<ResolvedPriceChirho> {
    validate_price_book_chirho(book_chirho)?;
    if let Some(price_chirho) = book_chirho.effect_prices_chirho.get(effect_chirho).copied() {
        return Ok(ResolvedPriceChirho {
            app_chirho: book_chirho.app_chirho.clone(),
            effect_chirho: effect_chirho.to_string(),
            price_chirho,
            price_book_chirho: price_book_hash_chirho,
            source_chirho: PriceSourceChirho::EffectChirho,
        });
    }
    if let Some(price_chirho) = book_chirho.price_per_request_chirho {
        return Ok(ResolvedPriceChirho {
            app_chirho: book_chirho.app_chirho.clone(),
            effect_chirho: effect_chirho.to_string(),
            price_chirho,
            price_book_chirho: price_book_hash_chirho,
            source_chirho: PriceSourceChirho::RequestChirho,
        });
    }
    bail!(
        "price book for app '{}' has no price for effect '{effect_chirho}'",
        book_chirho.app_chirho
    )
}

pub fn validate_price_book_chirho(book_chirho: &PriceBookChirho) -> Result<()> {
    validate_app_name_chirho(&book_chirho.app_chirho)?;
    if book_chirho.owner_principal_chirho.trim().is_empty() {
        bail!("owner_principal_chirho is required");
    }
    if book_chirho.price_per_request_chirho.is_none() && book_chirho.effect_prices_chirho.is_empty()
    {
        bail!("price book needs price_per_request_chirho or at least one effect price");
    }
    if let Some(price_chirho) = book_chirho.price_per_request_chirho {
        if price_chirho <= 0 {
            bail!("price_per_request_chirho must be positive");
        }
    }
    for (effect_chirho, price_chirho) in &book_chirho.effect_prices_chirho {
        if effect_chirho.trim().is_empty() {
            bail!("effect price key must not be empty");
        }
        if *price_chirho <= 0 {
            bail!("effect price for '{effect_chirho}' must be positive");
        }
    }
    if book_chirho.external_markup_bps_chirho < 0 {
        bail!("external_markup_bps_chirho must be non-negative");
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn proposed_price_book_preserves_previous_and_validates_chirho() {
        let previous_chirho = Some(HashChirho("a".repeat(64)));
        let book_chirho = propose_price_book_chirho(
            "pricedapp",
            "owner/test",
            Some(25),
            BTreeMap::new(),
            150,
            previous_chirho.clone(),
            1234,
        )
        .unwrap();

        assert_eq!(book_chirho.app_chirho, "pricedapp");
        assert_eq!(book_chirho.owner_principal_chirho, "owner/test");
        assert_eq!(book_chirho.previous_chirho, previous_chirho);
        assert_eq!(book_chirho.external_markup_bps_chirho, 150);

        let error_chirho = propose_price_book_chirho(
            "bad app",
            "owner/test",
            Some(25),
            BTreeMap::new(),
            0,
            None,
            0,
        )
        .unwrap_err()
        .to_string();
        assert!(error_chirho.contains("slashes or whitespace"));
    }

    #[test]
    fn resolve_price_prefers_effect_price_then_request_price_chirho() {
        let mut effect_prices_chirho = BTreeMap::new();
        effect_prices_chirho.insert("llm_chirho".to_string(), 41);
        let book_chirho = propose_price_book_chirho(
            "pricedapp",
            "owner/test",
            Some(13),
            effect_prices_chirho,
            0,
            None,
            1,
        )
        .unwrap();

        let hash_chirho = HashChirho("b".repeat(64));
        let effect_price_chirho =
            resolve_price_from_book_chirho(hash_chirho.clone(), &book_chirho, "llm_chirho")
                .unwrap();
        assert_eq!(effect_price_chirho.price_chirho, 41);
        assert_eq!(
            effect_price_chirho.source_chirho,
            PriceSourceChirho::EffectChirho
        );

        let request_price_chirho =
            resolve_price_from_book_chirho(hash_chirho, &book_chirho, "email_chirho").unwrap();
        assert_eq!(request_price_chirho.price_chirho, 13);
        assert_eq!(
            request_price_chirho.source_chirho,
            PriceSourceChirho::RequestChirho
        );
    }
}
