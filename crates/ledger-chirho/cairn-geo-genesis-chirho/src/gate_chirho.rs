// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The four product hard gates, false by type (section 3.2). Each gate enum has exactly one
//! `ClosedChirho` variant — there is no `OpenChirho` in V1 — so an open gate is not a value a caller
//! can construct or a byte string that can parse. This is stronger than serializing four booleans and
//! hoping they are false; opening a product gate is a different schema and an explicit L.J. approval.

use serde::{Deserialize, Serialize};

/// Production money movement gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionMoneyGateChirho {
    ClosedChirho,
}

/// Public self-serve signup gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicSignupGateChirho {
    ClosedChirho,
}

/// Public inbound webhook ingress gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicWebhookGateChirho {
    ClosedChirho,
}

/// Production real-user email delivery gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionRealUserEmailGateChirho {
    ClosedChirho,
}

/// All four product gates reasserted closed at the authority intent. Every field's type admits only
/// `ClosedChirho`, so an open gate cannot appear in the plan or the acceptance packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoProductHardGatesClosedV1Chirho {
    pub production_money_chirho: ProductionMoneyGateChirho,
    pub public_signup_chirho: PublicSignupGateChirho,
    pub public_webhook_chirho: PublicWebhookGateChirho,
    pub production_real_user_email_chirho: ProductionRealUserEmailGateChirho,
}

impl GeoProductHardGatesClosedV1Chirho {
    /// The only inhabitant: all four gates closed. There is no constructor that yields an open gate.
    pub fn all_closed_chirho() -> Self {
        Self {
            production_money_chirho: ProductionMoneyGateChirho::ClosedChirho,
            public_signup_chirho: PublicSignupGateChirho::ClosedChirho,
            public_webhook_chirho: PublicWebhookGateChirho::ClosedChirho,
            production_real_user_email_chirho: ProductionRealUserEmailGateChirho::ClosedChirho,
        }
    }
}
