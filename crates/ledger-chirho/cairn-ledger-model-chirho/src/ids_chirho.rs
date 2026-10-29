// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Typed identity newtypes for the real ledger record — distinct types so a money core can never
//! mix a digest for a channel id or a cluster id for a transfer id (frozen §11, Brick 2.1).

use crate::LogIdChirho;
use serde::{Deserialize, Serialize};

/// A hex BLAKE3 digest — the content-address of a record's signed line, a policy record, a cut, or a
/// finality proof. A distinct type so digests are never confused with free-form strings.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DigestChirho(pub String);

/// The per-CLUSTER journal identity — the L1 packing unit (frozen §11.0). Many accounts share one
/// cluster journal; the account identity ([`LogIdChirho`]) is orthogonal to its cluster.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClusterIdChirho(pub String);

/// A cross-cluster transfer's stable identity (F3 — carried in the counterpart claim so the two
/// per-cluster legs of one logical transfer can be correlated).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransferIdChirho(pub String);

/// The STABLE asset-kind identity (R5b two-concept law, gpt #4468): the name an account is keyed by.
/// It survives policy revision — revising a kind's policy record NEVER moves or strands balances.
/// Per-kind conservation (R5a) keys by THIS, never by the versioned policy digest. Distinct from
/// [`AssetKindRefChirho`] (a policy REVISION ref); admission binds the two:
/// `resolve(kind_policy_ref).kind_id == account.kind_id` (a registry act, enforced at B).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AssetKindIdChirho(pub String);

impl From<String> for AssetKindIdChirho {
    fn from(value_chirho: String) -> Self {
        Self(value_chirho)
    }
}

impl From<&str> for AssetKindIdChirho {
    fn from(value_chirho: &str) -> Self {
        Self(value_chirho.to_owned())
    }
}

/// A content-ref to ONE immutable asset-kind policy REVISION record (frozen §11.7) — the digest of
/// the policy under which a leg was admitted. NOT the account's kind identity (that is the stable
/// [`AssetKindIdChirho`]): a policy revision changes this digest but never the kind id, so balances
/// keyed by kind id are never stranded by a revision (R5b).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AssetKindRefChirho(pub DigestChirho);

/// A cross-cluster settlement lane (F3 — one component of a nullifier's binding).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SettlementChannelIdChirho(pub String);

/// A money trust-root grouping — the anchor under which a source burn's finality proof is verified
/// at the destination (F3 self-verifying finality: source-key trust, never saga trust).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MoneyGroupIdChirho(pub String);

/// An account reference. An account IS its `(owner, kind)` log identity, so `AccountIdChirho` is
/// exactly [`LogIdChirho`] — one type for the account, reused (never a second parallel id).
pub type AccountIdChirho = LogIdChirho;
