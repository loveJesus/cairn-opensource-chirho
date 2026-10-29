// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Pure order validation: turn an untrusted `OrderFormV1Chirho` into a durable `OrderRecordV1Chirho`,
//! either accepted or kindly rejected. No effects and no I/O — the only Rust a human writes for this
//! role. The boundary guest wraps the returned record in a scoped WriteStore request; the blessed
//! `save_order` reify node performs the actual signed write.

use crate::types_chirho::order_v1_chirho::{
    OrderFormV1Chirho, OrderLineV1Chirho, OrderRecordV1Chirho, ORDER_RECORD_SCHEMA_CHIRHO,
};

const MAX_TABLE_CHIRHO: u32 = 200;
const MAX_QTY_PER_LINE_CHIRHO: u32 = 50;
const MAX_LINES_CHIRHO: usize = 40;

/// Validate `form` and build the durable record under `order_ref_chirho`. Always returns a record:
/// invalid input yields status "rejected" with a kind reason rather than an error, so every
/// submission is logged honestly under the orders namespace (nothing silently disappears).
pub fn validate_order_chirho(
    form_chirho: &OrderFormV1Chirho,
    order_ref_chirho: &str,
) -> OrderRecordV1Chirho {
    if let Err(reason_chirho) = check_order_chirho(form_chirho) {
        return OrderRecordV1Chirho {
            schema_chirho: ORDER_RECORD_SCHEMA_CHIRHO.to_string(),
            status_chirho: "rejected".to_string(),
            order_ref_chirho: order_ref_chirho.to_string(),
            table_chirho: form_chirho.table_chirho,
            items_chirho: form_chirho.items_chirho.clone(),
            detail_chirho: Some(reason_chirho),
        };
    }
    let items_chirho = form_chirho
        .items_chirho
        .iter()
        .map(|line_chirho| OrderLineV1Chirho {
            name_chirho: line_chirho.name_chirho.trim().to_string(),
            qty_chirho: line_chirho.qty_chirho,
        })
        .collect();
    OrderRecordV1Chirho {
        schema_chirho: ORDER_RECORD_SCHEMA_CHIRHO.to_string(),
        status_chirho: "received".to_string(),
        order_ref_chirho: order_ref_chirho.to_string(),
        table_chirho: form_chirho.table_chirho,
        items_chirho,
        detail_chirho: None,
    }
}

fn check_order_chirho(form_chirho: &OrderFormV1Chirho) -> Result<(), String> {
    if form_chirho.table_chirho == 0 || form_chirho.table_chirho > MAX_TABLE_CHIRHO {
        return Err(format!(
            "please choose a table between 1 and {MAX_TABLE_CHIRHO}"
        ));
    }
    if form_chirho.items_chirho.is_empty() {
        return Err("please add at least one item to your order".to_string());
    }
    if form_chirho.items_chirho.len() > MAX_LINES_CHIRHO {
        return Err(format!(
            "that is more than {MAX_LINES_CHIRHO} lines — please split the order"
        ));
    }
    for line_chirho in &form_chirho.items_chirho {
        if line_chirho.name_chirho.trim().is_empty() {
            return Err("one of the items has no name".to_string());
        }
        if line_chirho.qty_chirho == 0 || line_chirho.qty_chirho > MAX_QTY_PER_LINE_CHIRHO {
            return Err(format!(
                "quantity for '{}' must be between 1 and {MAX_QTY_PER_LINE_CHIRHO}",
                line_chirho.name_chirho.trim()
            ));
        }
    }
    Ok(())
}

/// FNV-1a (64-bit) hex of `bytes` — a stable, dependency-free content key for the order. Identical
/// submissions collapse to one stone (idempotent); different orders get different keys. v0 keys on
/// the raw request bytes; a production order would mint a per-submission nonce via a logged clock or
/// counter so two genuinely distinct identical orders stay distinct.
pub fn order_ref_chirho(bytes_chirho: &[u8]) -> String {
    let mut hash_chirho: u64 = 0xcbf2_9ce4_8422_2325;
    for byte_chirho in bytes_chirho {
        hash_chirho ^= u64::from(*byte_chirho);
        hash_chirho = hash_chirho.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash_chirho:016x}")
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn line_chirho(name_chirho: &str, qty_chirho: u32) -> OrderLineV1Chirho {
        OrderLineV1Chirho {
            name_chirho: name_chirho.to_string(),
            qty_chirho,
        }
    }

    #[test]
    fn accepts_a_good_order_chirho() {
        let form_chirho = OrderFormV1Chirho {
            table_chirho: 5,
            items_chirho: vec![line_chirho(" Margherita ", 2), line_chirho("Diavola", 1)],
        };
        let record_chirho = validate_order_chirho(&form_chirho, "abc");
        assert_eq!(record_chirho.status_chirho, "received");
        assert_eq!(record_chirho.table_chirho, 5);
        // names are trimmed into the durable record
        assert_eq!(record_chirho.items_chirho[0].name_chirho, "Margherita");
        assert!(record_chirho.detail_chirho.is_none());
    }

    #[test]
    fn rejects_an_empty_order_chirho() {
        let form_chirho = OrderFormV1Chirho {
            table_chirho: 5,
            items_chirho: vec![],
        };
        let record_chirho = validate_order_chirho(&form_chirho, "abc");
        assert_eq!(record_chirho.status_chirho, "rejected");
        assert!(record_chirho.detail_chirho.is_some());
    }

    #[test]
    fn rejects_a_bad_table_chirho() {
        let form_chirho = OrderFormV1Chirho {
            table_chirho: 0,
            items_chirho: vec![line_chirho("Margherita", 1)],
        };
        assert_eq!(
            validate_order_chirho(&form_chirho, "abc").status_chirho,
            "rejected"
        );
    }

    #[test]
    fn rejects_a_bad_quantity_chirho() {
        let form_chirho = OrderFormV1Chirho {
            table_chirho: 3,
            items_chirho: vec![line_chirho("Margherita", 0)],
        };
        assert_eq!(
            validate_order_chirho(&form_chirho, "abc").status_chirho,
            "rejected"
        );
    }

    #[test]
    fn order_ref_is_stable_and_distinct_chirho() {
        assert_eq!(order_ref_chirho(b"same"), order_ref_chirho(b"same"));
        assert_ne!(order_ref_chirho(b"one"), order_ref_chirho(b"two"));
        assert_eq!(order_ref_chirho(b"same").len(), 16);
    }
}
