// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Pure render: turn the durable `OrderRecordV1Chirho` into a warm htmx confirmation partial. This
//! is the HTML trust boundary, so every value drawn from the (untrusted) order is escaped via the
//! shared kit before it is embedded — item names came from the world.

use crate::types_chirho::order_v1_chirho::OrderRecordV1Chirho;
use cairn_node_templating_chirho::{escape_html_chirho, HtmlPartialV1Chirho};

pub fn render_confirmation_chirho(record_chirho: &OrderRecordV1Chirho) -> HtmlPartialV1Chirho {
    if record_chirho.status_chirho == "received" {
        let lines_chirho: String = record_chirho
            .items_chirho
            .iter()
            .map(|line_chirho| {
                format!(
                    "<li>{} &times; {}</li>",
                    line_chirho.qty_chirho,
                    escape_html_chirho(&line_chirho.name_chirho)
                )
            })
            .collect();
        HtmlPartialV1Chirho::new_chirho(format!(
            "<section data-order-chirho=\"received\">\
<h2>Order received &mdash; table {table}</h2>\
<ul>{lines}</ul>\
<p>Grazie! Rosa is firing up the oven. (ref {order_ref})</p>\
</section>",
            table = record_chirho.table_chirho,
            lines = lines_chirho,
            order_ref = escape_html_chirho(&record_chirho.order_ref_chirho),
        ))
    } else {
        let detail_chirho = record_chirho
            .detail_chirho
            .as_deref()
            .unwrap_or("we could not read your order");
        HtmlPartialV1Chirho::new_chirho(format!(
            "<section data-order-chirho=\"rejected\"><p>Sorry &mdash; {}.</p></section>",
            escape_html_chirho(detail_chirho)
        ))
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::types_chirho::order_v1_chirho::{OrderLineV1Chirho, ORDER_RECORD_SCHEMA_CHIRHO};

    #[test]
    fn renders_a_received_order_chirho() {
        let record_chirho = OrderRecordV1Chirho {
            schema_chirho: ORDER_RECORD_SCHEMA_CHIRHO.to_string(),
            status_chirho: "received".to_string(),
            order_ref_chirho: "deadbeef".to_string(),
            table_chirho: 7,
            items_chirho: vec![OrderLineV1Chirho {
                name_chirho: "Margherita".to_string(),
                qty_chirho: 2,
            }],
            detail_chirho: None,
        };
        let html_chirho = render_confirmation_chirho(&record_chirho).html_chirho;
        assert!(html_chirho.contains("Order received"));
        assert!(html_chirho.contains("table 7"));
        assert!(html_chirho.contains("2 &times; Margherita"));
    }

    #[test]
    fn escapes_untrusted_item_names_chirho() {
        let record_chirho = OrderRecordV1Chirho {
            schema_chirho: ORDER_RECORD_SCHEMA_CHIRHO.to_string(),
            status_chirho: "received".to_string(),
            order_ref_chirho: "ref".to_string(),
            table_chirho: 1,
            items_chirho: vec![OrderLineV1Chirho {
                name_chirho: "<script>".to_string(),
                qty_chirho: 1,
            }],
            detail_chirho: None,
        };
        let html_chirho = render_confirmation_chirho(&record_chirho).html_chirho;
        assert!(!html_chirho.contains("<script>"));
        assert!(html_chirho.contains("&lt;script&gt;"));
    }

    #[test]
    fn renders_a_rejected_order_kindly_chirho() {
        let record_chirho = OrderRecordV1Chirho {
            schema_chirho: ORDER_RECORD_SCHEMA_CHIRHO.to_string(),
            status_chirho: "rejected".to_string(),
            order_ref_chirho: "ref".to_string(),
            table_chirho: 0,
            items_chirho: vec![],
            detail_chirho: Some("please add at least one item to your order".to_string()),
        };
        let html_chirho = render_confirmation_chirho(&record_chirho).html_chirho;
        assert!(html_chirho.contains("Sorry"));
        assert!(html_chirho.contains("please add at least one item"));
    }
}
