// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Pure render: turn the persisted order records (read back through the blessed query door) into an
//! htmx order-list partial. A dine-in order carries no PII, so the list shows the real order details
//! (table + items + status); item names came from the world, so they are escaped via the shared kit.

use crate::types_chirho::order_v1_chirho::OrderRecordV1Chirho;
use cairn_node_templating_chirho::{escape_html_chirho, HtmlPartialV1Chirho};

pub fn render_order_list_chirho(orders_chirho: &[OrderRecordV1Chirho]) -> HtmlPartialV1Chirho {
    if orders_chirho.is_empty() {
        return HtmlPartialV1Chirho::new_chirho(
            "<section data-order-list-chirho=\"empty\"><p>No orders yet.</p></section>",
        );
    }
    let mut body_chirho = String::from("<section data-order-list-chirho=\"ready\"><ul>");
    for order_chirho in orders_chirho {
        let items_chirho = order_chirho
            .items_chirho
            .iter()
            .map(|line_chirho| {
                format!(
                    "{}&times;{}",
                    line_chirho.qty_chirho,
                    escape_html_chirho(&line_chirho.name_chirho)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        body_chirho.push_str(&format!(
            "<li data-order-row-chirho=\"{status}\">table {table}: {items} <em>({status})</em></li>",
            status = escape_html_chirho(&order_chirho.status_chirho),
            table = order_chirho.table_chirho,
            items = items_chirho,
        ));
    }
    body_chirho.push_str("</ul></section>");
    HtmlPartialV1Chirho::new_chirho(body_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::types_chirho::order_v1_chirho::{OrderLineV1Chirho, ORDER_RECORD_SCHEMA_CHIRHO};

    fn order_chirho(table_chirho: u32, name_chirho: &str, qty_chirho: u32) -> OrderRecordV1Chirho {
        OrderRecordV1Chirho {
            schema_chirho: ORDER_RECORD_SCHEMA_CHIRHO.to_string(),
            status_chirho: "received".to_string(),
            order_ref_chirho: "ref".to_string(),
            table_chirho,
            items_chirho: vec![OrderLineV1Chirho {
                name_chirho: name_chirho.to_string(),
                qty_chirho,
            }],
            detail_chirho: None,
        }
    }

    #[test]
    fn empty_list_is_kind_chirho() {
        let html_chirho = render_order_list_chirho(&[]).html_chirho;
        assert!(html_chirho.contains("data-order-list-chirho=\"empty\""));
        assert!(html_chirho.contains("No orders yet"));
    }

    #[test]
    fn lists_orders_with_table_and_items_chirho() {
        let html_chirho = render_order_list_chirho(&[
            order_chirho(7, "Margherita", 2),
            order_chirho(3, "Diavola", 1),
        ])
        .html_chirho;
        assert!(html_chirho.contains("data-order-list-chirho=\"ready\""));
        assert!(html_chirho.contains("table 7: 2&times;Margherita"));
        assert!(html_chirho.contains("table 3: 1&times;Diavola"));
    }

    #[test]
    fn escapes_untrusted_item_names_chirho() {
        let html_chirho = render_order_list_chirho(&[order_chirho(1, "<script>", 1)]).html_chirho;
        assert!(!html_chirho.contains("<script>"));
        assert!(html_chirho.contains("&lt;script&gt;"));
    }
}
