// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Small, composable HTML components with escaping built in, styled by the cairn UI CSS. Building
//! blocks for app pages (buttons, inputs, fields, cards, alerts, a top bar) so authors compose safe,
//! consistent UI instead of hand-writing markup per app.

use crate::escape_chirho::{escape_attr_chirho, escape_html_chirho};

/// Severity of an [`alert_chirho`].
pub enum AlertKindChirho {
    OkChirho,
    ErrChirho,
    InfoChirho,
}

/// A submit button. `primary_chirho` styles it as the main call to action.
pub fn button_chirho(label_chirho: &str, primary_chirho: bool) -> String {
    let class_chirho = if primary_chirho {
        "btn-chirho btn-primary-chirho"
    } else {
        "btn-chirho"
    };
    format!(
        "<button class=\"{class_chirho}\" type=\"submit\">{}</button>",
        escape_html_chirho(label_chirho)
    )
}

/// A link styled as a button.
pub fn link_button_chirho(href_chirho: &str, label_chirho: &str) -> String {
    format!(
        "<a class=\"btn-chirho\" href=\"{}\">{}</a>",
        escape_attr_chirho(href_chirho),
        escape_html_chirho(label_chirho)
    )
}

/// A single-line text input. `kind_chirho` is the HTML input type (text/email/password/...).
pub fn text_input_chirho(
    name_chirho: &str,
    kind_chirho: &str,
    placeholder_chirho: &str,
    required_chirho: bool,
) -> String {
    format!(
        "<input class=\"input-chirho\" name=\"{}\" type=\"{}\" placeholder=\"{}\"{}>",
        escape_attr_chirho(name_chirho),
        escape_attr_chirho(kind_chirho),
        escape_attr_chirho(placeholder_chirho),
        if required_chirho { " required" } else { "" }
    )
}

/// A multi-line text input.
pub fn textarea_chirho(
    name_chirho: &str,
    placeholder_chirho: &str,
    required_chirho: bool,
) -> String {
    format!(
        "<textarea class=\"input-chirho\" name=\"{}\" placeholder=\"{}\"{}></textarea>",
        escape_attr_chirho(name_chirho),
        escape_attr_chirho(placeholder_chirho),
        if required_chirho { " required" } else { "" }
    )
}

/// A labelled form field wrapping a control (e.g. the output of [`text_input_chirho`]).
pub fn field_chirho(label_chirho: &str, control_html_chirho: &str) -> String {
    format!(
        "<label class=\"field-chirho\"><span class=\"label-chirho\">{}</span>{control_html_chirho}</label>",
        escape_html_chirho(label_chirho)
    )
}

/// A surface card wrapping arbitrary (trusted) inner markup.
pub fn card_chirho(inner_html_chirho: &str) -> String {
    format!("<div class=\"card-chirho\">{inner_html_chirho}</div>")
}

/// A coloured alert/notice. The message is escaped.
pub fn alert_chirho(kind_chirho: AlertKindChirho, message_chirho: &str) -> String {
    let class_chirho = match kind_chirho {
        AlertKindChirho::OkChirho => "alert-ok-chirho",
        AlertKindChirho::ErrChirho => "alert-err-chirho",
        AlertKindChirho::InfoChirho => "alert-info-chirho",
    };
    format!(
        "<div class=\"alert-chirho {class_chirho}\">{}</div>",
        escape_html_chirho(message_chirho)
    )
}

/// A page top bar: a brand on the left, trusted nav markup on the right.
pub fn topbar_chirho(brand_chirho: &str, right_html_chirho: &str) -> String {
    format!(
        "<header class=\"topbar-chirho\"><div class=\"topbar-inner-chirho\">\
<span class=\"brand-chirho\">{}</span><nav class=\"row-chirho\">{right_html_chirho}</nav>\
</div></header>",
        escape_html_chirho(brand_chirho)
    )
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn alert_escapes_message_chirho() {
        let html_chirho = alert_chirho(AlertKindChirho::ErrChirho, "<script>x</script>");
        assert!(html_chirho.contains("&lt;script&gt;"));
        assert!(!html_chirho.contains("<script>"));
        assert!(html_chirho.contains("alert-err-chirho"));
    }

    #[test]
    fn primary_button_renders_label_chirho() {
        let html_chirho = button_chirho("Save", true);
        assert!(html_chirho.contains("btn-primary-chirho"));
        assert!(html_chirho.contains("Save"));
    }

    #[test]
    fn input_attributes_are_escaped_chirho() {
        let html_chirho = text_input_chirho("email", "email", "you@example.com", true);
        assert!(html_chirho.contains("name=\"email\""));
        assert!(html_chirho.contains("type=\"email\""));
        assert!(html_chirho.contains(" required"));
    }
}
