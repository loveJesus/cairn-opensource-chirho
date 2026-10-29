// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

/// One item on the menu (a price in whole cents, kept exact).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MenuItemV1Chirho {
    pub name_chirho: String,
    pub price_cents_chirho: u32,
}

/// The menu Rosa edits — a pinned input stone, not code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MenuV1Chirho {
    pub items_chirho: Vec<MenuItemV1Chirho>,
}
