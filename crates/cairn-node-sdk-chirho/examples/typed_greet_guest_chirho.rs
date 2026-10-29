// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};
use std::string::String;

#[derive(Deserialize)]
struct GreetInputChirho {
    name_chirho: String,
}

#[derive(Serialize)]
struct GreetOutputChirho {
    message_chirho: String,
}

fn greet_impl_chirho(input_chirho: GreetInputChirho) -> GreetOutputChirho {
    GreetOutputChirho {
        message_chirho: format!("Hello, {}", input_chirho.name_chirho),
    }
}

cairn_node_sdk_chirho::export_json_node_chirho!(
    greet_chirho,
    GreetInputChirho,
    GreetOutputChirho,
    greet_impl_chirho
);
