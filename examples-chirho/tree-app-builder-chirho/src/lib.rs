// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The AI app-builder example — cairn's most intricate app: an EFFECTFUL dag that turns a business
//! description into a deployed landing app. This crate holds the app's three PURE node
//! implementations (build the LLM request, validate the model's params, render the result) and the
//! value types that cross the dag's ports; the two blessed effect doors (the bounded LLM and the
//! vetted template-deploy) are the dag's, not this crate's — app code can request impurity, never
//! mint it.

pub mod implementations_chirho;
pub mod types_chirho;
