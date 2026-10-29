// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The AI app-builder's pure node implementations: render the JS-free "describe your app" landing
//! form, build the bounded LLM request from the business description, strict-validate the model's
//! completion into vetted deploy params (fail closed on bad output), and render the "your app is
//! live" result page. Effects happen only through the dag's two blessed doors (the LLM and the
//! template-deploy), never here — these are pure transforms over their inputs.

pub mod build_llm_request_chirho;
pub mod render_build_result_chirho;
pub mod render_form_chirho;
pub mod validate_build_params_chirho;
