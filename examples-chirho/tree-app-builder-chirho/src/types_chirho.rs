// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Value types for the AI app-builder example (the shapes that cross the build dag's ports): the
//! incoming HTTP request, the bounded LLM request/completion, the vetted landing params the model
//! produces, and the deploy request/response that drive and report the blessed template-deploy door.

pub mod app_params_landing_v1_chirho;
pub mod deploy_request_v1_chirho;
pub mod deploy_response_v1_chirho;
pub mod http_request_v1_chirho;
pub mod llm_completion_v1_chirho;
pub mod llm_request_v1_chirho;
