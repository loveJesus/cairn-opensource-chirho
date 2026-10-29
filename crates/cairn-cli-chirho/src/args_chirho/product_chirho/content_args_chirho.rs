// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Grouped clap argument payloads for `content_args_chirho`.

#[derive(clap::Args)]
pub struct OnboardingSetArgsChirho {
    pub app_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "title")]
    pub title_chirho: String,
    #[arg(long = "step")]
    pub steps_chirho: Vec<String>,
}
