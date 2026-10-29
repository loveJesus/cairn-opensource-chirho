// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16 (KJV)

#[derive(Debug, Default, PartialEq, Eq)]
pub struct WorkspaceStatePageV1Chirho {
    pub workspace_name_chirho: Option<String>,
    pub current_version_chirho: Option<u64>,
    pub unavailable_chirho: bool,
}
