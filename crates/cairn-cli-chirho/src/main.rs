// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! cairn-chirho CLI binary — parse arguments, dispatch into the library, stay tiny.

fn main() -> anyhow::Result<()> {
    cairn_cli_chirho::dispatch_chirho::run_chirho()
}
