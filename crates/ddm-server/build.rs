fn main() {
    // rust-embed fails to compile if the folder is missing; on fresh
    // checkouts web/dist doesn't exist until `npm run build` has run.
    // Create an empty dir so the binary still builds (UI then serves
    // nothing unless web_dir points at a real directory).
    let dist = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/dist");
    if !dist.exists() {
        std::fs::create_dir_all(&dist).expect("create web/dist");
    }
}
