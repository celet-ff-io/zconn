use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("protos");
    let proto_files = vec![
        root.join("mail_spk_opk.proto"),
        root.join("mail.proto"),
        root.join("relay.proto"),
    ];

    // Tell cargo to recompile if any of these proto files are changed
    for proto_file in &proto_files {
        println!("cargo:rerun-if-changed={}", proto_file.display());
    }

    tonic_prost_build::configure().compile_protos(&proto_files, &[root])?;

    Ok(())
}
