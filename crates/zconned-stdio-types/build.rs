use std::{env, path::PathBuf};

/// Locate an executable on PATH (PROTOC may be a bare name).
fn which(name: &PathBuf) -> Option<PathBuf> {
    let name = name.to_str()?;
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // This assumes protobuf files are under a directory called `protos`
    // and in a protobuf package `mypackage`

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("protos");
    let material_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../zconned-material/protos");
    let proto_files = vec![root.join("frame.proto")];

    // The well-known-types include dir is not auto-resolved by protoc
    // once -I flags are passed. Derive it from the protoc location
    // (works for both the Nix store layout and the FHS convention:
    // <prefix>/bin/protoc -> <prefix>/include), falling back to
    // PROTOC_INCLUDE.
    let protoc = std::env::var("PROTOC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("protoc"));
    let protoc_abs = if protoc.is_absolute() {
        protoc.clone()
    } else {
        which(&protoc).unwrap_or(protoc.clone())
    };
    // Resolve symlinks: e.g. the NixOS profile puts protoc under
    // /run/current-system/sw/bin, while its include dir lives in the
    // store package the symlink points into.
    let protoc_abs = protoc_abs.canonicalize().unwrap_or(protoc_abs);
    let protoc_include = std::env::var("PROTOC_INCLUDE")
        .map(PathBuf::from)
        .ok()
        .filter(|p| p.join("google/protobuf/timestamp.proto").exists())
        .or_else(|| {
            protoc_abs
                .parent()
                .and_then(|bin| bin.parent())
                .map(|prefix| prefix.join("include"))
                .filter(|p| p.join("google/protobuf/timestamp.proto").exists())
        });
    let mut includes = vec![root.clone(), material_root.clone()];
    if let Some(wkt) = &protoc_include {
        includes.push(wkt.clone());
    }

    // Tell cargo to recompile if any of these proto files are changed
    for proto_file in &proto_files {
        println!("cargo:rerun-if-changed={}", proto_file.display());
    }

    let descriptor_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("proto_descriptor.bin");

    prost_build::Config::new()
        // Save descriptors to file
        .file_descriptor_set_path(&descriptor_path)
        // Override prost-types with pbjson-types
        .compile_well_known_types()
        .extern_path(".google.protobuf", "::pbjson_types")
        // material types are generated (and serde-mapped) in the
        // zconned-material crate; map the package there (orphan-safe:
        // the serde impls stay in their own crate).
        .extern_path(".zconn.zconned.material", "::zconned_material")
        // Generate prost structs
        .compile_protos(&proto_files, &includes)?;

    let descriptor_set = std::fs::read(descriptor_path)?;
    pbjson_build::Builder::new()
        .register_descriptors(&descriptor_set)?
        .extern_path(".zconn.zconned.material", "::zconned_material")
        .extern_path(".google.protobuf", "::pbjson_types")
        .build(&[".zconn.zconned.frame"])?;

    Ok(())
}
