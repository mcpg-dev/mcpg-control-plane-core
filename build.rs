//! Build script: compile the Agent gRPC contract from
//! `proto/mcpg/cp/v1/agent.proto` into Rust types via tonic-build.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = "proto";
    let proto_files = ["proto/mcpg/cp/v1/agent.proto"];

    for f in &proto_files {
        println!("cargo:rerun-if-changed={f}");
    }

    let mut includes = vec![PathBuf::from(proto_dir)];

    // A build system that supplies its own `protoc` wins over the vendored
    // binary. `protoc_bin_vendored` self-locates via `CARGO_MANIFEST_DIR`,
    // which is only meaningful under cargo; a sandboxed build resolves it to a
    // directory that no longer exists when the script runs. Well-known types
    // are built into protoc, so an externally supplied one needs no extra
    // include path. Otherwise: vendored protoc + its WKT include dir, so the
    // build works without system libprotobuf-dev.
    println!("cargo:rerun-if-env-changed=PROTOC");
    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()
            .expect("protoc-bin-vendored: could not locate binary");
        let wkt_include = protoc_bin_vendored::include_path()
            .expect("protoc-bin-vendored: could not locate include path");
        // SAFETY: build scripts are single-threaded at this point.
        unsafe { std::env::set_var("PROTOC", protoc) };
        includes.push(wkt_include);
    }

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&proto_files, &includes)?;

    Ok(())
}
