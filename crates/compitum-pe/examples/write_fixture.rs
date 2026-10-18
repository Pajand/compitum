//! Writes synthetic PE fixtures to disk.
//!
//! Exists so the CLI can be exercised against real files on a real machine without needing a
//! Windows installation to source binaries from. The images are structurally valid PE32+
//! files — a real parser reads them the same way it would read a genuine binary — but they
//! contain no genuine program, which is exactly what is wanted for a classification test.
//!
//! Usage:
//!
//! ```text
//! cargo run --release -p compitum-pe --example write_fixture -- <output-dir>
//! ```
//!
//! Writes one file per ABI family plus a variant with scalable-vector instructions in its
//! code section, so that the instruction scanner can be demonstrated too.

use std::path::PathBuf;

use compitum_pe::fixture::{
    machine, subsystem, synthetic, synthetic_advanced, synthetic_with_code,
};

fn main() {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("fixtures"));

    if let Err(error) = std::fs::create_dir_all(&dir) {
        eprintln!("cannot create {}: {error}", dir.display());
        std::process::exit(1);
    }

    // One image per ABI family, all console subsystem so that headless classification is
    // exercised, and all without graphics imports so the basic path is unambiguous.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "native-arm64.exe",
            synthetic(machine::ARM64, subsystem::CONSOLE, false),
        ),
        (
            "hybrid-arm64ec.exe",
            synthetic(machine::ARM64EC, subsystem::CONSOLE, false),
        ),
        (
            "fat-arm64x.exe",
            synthetic(machine::ARM64X, subsystem::CONSOLE, false),
        ),
        (
            "legacy-x86_64.exe",
            synthetic(machine::AMD64, subsystem::CONSOLE, false),
        ),
        (
            "legacy-x86.exe",
            synthetic(machine::I386, subsystem::CONSOLE, false),
        ),
        (
            "gui-arm64.exe",
            synthetic(machine::ARM64, subsystem::GUI, false),
        ),
        (
            "graphics-arm64.exe",
            synthetic_advanced(
                machine::ARM64,
                subsystem::GUI,
                false,
                &["kernel32.dll", "d3d12.dll", "dxgi.dll"],
                0x1000,
                false,
                0,
            ),
        ),
        (
            "managed-dotnet.exe",
            synthetic_advanced(
                machine::I386,
                subsystem::CONSOLE,
                false,
                &[],
                0x1000,
                true,
                0,
            ),
        ),
        (
            // A 16 KiB page-size image: the shape a host migrating to larger pages will see.
            "page16k-arm64.exe",
            synthetic_advanced(
                machine::ARM64,
                subsystem::CONSOLE,
                false,
                &[],
                0x4000,
                false,
                0,
            ),
        ),
    ];

    let mut written = 0usize;
    for (name, bytes) in cases {
        let path = dir.join(name);
        match std::fs::write(&path, &bytes) {
            Ok(()) => {
                println!("{} ({} bytes)", path.display(), bytes.len());
                written += 1;
            }
            Err(error) => eprintln!("cannot write {}: {error}", path.display()),
        }
    }

    // An image whose code contains a scalable-vector opcode, so that instruction scanning has
    // something to find. The bytes are a plausible SVE encoding, not a functioning program.
    let sve_code: Vec<u8> = {
        let mut code = vec![0u8; 64];
        code[8..12].copy_from_slice(&0x0420_0002u32.to_le_bytes());
        code[16..20].copy_from_slice(&0xC0C0_0000u32.to_le_bytes()); // SME outer product
        code
    };
    let path = dir.join("needs-sve-sme.exe");
    match std::fs::write(
        &path,
        synthetic_with_code(machine::ARM64, &sve_code, 0x1000),
    ) {
        Ok(()) => {
            println!(
                "{} (with scalable-vector and matrix opcodes)",
                path.display()
            );
            written += 1;
        }
        Err(error) => eprintln!("cannot write {}: {error}", path.display()),
    }

    println!("\n{written} fixture(s) written to {}", dir.display());
}
