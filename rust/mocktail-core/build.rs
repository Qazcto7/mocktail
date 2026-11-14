use std::env;
use std::path::Path;
use std::process::Command;

fn emit_search_dirs(raw: &str) {
    for part in raw.split([';', ':']) {
        let trimmed = part.trim();
        if !trimmed.is_empty() && Path::new(trimmed).is_dir() {
            println!("cargo:rustc-link-search=native={trimmed}");
        }
    }
}

fn main() {
    for var in [
        "MOCKTAIL_DEFAULT_COMPATIBILITY_MANIFEST",
        "MOCKTAIL_DEFAULT_SIGNING_TRUST_MANIFEST",
        "MOCKTAIL_DEFAULT_DOWNLOAD_SOURCES_MANIFEST",
        "MOCKTAIL_CAPSTONE_LIB_DIRS",
        "MOCKTAIL_OPENSSL_LIB_DIRS",
        "PKG_CONFIG_PATH",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }

    if let Ok(dirs) = env::var("MOCKTAIL_CAPSTONE_LIB_DIRS") {
        emit_search_dirs(&dirs);
    } else if let Ok(output) = Command::new("pkg-config")
        .args(["--libs-only-L", "capstone"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for flag in stdout.split_whitespace() {
                if let Some(dir) = flag.strip_prefix("-L") {
                    if !dir.is_empty() && Path::new(dir).is_dir() {
                        println!("cargo:rustc-link-search=native={dir}");
                    }
                }
            }
        }
    }

    if let Ok(dirs) = env::var("MOCKTAIL_OPENSSL_LIB_DIRS") {
        emit_search_dirs(&dirs);
    }

    println!("cargo:rustc-link-lib=capstone");
    println!("cargo:rustc-link-lib=crypto");
}
