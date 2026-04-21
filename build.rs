use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.githooks/pre-commit");
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        return;
    }

    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"),
    );

    let hook = manifest_dir.join(".githooks").join("pre-commit");
    if !hook.is_file() {
        println!("cargo:warning=.githooks/pre-commit missing; skipping git hook setup");
        return;
    }

    let ok = Command::new("git")
        .current_dir(&manifest_dir)
        .args(["config", "core.hooksPath", ".githooks"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !ok {
        println!("cargo:warning=could not run `git config core.hooksPath .githooks` (git missing or not a checkout?)");
    }
}
