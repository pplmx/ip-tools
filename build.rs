use husky_rs::{hooks_dir, should_skip_installation};

fn main() {
    // Re-run when hooks change
    println!("cargo:rerun-if-changed=.husky");

    if should_skip_installation() {
        println!("cargo:warning=husky: hooks installation skipped (NO_HUSKY_HOOKS=1)");
        return;
    }

    let hooks_path = hooks_dir(".");

    // Ensure .husky directory exists
    if !hooks_path.exists() {
        println!("cargo:warning=husky: .husky directory not found, skipping");
        return;
    }

    // Make all files in .husky executable (Unix-like systems)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for entry in std::fs::read_dir(&hooks_path).expect("failed to read .husky directory") {
            let entry = entry.expect("failed to read directory entry");
            let path = entry.path();
            if path.is_file() {
                let mut perms = std::fs::metadata(&path).expect("failed to read metadata").permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&path, perms).expect("failed to set permissions");
            }
        }
    }

    // Set core.hooksPath to .husky
    // NOTE: This must be done via git config at build time.
    // The husky-rs build script normally does this, but since we're using
    // [build-dependencies], we need to set it ourselves.
    let git_dir = std::path::Path::new(".git");
    if git_dir.exists() {
        let status = std::process::Command::new("git")
            .args(["config", "core.hooksPath", ".husky"])
            .status();
        match status {
            Ok(s) if s.success() => {
                println!("cargo:warning=husky: hooks installed at .husky");
            }
            _ => {
                println!("cargo:warning=husky: failed to set core.hooksPath (non-fatal)");
            }
        }
    }
}
