//! The crate's one unsafe call (AGENTS.md rule 6). `unsafe_code` is `deny`
//! here, not `forbid`, so that `main`'s call to
//! `libradicle::isolate_git_config` can carry its own `#[allow]`. This holds
//! the crate to that one call: no other line of its Rust sources, outside a
//! comment, names the lint, so no other item, module or statement lifts it,
//! and the one that does is that call's statement.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

/// The lint's name, built here so that this file's code doesn't name it.
fn lint() -> String {
    ["unsafe", "code"].join("_")
}

/// The `.rs` files under `dir`, recursively.
fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// A line that isn't only a comment.
fn code(line: &str) -> bool {
    !line.trim_start().starts_with("//")
}

#[test]
fn one_statement_lifts_the_lint() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let denied = format!("{} = \"deny\"", lint());
    assert_eq!(
        manifest
            .lines()
            .filter(|line| line.starts_with(&format!("{} ", lint())))
            .collect::<Vec<_>>(),
        [denied.as_str()],
        "Cargo.toml's [lints.rust] must hold the lint at deny"
    );

    let mut files = vec![root.join("build.rs")];
    sources(&root.join("src"), &mut files);
    sources(&root.join("tests"), &mut files);
    let mut lifts = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        let lines: Vec<&str> = text.lines().filter(|line| code(line)).collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains(&lint()) {
                let relative = file.strip_prefix(root).unwrap().to_owned();
                let next = lines.get(i + 1).map(|next| next.trim().to_owned());
                lifts.push((relative, line.trim().to_owned(), next));
            }
        }
    }
    assert_eq!(
        lifts,
        [(
            Path::new("src").join("main.rs"),
            format!("#[allow({})]", lint()),
            Some("let isolated = unsafe { libradicle::isolate_git_config() };".to_owned()),
        )],
        "only main's call to isolate_git_config may lift the lint"
    );
}
