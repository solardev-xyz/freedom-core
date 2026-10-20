//! The freedom-ipfs build this binary links, for `ipfs.hello`'s
//! `freedom_ipfs` (design 0007, "Methods").
//!
//! Upstream item 6 (build info as a library function) isn't done yet, and
//! the add-on's `buildInfoJson` reports nulls (0007, upstream item 6). The
//! service reports what it pins instead: the version and commit of the
//! freedom-ipfs crates in `Cargo.lock`, which a test holds to these
//! constants.

/// The freedom-ipfs release the pinned commit carries.
pub const FREEDOM_IPFS_VERSION: &str = "0.4.6";
/// The pinned commit, on freedom-ipfs's `integration/rust-core`.
pub const FREEDOM_IPFS_COMMIT: &str = "b5485ee8434a4389075e5d851bd6b87637b79afc";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every freedom-ipfs crate in the lockfile: (name, version, source).
    fn locked() -> Vec<(String, String, String)> {
        let lock = include_str!("../Cargo.lock");
        let mut found = Vec::new();
        for package in lock.split("[[package]]") {
            let field = |key: &str| {
                package.lines().find_map(|line| {
                    line.strip_prefix(key)
                        .and_then(|rest| rest.strip_prefix(" = \""))
                        .and_then(|rest| rest.strip_suffix('"'))
                        .map(str::to_owned)
                })
            };
            if let (Some(name), Some(version)) = (field("name"), field("version"))
                && name.starts_with("freedom-ipfs-")
            {
                found.push((name, version, field("source").unwrap_or_default()));
            }
        }
        found
    }

    #[test]
    fn the_constants_are_the_lockfiles_pin() {
        let locked = locked();
        assert!(
            locked
                .iter()
                .any(|(name, _, _)| name == "freedom-ipfs-gateway"),
            "{locked:?}"
        );
        let source = format!(
            "git+https://github.com/solardev-xyz/freedom-ipfs?rev={FREEDOM_IPFS_COMMIT}#{FREEDOM_IPFS_COMMIT}"
        );
        for (name, version, locked_source) in &locked {
            assert_eq!(version, FREEDOM_IPFS_VERSION, "{name}");
            assert_eq!(locked_source, &source, "{name}");
        }
    }

    #[test]
    fn the_manifest_pins_the_same_commit() {
        let manifest = include_str!("../Cargo.toml");
        let pins: Vec<&str> = manifest
            .lines()
            .filter(|line| line.starts_with("freedom-ipfs-"))
            .collect();
        assert!(!pins.is_empty());
        for pin in pins {
            assert!(
                pin.contains(&format!("rev = \"{FREEDOM_IPFS_COMMIT}\"")),
                "{pin}"
            );
        }
    }
}
