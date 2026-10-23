//! The libradicle build this binary links, for `rad.hello`'s `libradicle`
//! (design 0008, "Methods"): the version and commit of the crate in
//! `Cargo.lock`, which a test holds to these constants.

/// The libradicle release the pinned commit is.
pub const LIBRADICLE_VERSION: &str = "0.8.0";
/// The pinned commit: v0.8.0, the release freedom-browser pins.
pub const LIBRADICLE_COMMIT: &str = "e5b137e429cecabd0d0b45c2b5f36f2917853eab";

#[cfg(test)]
mod tests {
    use super::*;

    /// The lockfile's packages named `name`: (version, source).
    fn locked(name: &str) -> Vec<(String, String)> {
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
            if field("name").as_deref() == Some(name)
                && let Some(version) = field("version")
            {
                found.push((version, field("source").unwrap_or_default()));
            }
        }
        found
    }

    #[test]
    fn the_constants_are_the_lockfiles_pin() {
        assert_eq!(
            locked("libradicle"),
            [(
                LIBRADICLE_VERSION.to_owned(),
                format!(
                    "git+https://github.com/solardev-xyz/libradicle?rev={LIBRADICLE_COMMIT}#{LIBRADICLE_COMMIT}"
                )
            )]
        );
    }

    #[test]
    fn the_manifest_pins_the_same_commit() {
        let manifest = include_str!("../Cargo.toml");
        assert!(manifest.contains(&format!(
            "libradicle = {{ git = \"https://github.com/solardev-xyz/libradicle\", rev = \"{LIBRADICLE_COMMIT}\""
        )));
    }
}
