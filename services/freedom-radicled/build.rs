//! Refuses the `testhooks` feature (src/testhooks.rs) outside the debug and
//! test builds the tests use: Cargo's `PROFILE` must be `debug` (a profile
//! that inherits `dev`, as `test` does), and this package unoptimized. A
//! release-profile build is refused whatever its settings, debug assertions
//! included, which a `cfg(debug_assertions)` check would let through
//! (`--config profile.release.debug-assertions=true`). CI checks both.

// A build script speaks to Cargo on stdout.
#![allow(clippy::print_stdout)]

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_FEATURE_TESTHOOKS").is_none() {
        return;
    }
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let opt_level = std::env::var("OPT_LEVEL").unwrap_or_default();
    if profile != "debug" || opt_level != "0" {
        println!(
            "cargo::error=the `testhooks` feature is for debug and test builds only, never a release build (profile {profile}, opt-level {opt_level})"
        );
    }
}
