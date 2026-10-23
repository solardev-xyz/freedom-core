//! No TLS roots on disk (design 0010, "What each service needs"): the
//! service's TLS stack, if any, has its roots built in (`webpki-roots`), so
//! confinement grants no certificate store. This fails if the lockfile
//! gains a crate that reads the OS's.

#![allow(clippy::panic)]

/// Crates that read the OS's certificate store, or link a TLS library that
/// does.
const OS_ROOTS: &[&str] = &[
    "native-tls",
    "openssl",
    "openssl-probe",
    "openssl-sys",
    "rustls-native-certs",
    "rustls-platform-verifier",
    "schannel",
    "security-framework",
];

#[test]
fn the_lockfile_reads_no_os_certificate_store() {
    let lock = include_str!("../Cargo.lock");
    for name in OS_ROOTS {
        assert!(
            !lock.contains(&format!("name = \"{name}\"\n")),
            "{name} reads TLS roots from disk, which confinement doesn't grant"
        );
    }
}

#[test]
fn the_tls_roots_are_built_in() {
    let lock = include_str!("../Cargo.lock");
    assert!(lock.contains("name = \"webpki-roots\"\n"));
}
