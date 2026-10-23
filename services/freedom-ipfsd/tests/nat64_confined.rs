//! NAT64 discovery's link-local resolvers, confined with the service's own
//! policy (`src/confinement.rs`, included as it is): a named zone
//! (`fe80::1%lo`) is still looked up, through `SIOCGIFINDEX`, the one
//! `ioctl` the policy adds; a numeric zone needs no lookup; a name the
//! kernel doesn't know stays unaskable. Without the rule, the control, a
//! named zone is unaskable: so the rule is what the lookup needs (design
//! 0010).
//!
//! Each case runs in a child of its own (this binary again, with
//! `NAT64_CONFINED_CASE` set), which confines itself once, as the service
//! does, then reads a fixture resolver file the policy grants.
//!
//! Linux; elsewhere it does nothing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    dead_code
)]

#[path = "../src/confinement.rs"]
mod confinement;

const CASE: &str = "NAT64_CONFINED_CASE";
const FIXTURE: &str = "NAT64_CONFINED_FIXTURE";

fn main() {
    if let Ok(case) = std::env::var(CASE) {
        child(&case);
        return;
    }
    parent();
}

#[cfg(target_os = "linux")]
fn child(case: &str) {
    use fc_service::confine;
    use fc_service::network::NetworkPolicy;

    let _ = confine::clean_entry();
    let fixture = std::path::PathBuf::from(std::env::var(FIXTURE).unwrap());
    // The ephemeral process's policy: nothing writable, the lock absent.
    let mut policy = confinement::policy(Vec::new(), &NetworkPolicy::Direct, Vec::new());
    policy.read_only.push(fixture.clone());
    if case == "named-without-rule" {
        policy.interface_index = false;
    }
    confine::confine(&policy).unwrap();
    let learned =
        fc_nat64::resolvers::from_files(&[&fixture], fc_nat64::resolvers::interface_index);
    println!("LEARNED {learned:?}");
}

#[cfg(not(target_os = "linux"))]
fn child(_case: &str) {}

/// What the child confined as `case` learned from a resolver file listing
/// `nameserver`.
fn run(case: &str, nameserver: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let fixture = dir.path().join("resolv.conf");
    std::fs::write(&fixture, format!("nameserver {nameserver}\n")).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .env(CASE, case)
        .env(FIXTURE, &fixture)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{case}: {:?} {text}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    text.lines()
        .find_map(|line| line.strip_prefix("LEARNED "))
        .unwrap_or_else(|| panic!("{case}: {text}"))
        .to_owned()
}

fn parent() {
    #[cfg(target_os = "linux")]
    {
        use fc_nat64::resolvers::Learned;
        let ask = |scope: u32| {
            format!(
                "{:?}",
                vec![Learned::Ask(std::net::SocketAddr::V6(
                    std::net::SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, scope)
                ))]
            )
        };
        let unaskable = |text: &str| format!("{:?}", vec![Learned::Unaskable(text.into())]);
        // Unconfined, the kernel's answer for `lo`.
        let lo = fc_nat64::resolvers::interface_index("lo").expect("lo's index");
        assert_eq!(run("named", "fe80::1%lo"), ask(lo), "a named zone");
        assert_eq!(run("numeric", "fe80::1%1"), ask(1), "a numeric zone");
        assert_eq!(
            run("unknown", "fe80::1%nosuch0"),
            unaskable("fe80::1%nosuch0"),
            "a name the kernel doesn't know"
        );
        // The control: without the rule, the lookup is refused.
        assert_eq!(
            run("named-without-rule", "fe80::1%lo"),
            unaskable("fe80::1%lo"),
            "a named zone without SIOCGIFINDEX"
        );
        println!("nat64_confined: named zones resolve confined, through SIOCGIFINDEX alone");
    }
}
