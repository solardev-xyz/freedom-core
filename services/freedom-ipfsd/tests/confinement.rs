//! Confinement through the binary (design 0010, Tests): what `ipfs.hello`
//! reports, what the process holds at the confinement point, and what it
//! can't do once confined, from each kind of thread it has.
//!
//! The thread kinds a test hook reaches are the main thread, a runtime
//! worker and a blocking-pool thread. fc-service's own (logging's writer,
//! the connection's reader, writer, stdin and lifecycle threads, the
//! watchdogs) start after confinement by construction: the confinement
//! point is checked to have one thread.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{Value, json};

/// The kernel's Landlock ABI, if it has Landlock (Linux).
fn landlock_abi() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        fc_sys::linux::landlock_abi().ok().map(|abi| abi.min(9))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The log lines of `stderr` with message `msg`.
fn logged(stderr: &str, msg: &str) -> Vec<Value> {
    stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|line| line["msg"] == msg)
        .collect()
}

#[test]
fn hello_reports_the_policy_and_the_confinement_the_kernel_offers() {
    let dirs = Dirs::new();
    let mut ipfsd = Ipfsd::persistent(&dirs, &[]);
    let hello = ipfsd.hello();
    let result = &hello["result"];
    assert_eq!(result["network"], json!({ "mode": "direct" }), "{hello}");
    let confinement = &result["confinement"];
    match landlock_abi() {
        Some(abi) if cfg!(target_os = "linux") => {
            // The ABI the kernel offers, or CI fails: no silent downgrade.
            assert_eq!(
                confinement["mechanism"],
                format!("landlock-{abi}+seccomp"),
                "{confinement}"
            );
            assert_eq!(confinement["files"], "enforced", "{confinement}");
            assert_eq!(confinement["exec"], "enforced", "{confinement}");
            assert_eq!(confinement["network"], "none", "{confinement}");
            // freedom-ipfs-net resolves through the C library.
            assert!(
                matches!(
                    confinement["resolution"].as_str(),
                    Some("system" | "files_only")
                ),
                "{confinement}"
            );
        }
        _ => assert!(confinement.is_object(), "{confinement}"),
    }
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));

    // An ephemeral process under `socks5`: the policy as passed, and TCP to
    // the proxy's port alone from ABI 4.
    let mut ipfsd = Ipfsd::ephemeral_on("socks5:127.0.0.1:9150", &[]);
    let hello = ipfsd.hello();
    let result = &hello["result"];
    assert_eq!(
        result["network"],
        json!({ "mode": "socks5", "ip": "127.0.0.1", "port": 9150 }),
        "{hello}"
    );
    if let Some(abi) = landlock_abi().filter(|_| cfg!(target_os = "linux")) {
        let expected = if abi >= 4 { "enforced" } else { "unavailable" };
        assert_eq!(result["confinement"]["network"], expected, "{hello}");
    }
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
}

/// At the confinement point the process has one thread, and holds stdio
/// and its lock: the ephemeral process, stdio alone.
#[cfg(all(feature = "testhooks", target_os = "linux"))]
#[test]
fn at_the_confinement_point_one_thread_holds_stdio_and_the_lock() {
    let point = [("FREEDOM_IPFSD_TEST_CONFINEMENT_POINT", "1")];
    let dirs = Dirs::new();
    let mut ipfsd = Ipfsd::persistent(&dirs, &point);
    ipfsd.hello();
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    let stderr = ipfsd.stderr();
    let points = logged(&stderr, "confinement point");
    assert_eq!(points.len(), 1, "{stderr}");
    assert_eq!(points[0]["threads"], 1, "{stderr}");
    let descriptors = points[0]["descriptors"].as_array().unwrap();
    assert!(
        descriptors.len() == 1 && descriptors[0].as_str().unwrap().ends_with(".lock"),
        "{stderr}"
    );

    let mut ipfsd = Ipfsd::ephemeral(&point);
    ipfsd.hello();
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    let stderr = ipfsd.stderr();
    let points = logged(&stderr, "confinement point");
    assert_eq!(points.len(), 1, "{stderr}");
    assert_eq!(points[0]["threads"], 1, "{stderr}");
    assert_eq!(points[0]["descriptors"], json!([]), "{stderr}");
}

/// Once confined, no thread kind the hook reaches reads a file outside the
/// grant, no program runs, and under `socks5` TCP reaches only the proxy's
/// port: the kernel refuses, whatever the service's own gate would do.
#[cfg(all(feature = "testhooks", target_os = "linux"))]
#[test]
fn once_confined_no_thread_reads_outside_and_nothing_runs() {
    let Some(abi) = landlock_abi() else {
        return;
    };
    let dirs = Dirs::new();
    // A sibling of the data directory: outside every grant.
    let canary = dirs.data.with_file_name("canary");
    std::fs::create_dir_all(canary.parent().unwrap()).unwrap();
    std::fs::write(&canary, b"canary").unwrap();
    let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let other_port = other.local_addr().unwrap().port().to_string();
    let env = [
        ("FREEDOM_IPFSD_TEST_CANARY", canary.to_str().unwrap()),
        ("FREEDOM_IPFSD_TEST_EXEC", "1"),
        ("FREEDOM_IPFSD_TEST_CONNECT", other_port.as_str()),
    ];
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut ipfsd = Ipfsd::persistent_on(&dirs, &socks5(proxy.local_addr().unwrap()), &env);
    ipfsd.hello();
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    let stderr = ipfsd.stderr();
    let canaries = logged(&stderr, "canary");
    let threads: Vec<&str> = canaries
        .iter()
        .map(|line| line["thread"].as_str().unwrap())
        .collect();
    assert_eq!(
        threads.len(),
        3,
        "main, a runtime worker and a blocking-pool thread: {stderr}"
    );
    for line in &canaries {
        assert_eq!(line["read"], false, "{line}");
    }
    assert_eq!(logged(&stderr, "exec probe")[0]["ran"], false, "{stderr}");
    if abi >= 4 {
        assert_eq!(
            logged(&stderr, "connect probe")[0]["connected"],
            false,
            "{stderr}"
        );
    }
    assert_eq!(std::fs::read(&canary).unwrap(), b"canary");

    // The control: unconfined by `direct`'s network, the same port connects.
    let mut ipfsd = Ipfsd::ephemeral(&[("FREEDOM_IPFSD_TEST_CONNECT", other_port.as_str())]);
    ipfsd.hello();
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    let stderr = ipfsd.stderr();
    assert_eq!(
        logged(&stderr, "connect probe")[0]["connected"],
        true,
        "{stderr}"
    );
}

/// A descriptor inherited at spawn: one re-exec drops it, and the service
/// starts. With the marker already the process's own, it is refused:
/// exit 77, before `ipfs.hello`, its kind logged.
#[cfg(target_os = "linux")]
#[test]
fn an_inherited_descriptor_is_dropped_by_one_re_exec_or_refused() {
    // A shell holds /dev/null on descriptor 3 without close-on-exec, then
    // execs the service, which keeps it.
    let spawn = |script: &str| {
        let mut command = std::process::Command::new("/bin/sh");
        command.arg("-c").arg(script).arg(BIN).args([
            "serve",
            "--ephemeral",
            "--network",
            "direct",
        ]);
        Ipfsd::spawn(command, &[])
    };
    let mut ipfsd = spawn(r#"exec 3</dev/null; exec "$0" "$@""#);
    assert_eq!(ipfsd.hello()["result"]["kind"], "ephemeral");
    ipfsd.shutdown();
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(0));
    let stderr = ipfsd.stderr();
    assert_eq!(
        logged(
            &stderr,
            "re-executed once at entry: descriptors were inherited"
        )
        .len(),
        1,
        "{stderr}"
    );

    let mut ipfsd = spawn(r#"export FREEDOM_SERVICE_REEXEC=$$; exec 3</dev/null; exec "$0" "$@""#);
    assert_eq!(ipfsd.exit_code(EXIT_TIMEOUT), Some(77));
    let stderr = ipfsd.stderr();
    let refused = logged(&stderr, "confinement refused the process");
    assert_eq!(refused.len(), 1, "{stderr}");
    let reason = refused[0]["reason"].as_str().unwrap();
    assert!(reason.contains("descriptor 3 (device)"), "{reason}");
}
