//! A pinned Kubo, offline, in a repository of its own: it adds the fixtures,
//! exports their blocks, and serves the trustless gateway answers the
//! verifier asks for.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// The release the vectors pin. `KUBO_BIN` names its `ipfs` binary.
pub const VERSION: &str = "0.43.1";

type Err = Box<dyn std::error::Error>;

pub struct Kubo {
    bin: PathBuf,
    repo: PathBuf,
    gateway: String,
    daemon: Option<Child>,
}

fn free_port() -> Result<u16, Err> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

impl Kubo {
    pub fn new() -> Result<Self, Err> {
        let bin = PathBuf::from(
            std::env::var("KUBO_BIN").map_err(|_| "KUBO_BIN must name Kubo's ipfs binary")?,
        );
        let repo = std::env::temp_dir().join(format!("dweb-verify-kubo-{}", std::process::id()));
        if repo.exists() {
            std::fs::remove_dir_all(&repo)?;
        }
        let mut k = Self {
            bin,
            repo,
            gateway: String::new(),
            daemon: None,
        };
        let version = k.run(&["version", "--number"])?;
        if String::from_utf8_lossy(&version).trim() != VERSION {
            return Err(format!(
                "KUBO_BIN is Kubo {}, not {VERSION}",
                String::from_utf8_lossy(&version).trim()
            )
            .into());
        }
        k.run(&["init", "--empty-repo", "--profile=test"])?;
        let gw = free_port()?;
        let api = free_port()?;
        k.run(&[
            "config",
            "Addresses.Gateway",
            &format!("/ip4/127.0.0.1/tcp/{gw}"),
        ])?;
        k.run(&[
            "config",
            "Addresses.API",
            &format!("/ip4/127.0.0.1/tcp/{api}"),
        ])?;
        k.run(&["config", "--json", "Addresses.Swarm", "[]"])?;
        k.gateway = format!("http://127.0.0.1:{gw}");
        Ok(k)
    }

    fn command(&self) -> Command {
        let mut c = Command::new(&self.bin);
        c.env("IPFS_PATH", &self.repo)
            .env("IPFS_TELEMETRY", "off")
            .env_remove("IPFS_GATEWAY")
            .stdin(Stdio::null());
        c
    }

    pub fn run(&self, args: &[&str]) -> Result<Vec<u8>, Err> {
        let out = self.command().args(args).output()?;
        if !out.status.success() {
            return Err(format!(
                "ipfs {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        Ok(out.stdout)
    }

    /// `ipfs add -Q` with `flags`, offline: the root's CID.
    pub fn add(&self, path: &Path, flags: &[&str]) -> Result<String, Err> {
        let p = path.to_str().ok_or("path")?;
        let mut args = vec!["add", "-Q", "--pin=false"];
        args.extend_from_slice(flags);
        args.push(p);
        Ok(String::from_utf8_lossy(&self.run(&args)?)
            .trim()
            .to_string())
    }

    pub fn export(&self, cid: &str) -> Result<Vec<u8>, Err> {
        self.run(&["dag", "export", cid])
    }

    pub async fn start_daemon(&mut self) -> Result<(), Err> {
        let child = self
            .command()
            .args(["daemon", "--offline"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        self.daemon = Some(child);
        let client = reqwest::Client::new();
        for _ in 0..200 {
            if client
                .get(format!("{}/ipfs/bafkqaaa", self.gateway))
                .send()
                .await
                .is_ok()
            {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Err("Kubo's gateway didn't come up".into())
    }

    /// One gateway request; the `Date` header, the one that varies, is
    /// left out.
    pub async fn get(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Err> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let method = reqwest::Method::from_bytes(method.as_bytes())?;
        let mut req = client.request(method, format!("{}{path}", self.gateway));
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .filter(|(k, _)| k.as_str() != "date")
            .map(|(k, v)| {
                (
                    k.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = resp.bytes().await?.to_vec();
        Ok((status, headers, body))
    }
}

impl Drop for Kubo {
    fn drop(&mut self) {
        if let Some(mut child) = self.daemon.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.repo);
    }
}
