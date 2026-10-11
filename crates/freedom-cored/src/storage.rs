//! Storage qualification: which filesystems the core refuses because an OS
//! lock there may not exclude other hosts (design 0001, "Lifetime lock").

use std::path::Path;

/// The network filesystem `dir` lives on, if it's a known one.
pub fn network_filesystem(dir: &Path) -> Option<String> {
    imp::network_filesystem(dir)
}

#[cfg(target_os = "linux")]
mod imp {
    use std::path::Path;

    // statfs(2) magic numbers.
    const NETWORK: &[(u64, &str)] = &[
        (0x6969, "nfs"),
        (0x517B, "smb"),
        (0xFF53_4D42, "cifs"),
        (0xFE53_4D42, "smb2"),
        (0x5346_414F, "afs"),
        (0x6B41_4653, "kafs"),
        (0x00C3_6400, "ceph"),
        (0x0102_1997, "9p"),
        (0x0BD0_0BD0, "lustre"),
    ];
    const FUSE: u64 = 0x6573_5546;
    /// FUSE subtypes that are network filesystems. Local FUSE filesystems
    /// (gocryptfs, encfs, …) are fine.
    const NETWORK_FUSE: &[&str] = &[
        "sshfs",
        "rclone",
        "s3fs",
        "gcsfuse",
        "davfs",
        "curlftpfs",
        "glusterfs",
    ];

    pub fn network_filesystem(dir: &Path) -> Option<String> {
        let stat = rustix::fs::statfs(dir).ok()?;
        // f_type's width differs by architecture.
        #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
        let magic = (stat.f_type as i64 as u64) & 0xFFFF_FFFF;
        if let Some((_, name)) = NETWORK.iter().find(|(m, _)| *m == magic) {
            return Some((*name).to_owned());
        }
        if magic == FUSE {
            let subtype = fuse_subtype(dir)?;
            if NETWORK_FUSE.iter().any(|n| subtype.starts_with(n)) {
                return Some(format!("fuse.{subtype}"));
            }
        }
        None
    }

    /// The `fuse.<subtype>` of the mount holding `dir`, from mountinfo.
    fn fuse_subtype(dir: &Path) -> Option<String> {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        let dir = dir.to_str()?;
        let mut best: Option<(usize, String)> = None;
        for line in mountinfo.lines() {
            let mut halves = line.splitn(2, " - ");
            let (left, right) = (halves.next()?, halves.next()?);
            let mount_point = left.split(' ').nth(4)?.replace("\\040", " ");
            let fs_type = right.split(' ').next()?;
            let covers = dir == mount_point
                || mount_point == "/"
                || dir.starts_with(&format!("{}/", mount_point.trim_end_matches('/')));
            if covers
                && best
                    .as_ref()
                    .is_none_or(|(len, _)| mount_point.len() >= *len)
            {
                best = Some((mount_point.len(), fs_type.to_owned()));
            }
        }
        best.and_then(|(_, fs)| fs.strip_prefix("fuse.").map(str::to_owned))
    }
}

#[cfg(target_vendor = "apple")]
mod imp {
    use std::path::Path;

    const NETWORK: &[&str] = &["nfs", "smbfs", "afpfs", "webdav", "ftp", "cifs"];

    pub fn network_filesystem(dir: &Path) -> Option<String> {
        let stat = rustix::fs::statfs(dir).ok()?;
        let name: String = stat
            .f_fstypename
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| char::from(*c as u8))
            .collect();
        NETWORK.contains(&name.as_str()).then_some(name)
    }
}

#[cfg(windows)]
mod imp {
    use std::path::Path;

    /// UNC paths (`\\?\UNC\server\share`) are network shares. Mapped network
    /// drive letters need `GetDriveTypeW`, which is a follow-up (it needs a
    /// reviewed `unsafe` exception).
    pub fn network_filesystem(dir: &Path) -> Option<String> {
        let path = dir.to_str()?;
        (path.starts_with(r"\\?\UNC\") || (path.starts_with(r"\\") && !path.starts_with(r"\\?\")))
            .then(|| "unc".to_owned())
    }
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
mod imp {
    pub fn network_filesystem(_dir: &std::path::Path) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn temp_dir_is_local() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(super::network_filesystem(dir.path()), None);
    }
}
