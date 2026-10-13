//! Storage qualification: which filesystems a service refuses because an OS
//! lock there may not exclude other hosts (design 0001, "Lifetime lock").
//! Storage that can't be inspected is refused too: failing closed is the
//! safe default. The same as `freedom-cored`'s.

use std::path::Path;

/// The result of inspecting a directory's filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Qualification {
    Local,
    /// A known network filesystem.
    Network(String),
    /// Inspection failed; treated as unqualified.
    Unknown(String),
}

pub fn qualify(dir: &Path) -> Qualification {
    imp::qualify(dir)
}

#[cfg(target_os = "linux")]
mod imp {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::Qualification;

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
    const NETWORK_FUSE: &[&[u8]] = &[
        b"sshfs",
        b"rclone",
        b"s3fs",
        b"gcsfuse",
        b"davfs",
        b"curlftpfs",
        b"glusterfs",
    ];

    pub fn qualify(dir: &Path) -> Qualification {
        let stat = match rustix::fs::statfs(dir) {
            Ok(stat) => stat,
            Err(e) => return Qualification::Unknown(format!("statfs failed: {e}")),
        };
        // f_type's width differs by architecture.
        #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
        let magic = (stat.f_type as i64 as u64) & 0xFFFF_FFFF;
        if let Some((_, name)) = NETWORK.iter().find(|(m, _)| *m == magic) {
            return Qualification::Network((*name).to_owned());
        }
        if magic != FUSE {
            return Qualification::Local;
        }
        let mountinfo = match std::fs::read("/proc/self/mountinfo") {
            Ok(bytes) => bytes,
            Err(e) => return Qualification::Unknown(format!("cannot read mountinfo: {e}")),
        };
        match fuse_subtype(&mountinfo, dir.as_os_str().as_bytes()) {
            Some(subtype) if NETWORK_FUSE.iter().any(|n| subtype.starts_with(n)) => {
                Qualification::Network(format!("fuse.{}", String::from_utf8_lossy(&subtype)))
            }
            Some(_) => Qualification::Local,
            None => Qualification::Unknown("FUSE mount without a known subtype".into()),
        }
    }

    /// The `fuse.<subtype>` of the mount holding `dir`, from mountinfo bytes.
    pub(super) fn fuse_subtype(mountinfo: &[u8], dir: &[u8]) -> Option<Vec<u8>> {
        let mut best: Option<(usize, Vec<u8>)> = None;
        for line in mountinfo.split(|b| *b == b'\n') {
            let Some(separator) = line.windows(3).position(|w| w == b" - ") else {
                continue;
            };
            let (left, right) = (&line[..separator], &line[separator + 3..]);
            let Some(mount_point) = left.split(|b| *b == b' ').nth(4).map(unescape) else {
                continue;
            };
            let Some(fs_type) = right.split(|b| *b == b' ').next() else {
                continue;
            };
            if covers(&mount_point, dir)
                && best
                    .as_ref()
                    .is_none_or(|(len, _)| mount_point.len() >= *len)
            {
                best = Some((mount_point.len(), fs_type.to_vec()));
            }
        }
        let (_, fs_type) = best?;
        fs_type.strip_prefix(b"fuse.").map(<[u8]>::to_vec)
    }

    /// Whether `mount_point` is `dir` or one of its ancestors, comparing
    /// whole path components.
    fn covers(mount_point: &[u8], dir: &[u8]) -> bool {
        mount_point == b"/"
            || dir == mount_point
            || (dir.starts_with(mount_point) && dir.get(mount_point.len()) == Some(&b'/'))
    }

    /// Decodes the kernel's `\NNN` octal escapes (space, tab, newline,
    /// backslash and any other byte).
    fn unescape(field: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(field.len());
        let mut i = 0;
        while i < field.len() {
            if field[i] == b'\\'
                && i + 3 < field.len()
                && field[i + 1..=i + 3]
                    .iter()
                    .all(|d| (b'0'..=b'7').contains(d))
            {
                let value = field[i + 1..=i + 3]
                    .iter()
                    .fold(0u16, |acc, d| acc * 8 + u16::from(d - b'0'));
                out.push(u8::try_from(value).unwrap_or(b'?'));
                i += 4;
            } else {
                out.push(field[i]);
                i += 1;
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn line(mount_point: &str, fs_type: &str) -> String {
            format!("36 25 0:32 / {mount_point} rw,relatime shared:1 - {fs_type} src rw\n")
        }

        #[test]
        fn mountinfo_escapes_and_nesting() {
            let backslash = format!("{}134", '\\');
            let tab = format!("{}011", '\\');
            let newline = format!("{}012", '\\');
            let info = [
                line("/", "ext4"),
                line(&format!("/mnt/a{tab}b"), "fuse.sshfs"),
                line(&format!("/mnt/n{newline}l"), "fuse.rclone"),
                line(&format!("/mnt/s{backslash}x"), "fuse.gocryptfs"),
                line("/mnt/outer", "fuse.sshfs"),
                line("/mnt/outer/inner", "fuse.gocryptfs"),
            ]
            .concat();
            let info = info.as_bytes();
            assert_eq!(
                fuse_subtype(info, b"/mnt/a\tb/x").as_deref(),
                Some(&b"sshfs"[..])
            );
            assert_eq!(
                fuse_subtype(info, b"/mnt/n\nl").as_deref(),
                Some(&b"rclone"[..])
            );
            assert_eq!(
                fuse_subtype(info, b"/mnt/s\\x/y").as_deref(),
                Some(&b"gocryptfs"[..])
            );
            // The longest covering mount wins; prefixes must be whole components.
            assert_eq!(
                fuse_subtype(info, b"/mnt/outer/inner/v").as_deref(),
                Some(&b"gocryptfs"[..])
            );
            assert_eq!(
                fuse_subtype(info, b"/mnt/outer/v").as_deref(),
                Some(&b"sshfs"[..])
            );
            assert_eq!(
                fuse_subtype(info, b"/mnt/outerx/v"),
                None,
                "not under /mnt/outer"
            );
            // Non-UTF-8 paths are compared as bytes.
            let mut odd = b"/mnt/outer/".to_vec();
            odd.push(0xff);
            assert_eq!(fuse_subtype(info, &odd).as_deref(), Some(&b"sshfs"[..]));
        }
    }
}

#[cfg(target_vendor = "apple")]
mod imp {
    use std::path::Path;

    use super::Qualification;

    const NETWORK: &[&str] = &["nfs", "smbfs", "afpfs", "webdav", "ftp", "cifs"];

    pub fn qualify(dir: &Path) -> Qualification {
        let stat = match rustix::fs::statfs(dir) {
            Ok(stat) => stat,
            Err(e) => return Qualification::Unknown(format!("statfs failed: {e}")),
        };
        let name: String = stat
            .f_fstypename
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| char::from(*c as u8))
            .collect();
        if NETWORK.contains(&name.as_str()) {
            Qualification::Network(name)
        } else {
            Qualification::Local
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Component, Path, Prefix};

    use super::Qualification;

    // GetDriveTypeW results.
    const DRIVE_UNKNOWN: u32 = 0;
    const DRIVE_NO_ROOT_DIR: u32 = 1;
    const DRIVE_REMOTE: u32 = 4;

    /// UNC paths are network shares. Drive letters and volume paths are
    /// asked about with `GetDriveTypeW`: `DRIVE_REMOTE` (a mapped network
    /// drive) is refused, and an answer of unknown or no root fails closed.
    pub fn qualify(dir: &Path) -> Qualification {
        let Some(Component::Prefix(prefix)) = dir.components().next() else {
            return Qualification::Unknown("path without a drive or volume".into());
        };
        let root: Vec<u16> = match prefix.kind() {
            Prefix::UNC(..) | Prefix::VerbatimUNC(..) => {
                return Qualification::Network("unc".into());
            }
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                [u16::from(letter), u16::from(b':'), u16::from(b'\\'), 0].to_vec()
            }
            _ => prefix
                .as_os_str()
                .encode_wide()
                .chain([u16::from(b'\\'), 0])
                .collect(),
        };
        match drive_type(&root) {
            DRIVE_REMOTE => Qualification::Network("mapped network drive".into()),
            DRIVE_UNKNOWN | DRIVE_NO_ROOT_DIR => {
                Qualification::Unknown("drive type unknown".into())
            }
            _ => Qualification::Local,
        }
    }

    /// `GetDriveTypeW` on a NUL-terminated root path.
    #[allow(unsafe_code)]
    fn drive_type(root: &[u16]) -> u32 {
        if root.last() != Some(&0) {
            return DRIVE_UNKNOWN;
        }
        // SAFETY: `root` is a valid, NUL-terminated UTF-16 string that lives
        // for the whole call; GetDriveTypeW only reads it and keeps no
        // reference.
        unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(root.as_ptr()) }
    }
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
mod imp {
    use super::Qualification;

    pub fn qualify(_dir: &std::path::Path) -> Qualification {
        Qualification::Unknown("unsupported platform".into())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn temp_dir_is_local() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(super::qualify(&canonical), super::Qualification::Local);
    }
}
