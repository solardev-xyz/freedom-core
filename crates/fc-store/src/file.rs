//! One store file: 0012's permission files and the phone payments today,
//! 0013's stores as they move (design 0013, "How the core writes them").
//!
//! - **Reading** ([`read_file`]) follows 0001's rules: a regular file the
//!   user owns, never through a symlink, judged on the open handle, and no
//!   more than a bound. Anything else is [`Read::Unreadable`]; what that
//!   means for the store is the caller's.
//! - **Writing** ([`write_file`]) is 0001's single-file write
//!   ([`fsx::replace`]): a temp file of mode `0600`, its fsync, the rename,
//!   the directory's flush, with a test build's failure at each step.
//! - **A file that can't be read** is renamed aside once
//!   ([`set_aside`]: `<name>.unreadable`).

use std::io;
use std::path::Path;

use crate::Hooks;
use crate::fsx::{self, Done};

/// What reading a file found.
#[derive(Debug, PartialEq, Eq)]
pub enum Read {
    Missing,
    /// Not a regular file the user owns, past the bound, or an I/O error.
    Unreadable,
    Bytes(Vec<u8>),
}

/// Reads `path` under 0001's rules: a regular file, opened without
/// following a symlink and judged on the open handle, owned by the user,
/// and no more than `bound` bytes. On Windows the owner is read from the
/// handle too (freedom-core#360), so a file another account planted in a
/// split root (`--profile-dir`) reads as unreadable, as does one whose
/// owner can't be read; an elevated administrator's own files, which
/// Windows may give to the Administrators group, count as the user's
/// (`fc_sys::windows::owned_by_current_user`). A file the user owns that
/// another account may still edit is 0001's owner-only DACL follow-up.
pub fn read_file(path: &Path, bound: usize) -> Read {
    let file = match fsx::open_regular(path, false) {
        Ok(fsx::Regular::File(file)) => file,
        Ok(fsx::Regular::Missing) => return Read::Missing,
        Ok(fsx::Regular::Other) | Err(_) => return Read::Unreadable,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match file.metadata() {
            Ok(metadata) if metadata.uid() == rustix::process::getuid().as_raw() => {}
            _ => return Read::Unreadable,
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        if !matches!(
            fc_sys::windows::owned_by_current_user(file.as_handle()),
            Ok(true)
        ) {
            return Read::Unreadable;
        }
    }
    match fsx::read_at_most(&file, bound as u64) {
        Ok(Some(bytes)) => Read::Bytes(bytes),
        Ok(None) | Err(_) => Read::Unreadable,
    }
}

/// 0001's single-file write of `target` ([`fsx::replace`], nothing checked
/// and nothing gating the commit), with `hooks`' failures at each step
/// (`write`, `fsync`, `rename`, `flush`). Before the rename an error leaves
/// the target untouched and the temp file removed; after it, a failed flush
/// is [`Done::NotDurable`].
pub fn write_file(target: &Path, contents: &[u8], hooks: &dyn Hooks) -> io::Result<Done> {
    match fsx::replace(target, contents, |_| Ok(()), || true, hooks) {
        Ok(done) => Ok(done),
        Err(fsx::WriteError::Io(error)) => Err(error),
        // Neither can happen: the check accepts everything, and the gate
        // always allows.
        Err(fsx::WriteError::Check(reason)) => Err(io::Error::other(reason)),
        Err(fsx::WriteError::Abandoned) => Err(io::Error::other("the write was abandoned")),
    }
}

/// Renames `dir/name`, which can't be read, aside to `dir/<name>.unreadable`
/// (replacing an earlier one), then makes the rename durable
/// ([`fsx::sync_rename`]). An error: the rename failed, and nothing moved.
pub fn set_aside(dir: &Path, name: &str) -> io::Result<Done> {
    let aside = dir.join(format!("{name}.unreadable"));
    std::fs::rename(dir.join(name), &aside)?;
    Ok(fsx::flushed(fsx::sync_rename(dir, &aside)))
}

#[cfg(test)]
mod tests;
