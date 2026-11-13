//! Node's `path.join`, `path.normalize` and `path.dirname`, for the paths the
//! catalog records: `dir` is `path.join(appRoot, 'Profiles', id)`, and an
//! older build compares and opens it as text. Lexical only: nothing here
//! reads the filesystem (resolving a relative path is the [`crate::Store`]'s).

/// Which of Node's `path` modules: `path.posix` or `path.win32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Posix,
    Windows,
}

impl Style {
    /// This OS's: what `path` is in the reference running here.
    pub fn native() -> Style {
        if cfg!(windows) {
            Style::Windows
        } else {
            Style::Posix
        }
    }

    fn sep(self) -> char {
        match self {
            Style::Posix => '/',
            Style::Windows => '\\',
        }
    }

    fn is_sep(self, c: char) -> bool {
        match self {
            Style::Posix => c == '/',
            Style::Windows => c == '/' || c == '\\',
        }
    }

    /// `path.join(...parts)`.
    pub fn join(self, parts: &[&str]) -> String {
        let joined = parts
            .iter()
            .filter(|part| !part.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(&self.sep().to_string());
        if joined.is_empty() {
            return ".".into();
        }
        self.normalize(&joined)
    }

    /// `path.normalize(path)`: separators collapsed (and on Windows made
    /// backslashes), `.` dropped, `..` applied, a trailing separator kept.
    pub fn normalize(self, path: &str) -> String {
        if path.is_empty() {
            return ".".into();
        }
        let (root, rest) = self.split_root(path);
        let absolute = root.ends_with(self.sep());
        let trailing = rest.chars().last().is_some_and(|c| self.is_sep(c));
        let mut segments: Vec<&str> = Vec::new();
        for segment in rest.split(|c| self.is_sep(c)) {
            match segment {
                "" | "." => {}
                ".." => {
                    if segments.last().is_some_and(|last| *last != "..") {
                        segments.pop();
                    } else if !absolute {
                        segments.push("..");
                    }
                }
                other => segments.push(other),
            }
        }
        let mut tail = segments.join(&self.sep().to_string());
        if tail.is_empty() && !absolute {
            tail.push('.');
        }
        if !tail.is_empty() && trailing {
            tail.push(self.sep());
        }
        format!("{root}{tail}")
    }

    /// `path.dirname(path)`, for a normalized absolute path.
    pub fn dirname(self, path: &str) -> String {
        let (root, rest) = self.split_root(path);
        let rest = rest.trim_end_matches(|c| self.is_sep(c));
        match rest.rfind(|c| self.is_sep(c)) {
            Some(at) => format!("{root}{}", &rest[..at]),
            None if !root.is_empty() => root,
            None => ".".into(),
        }
    }

    /// Whether `path` is absolute.
    pub fn is_absolute(self, path: &str) -> bool {
        self.split_root(path).0.ends_with(self.sep())
    }

    /// The root (`/`; on Windows `C:\`, `\\server\share\`, `C:` or `\`), made
    /// canonical, and the rest.
    fn split_root(self, path: &str) -> (String, &str) {
        match self {
            Style::Posix => {
                if let Some(rest) = path.strip_prefix('/') {
                    ("/".into(), rest.trim_start_matches('/'))
                } else {
                    (String::new(), path)
                }
            }
            Style::Windows => {
                let bytes = path.as_bytes();
                let sep = |i: usize| bytes.get(i).is_some_and(|&b| b == b'/' || b == b'\\');
                if sep(0) && sep(1) {
                    // UNC: \\server\share\ (both parts present), as Node.
                    let after = &path[2..];
                    let mut parts = after.splitn(3, ['/', '\\']);
                    if let (Some(server), Some(share)) = (parts.next(), parts.next())
                        && !server.is_empty()
                        && !share.is_empty()
                    {
                        let rest = parts.next().unwrap_or("");
                        return (format!("\\\\{server}\\{share}\\"), rest);
                    }
                    return ("\\".into(), path.trim_start_matches(['/', '\\']));
                }
                if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                    let drive = &path[..2];
                    if sep(2) {
                        return (
                            format!("{drive}\\"),
                            path[3..].trim_start_matches(['/', '\\']),
                        );
                    }
                    return (drive.to_owned(), &path[2..]);
                }
                if sep(0) {
                    return ("\\".into(), path.trim_start_matches(['/', '\\']));
                }
                (String::new(), path)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_is_nodes() {
        let p = Style::Posix;
        assert_eq!(p.join(&["/a/b/", "Profiles", "x"]), "/a/b/Profiles/x");
        assert_eq!(p.join(&["/a/./b/../c", "Profiles"]), "/a/c/Profiles");
        assert_eq!(p.join(&["//a", "", "b/"]), "/a/b/");
        assert_eq!(p.join(&["a", "../.."]), "..");
        assert_eq!(p.normalize("/.."), "/");
        assert_eq!(p.dirname("/a/b"), "/a");
        assert_eq!(p.dirname("/a"), "/");
        assert!(p.is_absolute("/x") && !p.is_absolute("x"));
    }

    #[test]
    fn windows_is_nodes() {
        let w = Style::Windows;
        assert_eq!(
            w.join(&["C:\\Users\\u\\AppData\\Roaming\\Freedom", "Profiles", "x"]),
            "C:\\Users\\u\\AppData\\Roaming\\Freedom\\Profiles\\x"
        );
        assert_eq!(w.join(&["C:/a//b/", "..", "c"]), "C:\\a\\c");
        assert_eq!(w.join(&["\\\\srv\\share\\a", "b"]), "\\\\srv\\share\\a\\b");
        assert_eq!(w.dirname("C:\\a\\b"), "C:\\a");
        assert_eq!(w.dirname("C:\\a"), "C:\\");
        assert!(w.is_absolute("C:\\x") && !w.is_absolute("C:x"));
    }
}
