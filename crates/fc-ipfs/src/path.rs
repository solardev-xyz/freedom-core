//! A request path below its root, decoded as verified mode decodes it
//! (0009, The IPFS walk, deviation `ipfs-path-decoding`): split on `/`
//! first, then each segment percent-decoded exactly once, as Kubo, HTTP
//! gateways and freedom-ipfs (from 9700f548, freedom-ipfs#58, through
//! axum's `percent-encoding`) decode it. `%XX` with two hex digits is a
//! byte; anything else is kept as written. Nothing is decoded twice.

/// The path's segments, decoded; `None` when a segment decodes to `.` or
/// `..`, holds `/`, `\` or NUL once decoded, or isn't UTF-8. Empty segments
/// are kept, as the native node keeps them.
pub fn decode_segments(path: &str) -> Option<Vec<String>> {
    path.split('/').map(decode_segment).collect()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_segment(segment: &str) -> Option<String> {
    let b = segment.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (
                b.get(i + 1).and_then(|&c| hex(c)),
                b.get(i + 2).and_then(|&c| hex(c)),
            )
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    let s = String::from_utf8(out).ok()?;
    if s == "." || s == ".." || s.contains(['/', '\\', '\0']) {
        return None;
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined(path: &str) -> Option<String> {
        decode_segments(path).map(|s| s.join("/"))
    }

    /// freedom-ipfs#58's table (`path_segments_are_percent_decoded_once`).
    #[test]
    fn decoded_once_as_the_native_node_decodes() {
        let pct = '%';
        let cases = [
            (format!("space{pct}20name.txt"), "space name.txt".to_owned()),
            (
                format!("two{pct}20{pct}20spaces.txt"),
                "two  spaces.txt".to_owned(),
            ),
            (
                format!(
                    "{pct}C3{pct}BCn{pct}20{pct}C3{pct}AF/{pct}C3{pct}A7{pct}C3{pct}B8d{pct}C3{pct}A9.txt"
                ),
                "\u{fc}n \u{ef}/\u{e7}\u{f8}d\u{e9}.txt".to_owned(),
            ),
            (
                format!("{pct}c3{pct}bcn{pct}20{pct}c3{pct}af/"),
                "\u{fc}n \u{ef}/".to_owned(),
            ),
            ("a+b.txt".to_owned(), "a+b.txt".to_owned()),
            (format!("{pct}252F.txt"), format!("{pct}2F.txt")),
            (format!("{pct}252E{pct}252E"), format!("{pct}2E{pct}2E")),
            (format!("{pct}2541"), format!("{pct}41")),
            (format!("q{pct}3F{pct}23.txt"), "q?#.txt".to_owned()),
            (format!("{pct}zz{pct}4"), format!("{pct}zz{pct}4")),
            ("dir//a".to_owned(), "dir//a".to_owned()),
            ("..a/.b/a..".to_owned(), "..a/.b/a..".to_owned()),
            (format!("{pct}2E{pct}2E{pct}2E"), "...".to_owned()),
        ];
        for (path, decoded) in cases {
            assert_eq!(joined(&path), Some(decoded), "{path}");
        }
        let refused = [
            format!("a{pct}2Fb"),
            format!("a{pct}2fb"),
            format!("a{pct}5Cb"),
            "a\\b".to_owned(),
            format!("a{pct}00b"),
            ".".to_owned(),
            "..".to_owned(),
            format!("{pct}2E"),
            format!("{pct}2e{pct}2E"),
            format!("a/{pct}2E{pct}2E/b"),
            format!("{pct}FF.txt"),
            format!("{pct}C3"),
            format!("{pct}C3{pct}28"),
            format!("{pct}ED{pct}A0{pct}80"),
        ];
        for path in refused {
            assert_eq!(joined(&path), None, "{path}");
        }
    }
}
