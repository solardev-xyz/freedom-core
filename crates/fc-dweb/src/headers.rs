//! A header list with the Fetch standard's `Headers` semantics: names
//! compare case-insensitively, values are normalized, and iteration sorts by
//! name and combines repeated names, except `set-cookie`.

/// The header list of a request or a response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    /// Lowercase names and normalized values, in insertion order.
    list: Vec<(String, String)>,
}

/// HTTP whitespace, which `Headers` strips from both ends of a value.
fn is_http_whitespace(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | ' ')
}

impl Headers {
    pub fn new() -> Self {
        Self::default()
    }

    /// `new Headers(pairs)`.
    pub fn from_pairs<N: AsRef<str>, V: AsRef<str>>(
        pairs: impl IntoIterator<Item = (N, V)>,
    ) -> Self {
        let mut headers = Self::new();
        for (name, value) in pairs {
            headers.append(name.as_ref(), value.as_ref());
        }
        headers
    }

    /// `headers.append(name, value)`.
    pub fn append(&mut self, name: &str, value: &str) {
        self.list.push((
            name.to_ascii_lowercase(),
            value.trim_matches(is_http_whitespace).to_owned(),
        ));
    }

    /// `headers.get(name)`: every value, joined with `", "`.
    pub fn get(&self, name: &str) -> Option<String> {
        let name = name.to_ascii_lowercase();
        let mut values = self
            .list
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str());
        let first = values.next()?;
        Some(values.fold(first.to_owned(), |joined, value| joined + ", " + value))
    }

    /// `headers.has(name)`.
    pub fn has(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.list.iter().any(|(n, _)| *n == name)
    }

    /// `headers.delete(name)`.
    pub fn delete(&mut self, name: &str) {
        let name = name.to_ascii_lowercase();
        self.list.retain(|(n, _)| *n != name);
    }

    /// `headers.set(name, value)`: the first entry takes the value, the
    /// others go.
    pub fn set(&mut self, name: &str, value: &str) {
        let name = name.to_ascii_lowercase();
        let value = value.trim_matches(is_http_whitespace).to_owned();
        match self.list.iter().position(|(n, _)| *n == name) {
            Some(first) => {
                let mut index = 0;
                self.list.retain(|(n, _)| {
                    let keep = index <= first || *n != name;
                    index += 1;
                    keep
                });
                if let Some(entry) = self.list.get_mut(first) {
                    entry.1 = value;
                }
            }
            None => self.list.push((name, value)),
        }
    }

    /// `[...headers]`: sorted by name, repeated names combined with `", "`,
    /// except `set-cookie`, whose values stay separate.
    ///
    /// One sort, then one pass: the sort is stable, so each name's values
    /// stay in list order, and a run of equal names is one group. Planning
    /// so costs n log n in a request's headers, which arrive by the
    /// thousand within its size bound, never a scan of the list per name
    /// (PR #62 review, M1).
    pub fn entries(&self) -> Vec<(String, String)> {
        let mut sorted: Vec<&(String, String)> = self.list.iter().collect();
        sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
        let mut out: Vec<(String, String)> = Vec::new();
        for (name, value) in sorted {
            match out.last_mut() {
                Some((last, joined)) if last == name && name != "set-cookie" => {
                    joined.push_str(", ");
                    joined.push_str(value);
                }
                _ => out.push((name.clone(), value.clone())),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_semantics() {
        let mut headers = Headers::from_pairs([
            ("B", " 1\t"),
            ("a", "2"),
            ("b", "3"),
            ("Set-Cookie", "x"),
            ("set-cookie", "y"),
        ]);
        assert_eq!(headers.get("b").as_deref(), Some("1, 3"));
        assert_eq!(
            headers.entries(),
            [
                ("a", "2"),
                ("b", "1, 3"),
                ("set-cookie", "x"),
                ("set-cookie", "y")
            ]
            .map(|(n, v)| (n.to_owned(), v.to_owned()))
        );
        headers.set("B", "9");
        assert_eq!(headers.get("b").as_deref(), Some("9"));
        headers.delete("SET-COOKIE");
        assert!(!headers.has("set-cookie"));
    }
}
