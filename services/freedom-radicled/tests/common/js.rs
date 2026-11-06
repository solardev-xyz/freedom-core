//! A model of main's JavaScript, for the composed reads' expectations: a
//! value as `JSON.parse` makes it (its object's members in JavaScript's
//! order: array indices first, increasing, then the others as they came;
//! a repeated key in its first place, with its last value), written as
//! `JSON.stringify` writes it, and main's compositions over such values,
//! written as main writes them. It shares no code with the service's own
//! composition (src/reads/js.rs): tests/composed.rs pins both to
//! `vectors/radicle-reads.json`, which main's code at the reference
//! recorded, then checks the binary against this model on a fixture.
//!
//! Its limit: a string is read by serde_json, which refuses a lone
//! surrogate's escape.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

/// A JavaScript value, as `JSON.parse` makes it.
#[derive(Debug, Clone, PartialEq)]
pub enum Js {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Js>),
    /// Its members, in JavaScript's order.
    Object(Vec<(String, Js)>),
}

/// An array index's value, if `key` is one: its canonical decimal form, up
/// to 2^32 - 2.
fn index(key: &str) -> Option<u64> {
    if key.is_empty() || key.len() > 10 || !key.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if key.len() > 1 && key.starts_with('0') {
        return None;
    }
    let n: u64 = key.parse().ok()?;
    (n < u64::from(u32::MAX)).then_some(n)
}

impl Js {
    /// An object of `members` as JavaScript keeps them.
    pub fn object(members: Vec<(String, Js)>) -> Js {
        let mut kept: Vec<(String, Js)> = Vec::new();
        for (key, value) in members {
            match kept.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => kept.push((key, value)),
            }
        }
        let (mut indices, names): (Vec<_>, Vec<_>) =
            kept.into_iter().partition(|(k, _)| index(k).is_some());
        indices.sort_by_key(|(k, _)| index(k));
        indices.extend(names);
        Js::Object(indices)
    }

    /// `this.key`, or undefined.
    pub fn get(&self, key: &str) -> Option<&Js> {
        match self {
            Js::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Whether JavaScript takes it as true.
    pub fn truthy(&self) -> bool {
        match self {
            Js::Null | Js::Bool(false) => false,
            Js::Number(n) => *n != 0.0 && !n.is_nan(),
            Js::String(s) => !s.is_empty(),
            _ => true,
        }
    }
}

/// A recursive-descent reader of JSON text, as `JSON.parse` reads it: its
/// strings through serde_json, its numbers through Rust's `f64` parsing,
/// which rounds to the nearest double, as JavaScript does.
struct Reader<'a> {
    text: &'a str,
    at: usize,
}

impl Reader<'_> {
    fn ws(&mut self) {
        while self.text[self.at..].starts_with([' ', '\t', '\n', '\r']) {
            self.at += 1;
        }
    }

    fn eat(&mut self, c: char) -> Option<()> {
        self.ws();
        self.text[self.at..].starts_with(c).then(|| self.at += 1)
    }

    fn string(&mut self) -> Option<String> {
        self.ws();
        let rest = &self.text[self.at..];
        let mut escaped = false;
        let end = rest
            .char_indices()
            .skip(1)
            .find(|&(_, c)| {
                let done = c == '"' && !escaped;
                escaped = c == '\\' && !escaped;
                done
            })?
            .0;
        let token = &rest[..=end];
        self.at += end + 1;
        serde_json::from_str(token).ok()
    }

    fn value(&mut self) -> Option<Js> {
        self.ws();
        let rest = &self.text[self.at..];
        for (word, value) in [
            ("null", Js::Null),
            ("true", Js::Bool(true)),
            ("false", Js::Bool(false)),
        ] {
            if rest.starts_with(word) {
                self.at += word.len();
                return Some(value);
            }
        }
        match rest.chars().next()? {
            '"' => self.string().map(Js::String),
            '[' => {
                self.at += 1;
                let mut items = Vec::new();
                if self.eat(']').is_some() {
                    return Some(Js::Array(items));
                }
                loop {
                    items.push(self.value()?);
                    if self.eat(']').is_some() {
                        return Some(Js::Array(items));
                    }
                    self.eat(',')?;
                }
            }
            '{' => {
                self.at += 1;
                let mut members = Vec::new();
                if self.eat('}').is_some() {
                    return Some(Js::object(members));
                }
                loop {
                    let key = self.string()?;
                    self.eat(':')?;
                    members.push((key, self.value()?));
                    if self.eat('}').is_some() {
                        return Some(Js::object(members));
                    }
                    self.eat(',')?;
                }
            }
            _ => {
                let len = rest
                    .find(|c: char| !matches!(c, '-' | '+' | '.' | 'e' | 'E' | '0'..='9'))
                    .unwrap_or(rest.len());
                self.at += len;
                rest[..len].parse().ok().map(Js::Number)
            }
        }
    }
}

/// `JSON.parse(text)`, if the model can read it.
pub fn parse(text: &str) -> Option<Js> {
    let mut reader = Reader { text, at: 0 };
    let value = reader.value()?;
    reader.ws();
    (reader.at == text.len()).then_some(value)
}

/// `String(n)`, as `JSON.stringify` writes a number. Its digits are
/// serde_json's (Żmij's): the fewest that read back, and of two as close
/// the even one, as V8's. Not Rust's shortest form, which takes the one
/// above (1658206780088562.25 would be 1658206780088562.3), nor the
/// service's way to the same digits (src/reads/js.rs).
fn number(n: f64) -> String {
    if !n.is_finite() {
        return "null".into();
    }
    if n == 0.0 {
        return "0".into();
    }
    // serde_json writes `1234.5`, `1.5e-7` or `1e16`: its digits, and the
    // power of ten of the point before them.
    let text = serde_json::to_string(&n.abs()).unwrap();
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all = format!("{whole}{fraction}");
    let digits = all.trim_start_matches('0');
    let point =
        whole.len() as i32 - (all.len() - digits.len()) as i32 + exponent.parse::<i32>().unwrap();
    let digits = digits.trim_end_matches('0');
    let k = digits.len() as i32;
    let sign = if n < 0.0 { "-" } else { "" };
    // ECMA-262's Number::toString, steps 6 to 10.
    if k <= point && point <= 21 {
        format!("{sign}{digits}{}", "0".repeat((point - k) as usize))
    } else if 0 < point && point <= 21 {
        let (whole, fraction) = digits.split_at(point as usize);
        format!("{sign}{whole}.{fraction}")
    } else if -6 < point && point <= 0 {
        format!("{sign}0.{}{digits}", "0".repeat(-point as usize))
    } else {
        let (first, rest) = digits.split_at(1);
        let dot = if rest.is_empty() { "" } else { "." };
        let e = point - 1;
        let e_sign = if e < 0 { '-' } else { '+' };
        format!("{sign}{first}{dot}{rest}e{e_sign}{}", e.abs())
    }
}

/// `JSON.stringify(value)`.
pub fn stringify(value: &Js) -> String {
    match value {
        Js::Null => "null".into(),
        Js::Bool(b) => b.to_string(),
        Js::Number(n) => number(*n),
        Js::String(s) => serde_json::to_string(s).unwrap(),
        Js::Array(items) => format!(
            "[{}]",
            items.iter().map(stringify).collect::<Vec<_>>().join(",")
        ),
        Js::Object(members) => format!(
            "{{{}}}",
            members
                .iter()
                .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), stringify(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// `JSON.stringify(JSON.parse(text))`.
pub fn again(text: &str) -> Option<String> {
    parse(text).map(|v| stringify(&v))
}

const README_CANDIDATES: [&str; 5] = [
    "README.md",
    "README.markdown",
    "README.txt",
    "README",
    "readme.md",
];

/// Main's `findReadme`, of a `treeAt` text.
pub fn find_readme(tree: &str) -> Option<&'static str> {
    let tree = parse(tree)?;
    let Some(Js::Array(entries)) = tree.get("entries") else {
        return None;
    };
    let names: Vec<&str> = entries
        .iter()
        .filter(|e| e.get("kind") == Some(&Js::String("blob".into())))
        .filter_map(|e| match e.get("name") {
            Some(Js::String(name)) => Some(name.as_str()),
            _ => None,
        })
        .collect();
    README_CANDIDATES.into_iter().find(|c| names.contains(c))
}

/// Main's `readmeAtRaw`'s splice of a blob's text.
pub fn splice(raw: &str, candidate: &str) -> String {
    let end = raw.rfind('}').unwrap();
    format!(
        "{},\"path\":{}{}",
        &raw[..end],
        serde_json::to_string(candidate).unwrap(),
        &raw[end..]
    )
}

/// Main's `buildRepoMeta`, of a `repoInfo` text and a `seeders` one (`None`
/// for a failure), as `JSON.stringify` writes it.
pub fn repo_meta(info: &str, seeders: Option<&str>) -> String {
    let info = parse(info).unwrap();
    let seeding = match seeders.map(|s| parse(s).unwrap()) {
        None | Some(Js::Null) => Some(Js::Number(0.0)),
        Some(s) => s.get("seeding").cloned(),
    };
    let field = |key: &str| info.get(key).cloned();
    let defined = |pairs: Vec<(&str, Option<Js>)>| {
        Js::Object(
            pairs
                .into_iter()
                .filter_map(|(k, v)| v.map(|v| (k.to_string(), v)))
                .collect(),
        )
    };
    let meta =
        defined(vec![
            ("rid", field("rid")),
            (
                "payloads",
                Some(defined(vec![(
                    "xyz.radicle.project",
                    Some(defined(vec![
                        (
                            "data",
                            Some(defined(vec![
                                ("name", field("name")),
                                ("description", field("description")),
                                ("defaultBranch", field("defaultBranch")),
                            ])),
                        ),
                        (
                            "meta",
                            Some(defined(vec![
                                ("head", field("head")),
                                ("issues", Some(defined(vec![("open", field("issuesOpen"))]))),
                                (
                                    "patches",
                                    Some(defined(vec![("open", field("patchesOpen"))])),
                                ),
                            ])),
                        ),
                    ])),
                )])),
            ),
            (
                "delegates",
                Some(
                    field("delegates")
                        .filter(Js::truthy)
                        .unwrap_or(Js::Array(vec![])),
                ),
            ),
            (
                "threshold",
                Some(
                    field("threshold")
                        .filter(|t| *t != Js::Null)
                        .unwrap_or(Js::Number(1.0)),
                ),
            ),
            (
                "visibility",
                Some(field("visibility").filter(Js::truthy).unwrap_or_else(|| {
                    Js::Object(vec![("type".into(), Js::String("public".into()))])
                })),
            ),
            ("seeding", seeding),
        ]);
    stringify(&meta)
}

/// JavaScript's white space, as `parseInt` skips it.
fn space(c: char) -> bool {
    "\t\n\u{b}\u{c}\r \u{a0}\u{1680}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}\u{feff}".contains(c)
        || ('\u{2000}'..='\u{200a}').contains(&c)
}

/// `Number.parseInt(s, 10)`.
pub fn parse_int(s: &str) -> f64 {
    let mut chars = s.chars().skip_while(|c| space(*c)).peekable();
    let sign = match chars.peek() {
        Some('-') => {
            chars.next();
            -1.0
        }
        Some('+') => {
            chars.next();
            1.0
        }
        _ => 1.0,
    };
    let digits: String = chars.take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return f64::NAN;
    }
    sign * digits.parse::<f64>().unwrap()
}

/// Main's `paginate`, of an `issues` or `patches` text and the query's
/// `status`, `page` and `perPage` (null for absent).
pub fn paginate(
    items: &str,
    status: Option<&str>,
    page: Option<&str>,
    per_page: Option<&str>,
) -> String {
    let Js::Array(items) = parse(items).unwrap() else {
        panic!("not an array");
    };
    let or = |s: Option<&str>, d: &'static str| match s {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => d.to_string(),
    };
    let falsy = |n: f64, d: f64| if n.is_nan() || n == 0.0 { d } else { n };
    let filtered: Vec<&Js> = items
        .iter()
        .filter(|item| match status {
            Some(status) if !status.is_empty() => {
                item.get("state").and_then(|s| s.get("status"))
                    == Some(&Js::String(status.to_string()))
            }
            _ => true,
        })
        .collect();
    let page = falsy(parse_int(&or(page, "0")), 0.0).max(0.0);
    let per_page = falsy(parse_int(&or(per_page, "30")), 30.0).clamp(1.0, 100.0);
    let len = filtered.len() as f64;
    let from = (page * per_page).min(len);
    let to = ((page + 1.0) * per_page).min(len);
    let picked: Vec<Js> = if to > from {
        filtered[from as usize..to as usize]
            .iter()
            .map(|j| (*j).clone())
            .collect()
    } else {
        vec![]
    };
    stringify(&Js::Array(picked))
}
