//! The Publish group's JSON replies, each through its typed reader (design
//! 0015, "JSON replies"): a tag (`GET /tags/<uid>`: bee-js's `TagSchema`,
//! then publish-service.js's `normalizeTag`), and an upload's result
//! (`{ reference }`, as page-upload.js reads a page's upload and as bee-js
//! reads `POST /chunks`). Each reader reads the bytes once, keeps only the
//! fields named, and skips the rest.

use fc_json::JsString;

use crate::ReplyError;
use crate::js::{self, math_round};
use crate::json::{Reader, Token};
use crate::machine::JSON_REPLY_CAP;
use crate::value::Value;
use crate::zod::{Expected, Issue, Issues, Received, Segment};

/// A field as the reply had it.
#[derive(Debug, Clone, PartialEq)]
enum Field<T> {
    Missing,
    /// `null`, which only a nullish field admits.
    Null,
    Wrong(Received),
    Ok(T),
}

fn received(token: &Token<'_>) -> Received {
    match token {
        Token::Object => Received::Object,
        Token::Array => Received::Array,
        Token::String(_) => Received::String,
        Token::Number(n) => Received::of_number(*n),
        Token::Bool(_) => Received::Boolean,
        Token::Null => Received::Null,
    }
}

fn number(r: &mut Reader<'_>, token: Token<'_>) -> Result<Field<f64>, ReplyError> {
    match token {
        Token::Number(n) if n.is_finite() => Ok(Field::Ok(n)),
        Token::Number(n) => Ok(Field::Wrong(Received::of_number(n))),
        other => {
            let what = received(&other);
            r.skip(other)?;
            Ok(Field::Wrong(what))
        }
    }
}

fn string(r: &mut Reader<'_>, token: Token<'_>) -> Result<Field<JsString>, ReplyError> {
    match token {
        Token::String(raw) => Ok(Field::Ok(raw.decode())),
        Token::Null => Ok(Field::Null),
        other => {
            let what = received(&other);
            r.skip(other)?;
            Ok(Field::Wrong(what))
        }
    }
}

/// A tag as bee-js's `TagSchema` gives it: the fields `normalizeTag` reads.
#[derive(Debug, Clone, PartialEq)]
pub struct Tag {
    /// `address`, `''` when it was null or absent.
    pub address: JsString,
    pub seen: f64,
    pub sent: f64,
    pub split: f64,
    pub stored: f64,
    pub synced: f64,
    pub uid: f64,
}

/// What bee-js's `tag.get` made of a reply: the tag, or zod's refusal
/// (its `ZodError`'s message).
pub type TagRead = Result<Tag, JsString>;

/// The node's `/tags/<uid>` reply, as bee-js's `http` reads it
/// (`Response.text()`: a byte-order mark dropped; an empty text is `null`)
/// and `TagSchema` checks it. Fails `too_large` past 64 KiB; `TooDeep`
/// past the nesting bound; `Syntax` for a text `JSON.parse` refuses.
pub fn read_tag(reply: &[u8]) -> Result<TagRead, ReplyError> {
    if reply.len() > JSON_REPLY_CAP {
        return Err(ReplyError::TooLarge);
    }
    let text = js::strip_bom(reply);
    let mut issues = Issues::new();
    let push = |issues: &mut Issues, issue: Issue| {
        issues
            .push(issue, JSON_REPLY_CAP)
            .map_err(|_| ReplyError::TooLarge)
    };
    if text.is_empty() {
        push(
            &mut issues,
            Issue::new(Expected::Object, Received::Null, &[]),
        )?;
        return Ok(Err(JsString::from(issues.message())));
    }
    let mut r = Reader::new(text);
    let root = r.token()?;
    if root != Token::Object {
        push(
            &mut issues,
            Issue::new(Expected::Object, received(&root), &[]),
        )?;
        r.skip(root)?;
        r.finish()?;
        return Ok(Err(JsString::from(issues.message())));
    }
    let mut address = Field::Missing;
    let mut numbers = [
        ("seen", Field::Missing),
        ("sent", Field::Missing),
        ("split", Field::Missing),
        ("startedAt", Field::Missing),
        ("stored", Field::Missing),
        ("synced", Field::Missing),
        ("uid", Field::Missing),
    ];
    while let Some(key) = r.next_key()? {
        let token = r.token()?;
        // A repeated key keeps its last value, as `JSON.parse` does.
        if key.is("address") {
            address = string(&mut r, token)?;
            continue;
        }
        if key.is("startedAt") {
            // Only its type is read.
            numbers[3].1 = match string(&mut r, token)? {
                Field::Ok(_) => Field::Ok(0.0),
                Field::Null => Field::Wrong(Received::Null),
                Field::Wrong(what) => Field::Wrong(what),
                Field::Missing => Field::Missing,
            };
            continue;
        }
        match numbers.iter_mut().find(|(name, _)| key.is(name)) {
            Some((_, field)) => *field = number(&mut r, token)?,
            None => r.skip(token)?,
        }
    }
    r.finish()?;
    // zod's issues, in the schema's key order.
    if let Field::Wrong(what) = address {
        push(
            &mut issues,
            Issue::new(Expected::String, what, &[Segment::Key("address")]),
        )?;
    }
    let mut values = [0.0; 7];
    for (i, (name, field)) in numbers.iter().enumerate() {
        let expected = if *name == "startedAt" {
            Expected::String
        } else {
            Expected::Number
        };
        match field {
            Field::Ok(n) => values[i] = *n,
            Field::Missing => push(
                &mut issues,
                Issue::new(expected, Received::Undefined, &[Segment::Key(name)]),
            )?,
            Field::Wrong(what) => push(
                &mut issues,
                Issue::new(expected, *what, &[Segment::Key(name)]),
            )?,
            Field::Null => push(
                &mut issues,
                Issue::new(expected, Received::Null, &[Segment::Key(name)]),
            )?,
        }
    }
    if !issues.is_empty() {
        return Ok(Err(JsString::from(issues.message())));
    }
    let [seen, sent, split, _, stored, synced, uid] = values;
    Ok(Ok(Tag {
        address: match address {
            Field::Ok(s) => s,
            _ => JsString::default(),
        },
        seen,
        sent,
        split,
        stored,
        synced,
        uid,
    }))
}

/// `x || 0` for a number.
fn or_zero(x: f64) -> f64 {
    if x == 0.0 || x.is_nan() { 0.0 } else { x }
}

/// `/^[a-f0-9]{64}(?:[a-f0-9]{64})?$/i`: a reference, plain or encrypted.
fn is_reference(s: &JsString) -> bool {
    s.is_well_formed()
        && (s.len() == 64 || s.len() == 128)
        && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// publish-service.js's `normalizeTag(tag)`: the counts (`|| 0`), the share
/// sent of those split, in whole percent, and whether every split chunk is
/// synced or was seen; the tag's address when it is a reference, in lower
/// case.
pub fn normalize_tag(tag: &Tag) -> (Value, bool) {
    let split = or_zero(tag.split);
    let seen = or_zero(tag.seen);
    let stored = or_zero(tag.stored);
    let sent = or_zero(tag.sent);
    let synced = or_zero(tag.synced);
    let ratio = if split > 0.0 {
        (sent / split).min(1.0)
    } else {
        0.0
    };
    let done = split > 0.0 && synced + seen >= split;
    let mut members = vec![(JsString::from("tagUid"), Value::Number(tag.uid))];
    if is_reference(&tag.address) {
        members.push((
            JsString::from("reference"),
            Value::String(JsString::from(tag.address.as_str().to_ascii_lowercase())),
        ));
    }
    for (name, n) in [
        ("split", split),
        ("seen", seen),
        ("stored", stored),
        ("sent", sent),
        ("synced", synced),
        ("progress", math_round(ratio * 100.0)),
    ] {
        members.push((JsString::from(name), Value::Number(n)));
    }
    members.push((JsString::from("done"), Value::Bool(done)));
    (Value::Object(members), done)
}

/// An upload's result as JSON: what its root was, and its `reference`.
#[derive(Debug, Clone, PartialEq)]
pub struct UploadBody {
    /// `None` for an object; else what the root was.
    root: Option<Received>,
    reference: Field<JsString>,
}

/// An upload's `{ reference }` reply, read once. `TooDeep` past the
/// nesting bound; `Syntax` for a text `JSON.parse` refuses (an empty one
/// included).
fn read_upload(text: &[u8]) -> Result<UploadBody, ReplyError> {
    if text.len() > JSON_REPLY_CAP {
        return Err(ReplyError::TooLarge);
    }
    if text.is_empty() {
        return Err(ReplyError::Syntax(0));
    }
    let mut r = Reader::new(text);
    let root = r.token()?;
    if root != Token::Object {
        let what = received(&root);
        r.skip(root)?;
        r.finish()?;
        return Ok(UploadBody {
            root: Some(what),
            reference: Field::Missing,
        });
    }
    let mut reference = Field::Missing;
    while let Some(key) = r.next_key()? {
        let token = r.token()?;
        if key.is("reference") {
            reference = string(&mut r, token)?;
        } else {
            r.skip(token)?;
        }
    }
    r.finish()?;
    Ok(UploadBody {
        root: None,
        reference,
    })
}

/// What a page's upload result gave: page-upload.js's `uploadResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageUpload {
    /// The reference, in lower case (64 or 128 hex), and the tag.
    Ok {
        reference: String,
        tag_uid: Option<u64>,
    },
    /// `The node answered the upload with no reference`: the body isn't
    /// JSON, or has no reference of 64 or 128 hex.
    NoReference,
}

/// page-upload.js's text for an upload result without a reference.
pub const NO_REFERENCE_MESSAGE: &str = "The node answered the upload with no reference";

/// page-upload.js's reading of a page's upload result (`JSON.parse` of the
/// body as `Buffer.toString('utf8')`, a byte-order mark kept), then
/// `uploadResult`: `body?.reference` lowercased, 64 or 128 hex; the tag
/// from `swarm-tag` as `parseInt(…, 10)`, kept when a safe integer above 0.
/// Fails `TooDeep` past the nesting bound.
pub fn page_upload(body: &[u8], swarm_tag: Option<&str>) -> Result<PageUpload, ReplyError> {
    let read = match read_upload(body) {
        Ok(read) => read,
        Err(ReplyError::Syntax(_)) => return Ok(PageUpload::NoReference),
        Err(e) => return Err(e),
    };
    let reference = match (read.root, read.reference) {
        (None, Field::Ok(s)) if is_reference(&s) => s.as_str().to_ascii_lowercase(),
        _ => return Ok(PageUpload::NoReference),
    };
    // `toLowerCase()` of anything else can't make 64 or 128 ASCII hex
    // digits: no character outside ASCII lowercases into one.
    let tag_uid = swarm_tag.and_then(parse_int).filter(|n| *n > 0);
    Ok(PageUpload::Ok { reference, tag_uid })
}

/// `Number.parseInt(text, 10)` when it is a safe integer: leading white
/// space, a sign, then decimal digits up to the first other character.
fn parse_int(text: &str) -> Option<u64> {
    let trimmed = text.trim_start_matches(js::is_js_whitespace);
    let (negative, digits) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let digits: &str = &digits[..digits
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(digits.len())];
    if digits.is_empty() {
        return None;
    }
    // Past 2^53 - 1 it isn't a safe integer (and parseInt rounds).
    let value: u64 = digits.parse().ok()?;
    if negative || value > (1 << 53) - 1 {
        return None;
    }
    Some(value)
}

/// What bee-js's `chunk.upload` made of `POST /chunks`' result:
/// `UploadResultBody` (zod), then core-sdk's `Reference`, then the tag
/// header's `makeTagUid`. The error is the page's text.
pub fn chunk_upload(body: &[u8], swarm_tag: Option<&str>) -> Result<[u8; 32], ChunkUpload> {
    let text = js::strip_bom(body);
    let read = if text.is_empty() {
        // `text ? JSON.parse(text) : null`.
        UploadBody {
            root: Some(Received::Null),
            reference: Field::Missing,
        }
    } else {
        match read_upload(text) {
            Ok(read) => read,
            Err(ReplyError::Syntax(_)) => return Err(ChunkUpload::NotJson),
            Err(ReplyError::TooDeep) => return Err(ChunkUpload::TooDeep),
            Err(ReplyError::TooLarge) => return Err(ChunkUpload::TooLarge),
        }
    };
    let mut issues = Issues::new();
    let issue = match (read.root, &read.reference) {
        (Some(what), _) => Some(Issue::new(Expected::Object, what, &[])),
        (None, Field::Missing) => Some(Issue::new(
            Expected::String,
            Received::Undefined,
            &[Segment::Key("reference")],
        )),
        (None, Field::Null) => Some(Issue::new(
            Expected::String,
            Received::Null,
            &[Segment::Key("reference")],
        )),
        (None, Field::Wrong(what)) => Some(Issue::new(
            Expected::String,
            *what,
            &[Segment::Key("reference")],
        )),
        (None, Field::Ok(_)) => None,
    };
    if let Some(issue) = issue {
        // One issue is far under the cap.
        let _ = issues.push(issue, JSON_REPLY_CAP);
        return Err(ChunkUpload::Refused(JsString::from(issues.message())));
    }
    let Field::Ok(reference) = read.reference else {
        return Err(ChunkUpload::NotJson);
    };
    let address = parse_reference(&reference).map_err(ChunkUpload::Refused)?;
    if let Some(tag) = swarm_tag.filter(|t| !t.is_empty()) {
        tag_uid_check(tag).map_err(ChunkUpload::Refused)?;
    }
    Ok(address)
}

/// Why `POST /chunks`' result wasn't read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkUpload {
    /// Not JSON: the core's one text (deviation `reply-syntax`).
    NotJson,
    /// Nested past the bound: the call fails `error`.
    TooDeep,
    TooLarge,
    /// What bee-js threw: zod's message, or core-sdk's.
    Refused(JsString),
}

/// core-sdk 0.2.2's `new Reference(text)`: `0x`-prefixed or bare hex of 32
/// or 64 bytes. A 64-byte (encrypted) reference reads, but is no chunk's
/// address. core-sdk also reads a `bah5…` CID; the core doesn't decode
/// one, and refuses it as another reference than the chunk's.
fn parse_reference(text: &JsString) -> Result<[u8; 32], JsString> {
    let with = |prefix: &str| js::concat(&[&JsString::from(prefix), text]);
    if text.utf16_len() == 0 {
        return Err(with("Bytes#constructor: constructor parameter is falsy: "));
    }
    let s = text.as_bytes();
    if s.starts_with(b"bah5") {
        return Ok(not_the_chunk());
    }
    let digits = match s {
        [b'0', b'x' | b'X', rest @ ..] => rest,
        _ => s,
    };
    if !text.is_well_formed() || !digits.iter().all(u8::is_ascii_hexdigit) || digits.len() % 2 != 0
    {
        return Err(with("Bytes#constructor: invalid hex string: "));
    }
    let length = digits.len() / 2;
    if length != 32 && length != 64 {
        return Err(JsString::from(format!(
            "Bytes#checkByteLength: bytes length is {length} but expected 32 or 64"
        )));
    }
    if length == 64 {
        return Ok(not_the_chunk());
    }
    crate::chunks::unhex::<32>(&String::from_utf8_lossy(digits).to_ascii_lowercase())
        .ok_or_else(|| with("Bytes#constructor: invalid hex string: "))
}

/// What a reference that reads but can't be a chunk's address (an
/// encrypted reference, a CID) is compared as: every byte 0xff, which the
/// chunk's own address (a keccak256) differs from but for a preimage.
fn not_the_chunk() -> [u8; 32] {
    [0xff; 32]
}

/// bee-js's `makeTagUid(header)`: `z.coerce.number().min(0)` over the
/// `swarm-tag` header, its `ZodError` where it refuses.
fn tag_uid_check(text: &str) -> Result<(), JsString> {
    let n = js::string_to_number(text);
    let issue = if n.is_nan() {
        Some(invalid_number("NaN"))
    } else if n == f64::INFINITY {
        Some(invalid_number("Infinity"))
    } else if n == f64::NEG_INFINITY {
        Some(invalid_number("-Infinity"))
    } else if n < 0.0 {
        Some(
            "[\n  {\n    \"origin\": \"number\",\n    \"code\": \"too_small\",\n    \"minimum\": 0,\n    \"inclusive\": true,\n    \"path\": [],\n    \"message\": \"Too small: expected number to be >=0\"\n  }\n]"
                .to_owned(),
        )
    } else {
        None
    };
    match issue {
        Some(message) => Err(JsString::from(message)),
        None => Ok(()),
    }
}

fn invalid_number(received: &str) -> String {
    format!(
        "[\n  {{\n    \"expected\": \"number\",\n    \"code\": \"invalid_type\",\n    \"received\": \"{received}\",\n    \"path\": [],\n    \"message\": \"Invalid input: expected number, received {received}\"\n  }}\n]"
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn tags_read_as_bee_js_and_normalize_tag() {
        let tag = read_tag(
            br#"{"uid":101,"split":10,"seen":2,"stored":10,"sent":5,"synced":3,"address":"ABAB","startedAt":"x"}"#,
        )
        .unwrap()
        .unwrap();
        let (value, done) = normalize_tag(&tag);
        assert!(!done);
        assert_eq!(
            value.stringify().unwrap(),
            r#"{"tagUid":101,"split":10,"seen":2,"stored":10,"sent":5,"synced":3,"progress":50,"done":false}"#
        );
        let refused = read_tag(br#"{"uid":1,"address":5}"#).unwrap().unwrap_err();
        assert!(
            refused
                .as_str()
                .starts_with("[\n  {\n    \"expected\": \"string\"")
        );
        assert_eq!(refused.as_str().matches("\"code\"").count(), 7);
        assert_eq!(
            read_tag(b"").unwrap().unwrap_err().as_str(),
            "[\n  {\n    \"expected\": \"object\",\n    \"code\": \"invalid_type\",\n    \"path\": [],\n    \"message\": \"Invalid input: expected object, received null\"\n  }\n]"
        );
        assert_eq!(read_tag(b"<html>"), Err(ReplyError::Syntax(0)));
    }

    #[test]
    fn a_page_upload_reads_as_page_upload_js() {
        let ab = "AB".repeat(32);
        let body = format!(r#"{{"reference":"{ab}"}}"#);
        assert_eq!(
            page_upload(body.as_bytes(), Some(" 7x")).unwrap(),
            PageUpload::Ok {
                reference: "ab".repeat(32),
                tag_uid: Some(7)
            }
        );
        for tag in ["-3", "0", "abc", "9007199254740992"] {
            assert_eq!(
                page_upload(body.as_bytes(), Some(tag)).unwrap(),
                PageUpload::Ok {
                    reference: "ab".repeat(32),
                    tag_uid: None
                },
                "{tag}"
            );
        }
        for bad in [
            &b"<html>"[..],
            b"",
            b"null",
            br#"{"reference":5}"#,
            br#"{"reference":"0xabab"}"#,
        ] {
            assert_eq!(page_upload(bad, None).unwrap(), PageUpload::NoReference);
        }
        let bom = format!("\u{feff}{body}");
        assert_eq!(
            page_upload(bom.as_bytes(), None).unwrap(),
            PageUpload::NoReference
        );
    }

    #[test]
    fn a_chunk_upload_reads_as_bee_js() {
        let ab = "ab".repeat(32);
        let body = format!(r#"{{"reference":"0x{ab}"}}"#);
        assert_eq!(
            chunk_upload(body.as_bytes(), Some("0")).unwrap(),
            [0xab; 32]
        );
        assert_eq!(chunk_upload(b"<html>", None), Err(ChunkUpload::NotJson));
        let Err(ChunkUpload::Refused(m)) = chunk_upload(b"{}", None) else {
            panic!()
        };
        assert!(m.as_str().contains("received undefined"));
        let Err(ChunkUpload::Refused(m)) = chunk_upload(br#"{"reference":"zz"}"#, None) else {
            panic!()
        };
        assert_eq!(m, "Bytes#constructor: invalid hex string: zz");
        let Err(ChunkUpload::Refused(m)) = chunk_upload(body.as_bytes(), Some("-3")) else {
            panic!()
        };
        assert!(m.as_str().contains("too_small"));
        let Err(ChunkUpload::Refused(m)) = chunk_upload(body.as_bytes(), Some("5, 6")) else {
            panic!()
        };
        assert!(m.as_str().contains("received NaN"));
        assert_ne!(
            chunk_upload(
                format!(r#"{{"reference":"{}"}}"#, "ab".repeat(64)).as_bytes(),
                None
            )
            .unwrap(),
            [0xab; 32]
        );
    }
}
