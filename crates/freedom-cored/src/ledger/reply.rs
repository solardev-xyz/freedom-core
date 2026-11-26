//! `shell.ledger_apdu`'s replies (design 0016, "`shell.ledger_apdu`"),
//! read strictly, as 0015 reads `shell.swarm_api`'s.
//!
//! - **The result** is exactly one of `{ answer }`, hex, 2 to 260 bytes
//!   ending in the status word; `{ answer, hash_only: "shown" }`, only for
//!   a `6D00` to the operation's first `E0 1A` (Q23); and `{ failed }`,
//!   one of `not_found`, `busy`, `disconnected`, `unresponsive` and
//!   `timeout`.
//! - **The error** is one of main's two: `invalid_argument` with `data: {
//!   rule }`, the grammar's rule for an APDU it refused before the device
//!   (`parent`, `order`, `header`, `count`, `path`, `payload` or `ended`),
//!   or `cancelled`, without data, the answer to the core's cancel.
//! - **Anything else is a protocol error** ([`Fault`]): an unknown,
//!   missing or repeated member, a member of another type or outside its
//!   set, an answer outside 2 to 260 bytes, `hash_only` on any other
//!   answer, or another error. The lane then ends the connection, as 0001
//!   has it for a peer that breaks the protocol.
//! - **The bound** ([`REPLY_BOUND`]): the largest reply, serialized, is the
//!   largest answer's, so each `shell.ledger_apdu` is sent with it, and the
//!   transport refuses a longer reply before this module sees it.
//!
//! What passes is handed to the operation as `fc-ledger`'s
//! [`Reply`] ([`Answered::reply`]), which checks the answer against the APDU
//! it answers. It holds no secret: a Ledger's answers are public keys,
//! addresses, the app's name and signatures.

use fc_ledger::{Failed, MAX_ANSWER, MIN_ANSWER, Reply};
use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_protocol::message::MAX_ID;
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

/// The one answer `hash_only` may come with: the status word "instruction
/// not supported" alone (Q23).
const HASH_ONLY_ANSWER: [u8; 2] = [0x6d, 0x00];

/// `n`'s decimal digits.
const fn digits(mut n: u64) -> usize {
    let mut count = 1;
    while n >= 10 {
        n /= 10;
        count += 1;
    }
    count
}

/// What a response takes beside its result, as main writes it (one
/// `JSON.stringify`, no whitespace): `{"type":"response","id":`, the
/// largest ID (2^53 − 1, 16 digits), `,"result":` and the closing `}`. 51
/// bytes.
const ENVELOPE: usize = r#"{"type":"response","id":,"result":}"#.len() + digits(MAX_ID);

/// The largest result an operation takes: `{"answer":"…"}` around
/// fc-ledger's [`MAX_ANSWER`], 260 bytes, as 520 hex digits. 533 bytes.
/// `hash_only` comes only beside the 2-byte `6d00`, `{ failed }` is at
/// most `{"failed":"disconnected"}`, and main's error replies carry its
/// fixed messages (`{"code":"invalid_argument","message":"Invalid
/// argument","data":{"rule":"payload"}}`): each is shorter.
const LARGEST_RESULT: usize = r#"{"answer":""}"#.len() + 2 * MAX_ANSWER;

/// The most bytes main's reply to one `shell.ledger_apdu` takes,
/// serialized: [`ENVELOPE`] and [`LARGEST_RESULT`], 584 bytes. Each is sent
/// with it as its bound ([`crate::requests::Expect::reply_bound`]); past it,
/// whole or fragmented, the reply is a protocol error.
pub const REPLY_BOUND: usize = ENVELOPE + LARGEST_RESULT;

/// What the APDU a reply answers was, as far as `hash_only` goes (Q23):
/// the lane knows, as it sends each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    /// The operation's first `E0 1A`: a `6D00` to it may carry `hash_only:
    /// "shown"`, once main's hash-only warning is on screen.
    FirstDefinition,
    /// Any other APDU: `hash_only` is stray.
    Other,
}

/// A rule of main's grammar (design 0016, "What main checks"), named in
/// its refusal of an APDU. Main logs it; so does the core, never an APDU's
/// bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Parent,
    Order,
    Header,
    Count,
    Path,
    Payload,
    Ended,
}

impl Rule {
    pub const ALL: [Rule; 7] = [
        Rule::Parent,
        Rule::Order,
        Rule::Header,
        Rule::Count,
        Rule::Path,
        Rule::Payload,
        Rule::Ended,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Rule::Parent => "parent",
            Rule::Order => "order",
            Rule::Header => "header",
            Rule::Count => "count",
            Rule::Path => "path",
            Rule::Payload => "payload",
            Rule::Ended => "ended",
        }
    }

    fn parse(name: &str) -> Option<Rule> {
        Rule::ALL.into_iter().find(|rule| rule.as_str() == name)
    }
}

/// Main's reply to one `shell.ledger_apdu`, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answered {
    /// `{ answer }`, its bytes; `hash_only_shown` for `{ answer, hash_only:
    /// "shown" }`.
    Answer {
        answer: Vec<u8>,
        hash_only_shown: bool,
    },
    /// `{ failed }`: main couldn't exchange the APDU.
    Failed(Failed),
    /// `invalid_argument` with `data: { rule }`: main refused the APDU
    /// before the device. The operation ends `LEDGER_UNKNOWN`.
    Refused(Rule),
    /// `cancelled`: the answer to the core's cancel. The lane takes it only
    /// for an APDU it cancelled.
    Cancelled,
}

impl Answered {
    /// As the operation takes it; `None` for [`Answered::Cancelled`], which
    /// the lane ends itself.
    pub fn reply(&self) -> Option<Reply<'_>> {
        Some(match self {
            Answered::Answer {
                answer,
                hash_only_shown,
            } => Reply::Answer {
                answer,
                hash_only_shown: *hash_only_shown,
            },
            Answered::Failed(failed) => Reply::Failed(*failed),
            Answered::Refused(_) => Reply::Refused,
            Answered::Cancelled => return None,
        })
    }
}

/// Why a reply isn't one of `shell.ledger_apdu`'s: a protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Not one of the result's forms: not an object, an unknown, missing
    /// or repeated member, `answer` beside `failed`, or `hash_only` without
    /// `answer`.
    Form,
    /// A member of another type, or outside its set: `answer` that isn't a
    /// string of hex, `hash_only` other than `"shown"`, `failed` other than
    /// the five.
    Type,
    /// An answer outside 2 to 260 bytes.
    AnswerBounds,
    /// `hash_only` on any answer but a `6D00` to the operation's first
    /// `E0 1A`.
    HashOnly,
    /// An error other than main's two.
    Error,
}

impl Fault {
    /// Its category, for the protocol error's log line.
    pub fn category(self) -> &'static str {
        match self {
            Fault::Form => "ledger_reply_form",
            Fault::Type => "ledger_reply_type",
            Fault::AnswerBounds => "ledger_answer_bounds",
            Fault::HashOnly => "ledger_hash_only",
            Fault::Error => "ledger_reply_error",
        }
    }
}

/// Main's reply to one `shell.ledger_apdu` for an APDU `asked`: the text of
/// its `result` (`Ok`) or of its `error` (`Err`).
pub fn read(outcome: Result<&str, &str>, asked: Asked) -> Result<Answered, Fault> {
    match outcome {
        Ok(result) => read_result(result, asked),
        Err(error) => read_error(error),
    }
}

/// A member's value as it was written: `null` is present, of another type.
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<&'de RawValue>, D::Error> {
    <&'de RawValue>::deserialize(d).map(Some)
}

/// The result's members, each read whole first: a member it doesn't name,
/// or one written twice, isn't one of its forms.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Members<'a> {
    #[serde(borrow, default, deserialize_with = "present")]
    answer: Option<&'a RawValue>,
    #[serde(borrow, default, deserialize_with = "present")]
    hash_only: Option<&'a RawValue>,
    #[serde(borrow, default, deserialize_with = "present")]
    failed: Option<&'a RawValue>,
}

/// A member that must be a string.
fn string(raw: &RawValue) -> Result<String, Fault> {
    serde_json::from_str(raw.get()).map_err(|_| Fault::Type)
}

/// Hex digits, in pairs, either case, no prefix.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |b: u8| char::from(b).to_digit(16);
    let (pairs, odd) = text.as_bytes().as_chunks::<2>();
    if !odd.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[high, low]| u8::try_from(digit(high)? << 4 | digit(low)?).ok())
        .collect()
}

fn read_result(text: &str, asked: Asked) -> Result<Answered, Fault> {
    // serde's derived structs would also take an array of the members in
    // order, which isn't one of main's forms.
    if !text.trim_start().starts_with('{') {
        return Err(Fault::Form);
    }
    let members: Members<'_> = serde_json::from_str(text).map_err(|_| Fault::Form)?;
    match members {
        Members {
            answer: None,
            hash_only: None,
            failed: Some(failed),
        } => Failed::parse(&string(failed)?)
            .map(Answered::Failed)
            .ok_or(Fault::Type),
        Members {
            answer: Some(answer),
            hash_only,
            failed: None,
        } => {
            let answer = unhex(&string(answer)?).ok_or(Fault::Type)?;
            let shown = match hash_only {
                None => false,
                Some(raw) if string(raw)? == "shown" => true,
                Some(_) => return Err(Fault::Type),
            };
            if !(MIN_ANSWER..=MAX_ANSWER).contains(&answer.len()) {
                return Err(Fault::AnswerBounds);
            }
            if shown && (asked != Asked::FirstDefinition || answer != HASH_ONLY_ANSWER) {
                return Err(Fault::HashOnly);
            }
            Ok(Answered::Answer {
                answer,
                hash_only_shown: shown,
            })
        }
        _ => Err(Fault::Form),
    }
}

/// An error's `data` as it was written. Its other members are read by
/// [`ErrorBody`]; a `data` written twice is refused here, which a parse
/// into a map would keep only the last of.
#[derive(Deserialize)]
struct WrittenData<'a> {
    #[serde(borrow, default, deserialize_with = "present")]
    data: Option<&'a RawValue>,
}

/// A refusal's `data`: exactly `{ "rule": <string> }`, its member once.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusalData {
    rule: String,
}

fn read_error(text: &str) -> Result<Answered, Fault> {
    let raw: &RawValue = serde_json::from_str(text).map_err(|_| Fault::Error)?;
    let error = ErrorBody::from_raw(raw).map_err(|_| Fault::Error)?;
    match (error.code, error.data) {
        (ErrorCode::Cancelled, None) => Ok(Answered::Cancelled),
        (ErrorCode::InvalidArgument, Some(_)) => {
            // Read again as written, so that a member repeated in `data`,
            // or `data` itself repeated, is refused (Codex, round 1 on #518).
            let written: WrittenData<'_> = serde_json::from_str(text).map_err(|_| Fault::Error)?;
            let data = written.data.ok_or(Fault::Error)?;
            // serde's derived structs would also take an array in order.
            if !data.get().trim_start().starts_with('{') {
                return Err(Fault::Error);
            }
            let refusal: RefusalData =
                serde_json::from_str(data.get()).map_err(|_| Fault::Error)?;
            let rule = Rule::parse(&refusal.rule).ok_or(Fault::Error)?;
            Ok(Answered::Refused(rule))
        }
        _ => Err(Fault::Error),
    }
}

#[cfg(test)]
mod tests {
    use fc_ledger::{LedgerCode, LedgerPath, Operation, Scheme, Step};
    use fc_protocol::message::{self, Message};

    use super::*;

    const FAILED: [(&str, Failed); 5] = [
        ("not_found", Failed::NotFound),
        ("busy", Failed::Busy),
        ("disconnected", Failed::Disconnected),
        ("unresponsive", Failed::Unresponsive),
        ("timeout", Failed::Timeout),
    ];

    fn result(text: &str) -> Result<Answered, Fault> {
        read(Ok(text), Asked::Other)
    }

    fn answer(bytes: &[u8], shown: bool) -> Answered {
        Answered::Answer {
            answer: bytes.to_vec(),
            hash_only_shown: shown,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `text` as main sends it: a response at the largest ID, decoded as
    /// the core's reader decodes it, its result's or error's text read.
    fn through_the_wire(
        result: Result<serde_json::Value, ErrorBody>,
        asked: Asked,
    ) -> (usize, Result<Answered, Fault>) {
        let mut frame = Vec::new();
        match &result {
            Ok(value) => message::write_result(&mut frame, MAX_ID, value).unwrap(),
            Err(error) => message::write_error(&mut frame, MAX_ID, error).unwrap(),
        }
        let Message::Response { id, outcome } = Message::decode(&frame).unwrap() else {
            panic!("not a response");
        };
        assert_eq!(id, MAX_ID);
        let read = match outcome {
            Ok(result) => read(Ok(result.get()), asked),
            Err(error) => read(Err(error.raw().get()), asked),
        };
        (frame.len(), read)
    }

    #[test]
    fn a_well_formed_answer_reads_back() {
        // The smallest, a status word alone; the largest, 260 bytes; and
        // between, in either case.
        assert_eq!(
            result(r#"{"answer":"9000"}"#),
            Ok(answer(&[0x90, 0x00], false))
        );
        assert_eq!(
            result(r#"{"answer":"6985"}"#),
            Ok(answer(&[0x69, 0x85], false))
        );
        assert_eq!(
            result(r#"{"answer":"0A0b9000"}"#),
            Ok(answer(&[0x0a, 0x0b, 0x90, 0x00], false))
        );
        let largest: Vec<u8> = (0..=255).chain([1, 2, 0x90, 0x00]).collect();
        assert_eq!(largest.len(), MAX_ANSWER);
        assert_eq!(
            result(&format!(r#"{{"answer":"{}"}}"#, hex(&largest))),
            Ok(answer(&largest, false))
        );
        // Q23: a 6D00 to the operation's first E0 1A, the warning shown, in
        // either member order.
        for text in [
            r#"{"answer":"6d00","hash_only":"shown"}"#,
            r#"{"hash_only":"shown","answer":"6D00"}"#,
        ] {
            assert_eq!(
                read(Ok(text), Asked::FirstDefinition),
                Ok(answer(&HASH_ONLY_ANSWER, true)),
                "{text}"
            );
        }
        // Without it, the same 6D00 is an answer as any other: the
        // operation ends it LEDGER_UNKNOWN.
        assert_eq!(
            read(Ok(r#"{"answer":"6d00"}"#), Asked::FirstDefinition),
            Ok(answer(&HASH_ONLY_ANSWER, false))
        );
        // Through the wire, at the largest ID.
        let (_, read) = through_the_wire(
            Ok(serde_json::json!({ "answer": hex(&largest) })),
            Asked::Other,
        );
        assert_eq!(read, Ok(answer(&largest, false)));
    }

    #[test]
    fn a_failure_reads_back() {
        for (name, failed) in FAILED {
            assert_eq!(
                result(&format!(r#"{{"failed":"{name}"}}"#)),
                Ok(Answered::Failed(failed)),
                "{name}"
            );
            let (_, read) = through_the_wire(
                Ok(serde_json::json!({ "failed": name })),
                Asked::FirstDefinition,
            );
            assert_eq!(read, Ok(Answered::Failed(failed)), "{name}");
        }
        // Main's refusals: each rule, and the answer to a cancel.
        for rule in Rule::ALL {
            let error = ErrorBody::new(ErrorCode::InvalidArgument, "Invalid argument")
                .with_data(serde_json::json!({ "rule": rule.as_str() }));
            let (_, read) = through_the_wire(Err(error), Asked::Other);
            assert_eq!(read, Ok(Answered::Refused(rule)), "{rule:?}");
        }
        let (_, read) = through_the_wire(
            Err(ErrorBody::new(ErrorCode::Cancelled, "Cancelled")),
            Asked::Other,
        );
        assert_eq!(read, Ok(Answered::Cancelled));
    }

    /// What passes goes to the operation as fc-ledger's reply, which ends
    /// it with the device's status, main's failure or its refusal.
    #[test]
    fn what_passes_drives_the_operation() {
        let end = |reply: &Answered| {
            let path = LedgerPath::new(Scheme::Live, 0).unwrap();
            let mut add = Operation::add(path);
            assert!(matches!(add.start(), Step::Send(_)));
            match add.answer(reply.reply().unwrap()) {
                Step::Done(Err(failure)) => failure.code,
                other => panic!("{other:?}"),
            }
        };
        let rejected = result(r#"{"answer":"6985"}"#).unwrap();
        assert_eq!(end(&rejected), LedgerCode::UserRejected);
        for (name, failed) in FAILED {
            let read = result(&format!(r#"{{"failed":"{name}"}}"#)).unwrap();
            assert_eq!(end(&read), failed.code(), "{name}");
        }
        let refused = read(Err(r#"{"code":"invalid_argument","message":"Invalid argument","data":{"rule":"payload"}}"#), Asked::Other).unwrap();
        assert_eq!(refused.reply(), Some(Reply::Refused));
        assert_eq!(end(&refused), LedgerCode::Unknown);
        assert_eq!(Answered::Cancelled.reply(), None);
        let shown = answer(&HASH_ONLY_ANSWER, true);
        assert_eq!(
            shown.reply(),
            Some(Reply::Answer {
                answer: &HASH_ONLY_ANSWER,
                hash_only_shown: true
            })
        );
    }

    #[test]
    fn an_unknown_missing_or_repeated_member_is_refused() {
        for text in [
            r#"{"answer":"9000","extra":1}"#,
            r#"{"answer":"9000","hash_only":"shown","extra":null}"#,
            r#"{"failed":"busy","extra":"x"}"#,
            r#"{"Answer":"9000"}"#,
            r#"{"status":"9000"}"#,
            r#"{"answer":"9000","answer":"9000"}"#,
            r#"{"failed":"busy","failed":"busy"}"#,
            r#"{"answer":"6d00","hash_only":"shown","hash_only":"shown"}"#,
            // Not one form: both, neither, or hash_only alone.
            r#"{"answer":"9000","failed":"busy"}"#,
            r#"{"failed":"busy","hash_only":"shown"}"#,
            r#"{"hash_only":"shown"}"#,
            r#"{}"#,
            // Not an object: an array of the members in order is serde's
            // other form of a struct, never main's.
            r#"["9000"]"#,
            r#"["9000","shown",null]"#,
            r#""9000""#,
            "9000",
            "null",
            "true",
        ] {
            for asked in [Asked::Other, Asked::FirstDefinition] {
                assert_eq!(read(Ok(text), asked), Err(Fault::Form), "{text}");
            }
        }
    }

    #[test]
    fn every_members_wrong_type_is_refused() {
        let others = [
            "null",
            "true",
            "1",
            "-1",
            "1.5",
            "[]",
            "{}",
            r#"["9000"]"#,
            r#"{"answer":"9000"}"#,
        ];
        for other in others {
            for text in [
                format!(r#"{{"answer":{other}}}"#),
                format!(r#"{{"answer":"6d00","hash_only":{other}}}"#),
                format!(r#"{{"failed":{other}}}"#),
            ] {
                assert_eq!(
                    read(Ok(&text), Asked::FirstDefinition),
                    Err(Fault::Type),
                    "{text}"
                );
            }
        }
        // `answer`: a string of hex digits, in pairs, no prefix or space.
        for bad in [
            "900",
            "zz00",
            "0x9000",
            "90 00",
            "9000 ",
            "+900",
            "９０００",
            "90\\u0000",
        ] {
            let text = format!(r#"{{"answer":"{bad}"}}"#);
            assert_eq!(result(&text), Err(Fault::Type), "{text}");
        }
        // `hash_only`: only "shown".
        for bad in ["", "Shown", "SHOWN", "shown ", "hidden", "true"] {
            let text = format!(r#"{{"answer":"6d00","hash_only":"{bad}"}}"#);
            assert_eq!(
                read(Ok(&text), Asked::FirstDefinition),
                Err(Fault::Type),
                "{text}"
            );
        }
        // `failed`: only the five, as written.
        for bad in [
            "",
            "NotFound",
            "not-found",
            "BUSY",
            "stopped",
            "cancelled",
            "error",
            "too_large",
        ] {
            let text = format!(r#"{{"failed":"{bad}"}}"#);
            assert_eq!(result(&text), Err(Fault::Type), "{text}");
        }
    }

    #[test]
    fn an_answer_outside_2_to_260_bytes_is_refused() {
        for len in [0, 1, MAX_ANSWER + 1, MAX_ANSWER + 2, 300] {
            let text = format!(r#"{{"answer":"{}"}}"#, "90".repeat(len));
            assert_eq!(result(&text), Err(Fault::AnswerBounds), "{len}");
        }
        for len in [MIN_ANSWER, 3, MAX_ANSWER - 1, MAX_ANSWER] {
            let text = format!(r#"{{"answer":"{}"}}"#, "90".repeat(len));
            assert!(result(&text).is_ok(), "{len}");
        }
        // With hash_only too, the bound is checked first.
        assert_eq!(
            read(
                Ok(r#"{"answer":"6d","hash_only":"shown"}"#),
                Asked::FirstDefinition
            ),
            Err(Fault::AnswerBounds)
        );
    }

    #[test]
    fn a_stray_hash_only_is_refused() {
        // On a 6D00 to any APDU but the operation's first E0 1A.
        assert_eq!(
            read(Ok(r#"{"answer":"6d00","hash_only":"shown"}"#), Asked::Other),
            Err(Fault::HashOnly)
        );
        // On any other answer to the first E0 1A: another status, or a
        // 6D00 after data.
        for other in [
            "9000", "6e00", "6985", "6d01", "006d00", "01026d00", "6d009000",
        ] {
            let text = format!(r#"{{"answer":"{other}","hash_only":"shown"}}"#);
            for asked in [Asked::FirstDefinition, Asked::Other] {
                assert_eq!(
                    read(Ok(&text), asked),
                    Err(Fault::HashOnly),
                    "{text} {asked:?}"
                );
            }
        }
    }

    #[test]
    fn an_error_other_than_mains_two_is_refused() {
        for text in [
            // invalid_argument without its rule, with another, or with more.
            r#"{"code":"invalid_argument","message":"Invalid argument"}"#,
            r#"{"code":"invalid_argument","message":"Invalid argument","data":null}"#,
            r#"{"code":"invalid_argument","message":"Invalid argument","data":{}}"#,
            r#"{"code":"invalid_argument","message":"Invalid argument","data":"payload"}"#,
            r#"{"code":"invalid_argument","message":"Invalid argument","data":["payload"]}"#,
            r#"{"code":"invalid_argument","message":"Invalid argument","data":{"rule":"form"}}"#,
            r#"{"code":"invalid_argument","message":"Invalid argument","data":{"rule":"Payload"}}"#,
            r#"{"code":"invalid_argument","message":"Invalid argument","data":{"rule":1}}"#,
            r#"{"code":"invalid_argument","message":"Invalid argument","data":{"rule":null}}"#,
            r#"{"code":"invalid_argument","message":"Invalid argument","data":{"rule":"payload","apdu":"e0"}}"#,
            r#"{"code":"invalid_argument","message":"Invalid argument","data":{"reason":"payload"}}"#,
            // A member written twice: the rule, or data itself.
            r#"{"code":"invalid_argument","message":"Invalid argument","data":{"rule":"parent","rule":"payload"}}"#,
            r#"{"code":"invalid_argument","message":"Invalid argument","data":{"rule":"payload","rule":"payload"}}"#,
            r#"{"code":"invalid_argument","message":"Invalid argument","data":{"rule":"parent"},"data":{"rule":"payload"}}"#,
            // cancelled with data.
            r#"{"code":"cancelled","message":"Cancelled","data":{}}"#,
            r#"{"code":"cancelled","message":"Cancelled","data":{"rule":"ended"}}"#,
            // Main's other codes.
            r#"{"code":"internal","message":"Internal error"}"#,
            r#"{"code":"busy","message":"Busy"}"#,
            r#"{"code":"unknown_method","message":"Unknown method"}"#,
            r#"{"code":"timeout","message":"Timed out"}"#,
            r#"{"code":"device_failed","message":"x","data":{"ledger":"LEDGER_BUSY"}}"#,
            // Not 0001's error shape.
            r#"{"code":"cancelled"}"#,
            r#"{"code":"cancelled","message":1}"#,
            r#"{"code":"cancelled","message":"Cancelled","extra":1}"#,
            r#"{"code":"no_such_code","message":"x"}"#,
            r#"["cancelled","Cancelled"]"#,
            r#""cancelled""#,
        ] {
            assert_eq!(read(Err(text), Asked::Other), Err(Fault::Error), "{text}");
        }
    }

    /// 584 bytes: the largest answer's response at the largest ID, exactly;
    /// every other well-formed reply is shorter, main's error replies with
    /// their fixed messages included.
    #[test]
    fn the_reply_bound_is_the_largest_answers_response() {
        assert_eq!((ENVELOPE, LARGEST_RESULT, REPLY_BOUND), (51, 533, 584));
        let largest = hex(&[0xab; MAX_ANSWER]);
        let (len, read) =
            through_the_wire(Ok(serde_json::json!({ "answer": largest })), Asked::Other);
        assert_eq!((len, read.is_ok()), (REPLY_BOUND, true));
        // One byte more is past the answer's bound as well as the reply's.
        let (len, read) = through_the_wire(
            Ok(serde_json::json!({ "answer": hex(&[0xab; MAX_ANSWER + 1]) })),
            Asked::Other,
        );
        assert_eq!((len, read), (REPLY_BOUND + 2, Err(Fault::AnswerBounds)));
        let mut others = vec![
            Ok(serde_json::json!({ "answer": "6d00", "hash_only": "shown" })),
            Err(ErrorBody::new(ErrorCode::Cancelled, "Cancelled")),
        ];
        others.extend(FAILED.map(|(name, _)| Ok(serde_json::json!({ "failed": name }))));
        others.extend(Rule::ALL.map(|rule| {
            Err(
                ErrorBody::new(ErrorCode::InvalidArgument, "Invalid argument")
                    .with_data(serde_json::json!({ "rule": rule.as_str() })),
            )
        }));
        for other in others {
            let (len, read) = through_the_wire(other, Asked::FirstDefinition);
            assert!(read.is_ok() && len < REPLY_BOUND, "{len} {read:?}");
        }
    }

    #[test]
    fn each_fault_has_its_own_category() {
        let faults = [
            Fault::Form,
            Fault::Type,
            Fault::AnswerBounds,
            Fault::HashOnly,
            Fault::Error,
        ];
        for (i, a) in faults.iter().enumerate() {
            assert!(a.category().starts_with("ledger_"), "{a:?}");
            for b in &faults[i + 1..] {
                assert_ne!(a.category(), b.category());
            }
        }
        for rule in Rule::ALL {
            assert_eq!(Rule::parse(rule.as_str()), Some(rule));
        }
    }
}
