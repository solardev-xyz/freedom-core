//! The core's prompts (design 0012, "fc-eip1193 and approval.request";
//! APR-5c): `approval.request`, the core-to-main request that asks main to
//! show one, and main's answer.
//!
//! - **A prompt's id** is 16 random bytes the core makes for it, written as
//!   32 lowercase hex digits (*inferred*). [`Prompts`] refuses bytes that
//!   name a prompt still live, and the caller draws again. A prompt is
//!   live from its issue to main's terminal answer, which retires it (or
//!   until the core forgets one it never sent). Ids are 16 random bytes
//!   and answers reach the core by its own request ids, never reused, so
//!   uniqueness needs only the live ids, not every id ever issued: a
//!   retired id comes back only by drawing the same 128 bits again
//!   (*inferred*).
//! - **Main's answer** is one of three (*inferred* in part):
//!   - `{ prompt, handle, approve, choices, world? }`: the decision made on
//!     the handle main opened for the prompt, which is 0011's 32 random
//!     bytes in lowercase hex. `world` is main's wallet state read as it
//!     answers, in `eip1193.request`'s form, and is required with an
//!     approve: what the reference reads again after its prompt (the
//!     account picked may have gone meanwhile).
//!   - `{ prompt, closed }`: the handle closed with no decision, `closed`
//!     being 0011's reason (`navigated`, `closed`, `cancelled` or
//!     `expired`);
//!   - `{ prompt, busy: true }`: the window already shows a wallet prompt,
//!     and no handle was opened.
//! - **The core checks it:** its `prompt` must be the prompt's own id, its
//!   handle well formed and one no earlier answer carried, and nothing else
//!   may be in it. Otherwise it is [`Crossed`], and the request fails with
//!   nothing signed and nothing granted. A handle is taken as seen once an
//!   answer carries it, whether that answer is accepted or not: one that
//!   has named a handle for one prompt never makes it count for another.
//! - **The [`MAX_HANDLES`] handles answers named most recently are
//!   kept** (*inferred*), a handle named again counting as named last, and
//!   the one named longest ago dropped. Main mints each handle from
//!   32 random bytes and never reuses one (0011), so the check guards
//!   against main's bugs, not its intent. At most 64 prompts are open and
//!   each cancelled one awaits one terminal answer, within main's 256
//!   slots for the core's requests: 4096 is well over the answers that
//!   can be in play at once. A handle dropped from the window could be
//!   accepted again only for an answer that names the current prompt's
//!   own id, after 4096 later answers named handles: a decision main
//!   relays for that prompt, as one with a fresh handle would be.

use std::collections::{BTreeSet, VecDeque};

use fc_json::JsValue;

use crate::request::{World, object};

/// A prompt's id: 16 random bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PromptId([u8; 16]);

impl PromptId {
    /// Its wire form: 32 lowercase hex digits.
    pub fn hex(&self) -> String {
        hex(&self.0)
    }
}

/// An answer that isn't main's decision on this prompt: refused, the
/// request fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crossed;

/// Main's decision on a prompt.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Approved on `handle`, with the user's picks and main's wallet state
    /// as it answered.
    Approve {
        choices: JsValue,
        world: World,
        handle: String,
    },
    /// Rejected on its handle.
    Reject,
    /// Its handle closed with no decision.
    Closed,
    /// The window already had a wallet prompt open (the page gets
    /// `-32002`).
    Busy,
}

/// 0011's reasons a handle closes without a decision.
const CLOSED: &[&str] = &["navigated", "closed", "cancelled", "expired"];

/// The most handles kept: those the latest answers named.
pub const MAX_HANDLES: usize = 4096;

/// The core's live prompt ids, and the handles main's latest answers named.
#[derive(Debug, Default)]
pub struct Prompts {
    live: BTreeSet<[u8; 16]>,
    handles: BTreeSet<String>,
    /// `handles`, oldest first.
    order: VecDeque<String>,
}

impl Prompts {
    pub fn new() -> Prompts {
        Prompts::default()
    }

    /// A new prompt's id from 16 random bytes: `None` when they name a
    /// live prompt, and the caller draws again.
    pub fn issue(&mut self, bytes: [u8; 16]) -> Option<PromptId> {
        self.live.insert(bytes).then_some(PromptId(bytes))
    }

    /// Prompt `id` was never sent: it is retired with no answer.
    pub fn forget(&mut self, id: &PromptId) {
        self.live.remove(&id.0);
    }

    /// What is kept: the live ids, and the handles.
    pub fn retained(&self) -> (usize, usize) {
        (self.live.len(), self.handles.len())
    }

    /// Main's terminal answer to prompt `id`, its `approval.request`'s
    /// result as JSON text: the decision, or [`Crossed`]. The prompt is
    /// retired either way, and a handle the answer names is seen.
    pub fn accept(&mut self, id: &PromptId, answer: &str) -> Result<Decision, Crossed> {
        self.live.remove(&id.0);
        let props = fc_json::parse(answer)
            .ok()
            .and_then(object)
            .ok_or(Crossed)?;
        let mut fields = Fields::default();
        for (key, value) in props {
            let slot = match key.as_str() {
                "prompt" => &mut fields.prompt,
                "handle" => &mut fields.handle,
                "approve" => &mut fields.approve,
                "choices" => &mut fields.choices,
                "world" => &mut fields.world,
                "closed" => &mut fields.closed,
                "busy" => &mut fields.busy,
                _ => return Err(Crossed),
            };
            *slot = Some(value);
        }
        // A handle counts as seen as soon as an answer names it.
        let named = match fields.handle.as_ref() {
            Some(handle) => {
                let handle = handle.as_str().filter(|h| is_handle(h)).ok_or(Crossed)?;
                if !self.remember(handle) {
                    return Err(Crossed);
                }
                Some(handle.to_owned())
            }
            None => None,
        };
        let handle = named.is_some();
        let prompt = fields.prompt.as_ref().and_then(JsValue::as_str);
        if prompt != Some(id.hex().as_str()) {
            return Err(Crossed);
        }
        match fields {
            Fields {
                approve: Some(JsValue::Bool(approve)),
                choices: Some(choices @ JsValue::Object(_)),
                world,
                closed: None,
                busy: None,
                ..
            } if handle => {
                if !approve {
                    return match world {
                        None => Ok(Decision::Reject),
                        Some(_) => Err(Crossed),
                    };
                }
                let world = World::from_value(world.ok_or(Crossed)?).map_err(|_| Crossed)?;
                Ok(Decision::Approve {
                    choices,
                    world,
                    handle: named.unwrap_or_default(),
                })
            }
            Fields {
                closed: Some(JsValue::String(ref reason)),
                approve: None,
                choices: None,
                world: None,
                busy: None,
                ..
            } if !handle && CLOSED.contains(&reason.as_str()) => Ok(Decision::Closed),
            Fields {
                busy: Some(JsValue::Bool(true)),
                approve: None,
                choices: None,
                world: None,
                closed: None,
                ..
            } if !handle => Ok(Decision::Busy),
            _ => Err(Crossed),
        }
    }
}

impl Prompts {
    /// Keeps `handle` as the latest, the oldest dropped past
    /// [`MAX_HANDLES`]: `false` when it is kept already, and it is the
    /// latest again.
    fn remember(&mut self, handle: &str) -> bool {
        let fresh = self.handles.insert(handle.to_owned());
        if !fresh {
            self.order.retain(|kept| kept != handle);
        }
        self.order.push_back(handle.to_owned());
        while self.order.len() > MAX_HANDLES {
            if let Some(oldest) = self.order.pop_front() {
                self.handles.remove(&oldest);
            }
        }
        fresh
    }
}

#[derive(Default)]
struct Fields {
    prompt: Option<JsValue>,
    handle: Option<JsValue>,
    approve: Option<JsValue>,
    choices: Option<JsValue>,
    world: Option<JsValue>,
    closed: Option<JsValue>,
    busy: Option<JsValue>,
}

/// 0011's handle: 32 random bytes in lowercase hex.
fn is_handle(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// `approval.recheck`'s answer (design 0012): `{ live, agent }`, read by
/// main just before an effect the core makes with no prompt. `live`: the
/// request's document is still there, holding its key; `agent`: its tab is
/// in Agent custody. Anything else is [`Crossed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recheck {
    pub live: bool,
    pub agent: bool,
}

impl Recheck {
    pub fn parse(answer: &str) -> Result<Recheck, Crossed> {
        let props = fc_json::parse(answer)
            .ok()
            .and_then(object)
            .ok_or(Crossed)?;
        let (mut live, mut agent) = (None, None);
        for (key, value) in props {
            let slot = match key.as_str() {
                "live" => &mut live,
                "agent" => &mut agent,
                _ => return Err(Crossed),
            };
            match value {
                JsValue::Bool(on) => *slot = Some(on),
                _ => return Err(Crossed),
            }
        }
        Ok(Recheck {
            live: live.ok_or(Crossed)?,
            agent: agent.ok_or(Crossed)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HANDLE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const WORLD: &str = r#"{"enabled":true,"wallets":[],"networks":{}}"#;

    fn issued(prompts: &mut Prompts, byte: u8) -> PromptId {
        prompts.issue([byte; 16]).unwrap()
    }

    fn handle(n: u8) -> String {
        format!("{:02x}{}", n, &HANDLE[2..])
    }

    #[test]
    fn an_id_is_never_issued_twice_while_live() {
        let mut prompts = Prompts::new();
        let id = issued(&mut prompts, 7);
        assert_eq!(id.hex(), "07".repeat(16));
        assert_eq!(prompts.issue([7; 16]), None);
        let other = issued(&mut prompts, 8);
        // Answered or forgotten, an id is retired.
        let busy = format!(r#"{{"prompt":"{}","busy":true}}"#, id.hex());
        assert_eq!(prompts.accept(&id, &busy), Ok(Decision::Busy));
        assert_eq!(prompts.retained(), (1, 0));
        prompts.forget(&other);
        assert_eq!(prompts.retained(), (0, 0));
        assert!(prompts.issue([7; 16]).is_some());
        let mut bytes = [0u8; 16];
        bytes[0] = 0xab;
        bytes[15] = 0x0c;
        assert_eq!(PromptId(bytes).hex(), "ab00000000000000000000000000000c");
    }

    #[test]
    fn each_answer_form_is_accepted_for_its_own_prompt() {
        let mut prompts = Prompts::new();
        let id = issued(&mut prompts, 1);
        let p = id.hex();
        let approve = format!(
            r#"{{"prompt":"{p}","handle":"{}","approve":true,"choices":{{"walletIndex":0}},"world":{WORLD}}}"#,
            handle(1)
        );
        match prompts.accept(&id, &approve) {
            Ok(Decision::Approve { choices, world, .. }) => {
                assert_eq!(choices.stringify(), r#"{"walletIndex":0}"#);
                assert!(world.enabled);
            }
            other => panic!("{other:?}"),
        }
        let reject = format!(
            r#"{{"prompt":"{p}","handle":"{}","approve":false,"choices":{{}}}}"#,
            handle(2)
        );
        assert_eq!(prompts.accept(&id, &reject), Ok(Decision::Reject));
        for reason in CLOSED {
            let closed = format!(r#"{{"prompt":"{p}","closed":"{reason}"}}"#);
            assert_eq!(prompts.accept(&id, &closed), Ok(Decision::Closed));
        }
        let busy = format!(r#"{{"prompt":"{p}","busy":true}}"#);
        assert_eq!(prompts.accept(&id, &busy), Ok(Decision::Busy));
    }

    #[test]
    fn another_prompts_id_or_a_handle_seen_before_is_crossed() {
        let mut prompts = Prompts::new();
        let first = issued(&mut prompts, 1);
        let second = issued(&mut prompts, 2);
        let answer = |prompt: &PromptId, handle: &str| {
            format!(
                r#"{{"prompt":"{}","handle":"{handle}","approve":false,"choices":{{}}}}"#,
                prompt.hex()
            )
        };
        // The other prompt's id: crossed, and its handle is seen from now on.
        assert_eq!(
            prompts.accept(&first, &answer(&second, &handle(1))),
            Err(Crossed)
        );
        assert_eq!(
            prompts.accept(&second, &answer(&second, &handle(1))),
            Err(Crossed)
        );
        // A handle accepted for one prompt is never accepted for another,
        // nor again for the same one.
        assert_eq!(
            prompts.accept(&first, &answer(&first, &handle(2))),
            Ok(Decision::Reject)
        );
        assert_eq!(
            prompts.accept(&second, &answer(&second, &handle(2))),
            Err(Crossed)
        );
        assert_eq!(
            prompts.accept(&first, &answer(&first, &handle(2))),
            Err(Crossed)
        );
        assert_eq!(
            prompts.accept(&second, &answer(&second, &handle(3))),
            Ok(Decision::Reject)
        );
    }

    #[test]
    fn a_malformed_answer_is_crossed() {
        let mut prompts = Prompts::new();
        let id = issued(&mut prompts, 0xab);
        let p = id.hex();
        let h = handle(9);
        for text in [
            String::from("[]"),
            String::from("null"),
            format!(r#"{{"prompt":"{}"}}"#, p),
            format!(r#"{{"prompt":"{}","busy":false}}"#, p),
            format!(r#"{{"prompt":"{}","closed":"decided"}}"#, p),
            format!(
                r#"{{"prompt":"{}","closed":"navigated","handle":"{h}"}}"#,
                p
            ),
            format!(r#"{{"prompt":"{}","busy":true,"closed":"closed"}}"#, p),
            format!(r#"{{"prompt":"{}","busy":true,"extra":1}}"#, p),
            format!(
                r#"{{"prompt":"{}","approve":true,"choices":{{}},"world":{WORLD}}}"#,
                p
            ),
            format!(
                r#"{{"prompt":"{}","handle":"{h}","approve":true,"choices":{{}}}}"#,
                p
            ),
            format!(
                r#"{{"prompt":"{}","handle":"{h}","approve":"yes","choices":{{}}}}"#,
                p
            ),
            format!(
                r#"{{"prompt":"{}","handle":"{h}","approve":true,"choices":[],"world":{WORLD}}}"#,
                p
            ),
            format!(
                r#"{{"prompt":"{}","handle":"{h}","approve":true,"world":{WORLD}}}"#,
                p
            ),
            format!(
                r#"{{"prompt":"{}","handle":"{h}","approve":false,"choices":{{}},"world":{WORLD}}}"#,
                p
            ),
            format!(
                r#"{{"prompt":"{}","handle":"{h}","approve":true,"choices":{{}},"world":{{}}}}"#,
                p
            ),
            format!(
                r#"{{"prompt":"{}","handle":"{h}","approve":true,"choices":{{}},"world":{WORLD},"busy":true}}"#,
                p
            ),
            format!(
                r#"{{"prompt":"{}","handle":"{}","approve":false,"choices":{{}}}}"#,
                p,
                h.to_uppercase()
            ),
            format!(
                r#"{{"prompt":"{}","handle":"{}","approve":false,"choices":{{}}}}"#,
                p,
                &h[1..]
            ),
            format!(r#"{{"prompt":"{}","busy":true}}"#, p.to_uppercase()),
            String::from(r#"{"prompt":1,"busy":true}"#),
            String::from(r#"{"busy":true}"#),
        ] {
            // A fresh handle each time where one is named, so only the form
            // decides.
            let mut fresh = Prompts::new();
            let id = fresh.issue([0xab; 16]).unwrap();
            assert_eq!(fresh.accept(&id, &text), Err(Crossed), "{text}");
        }
        let _ = prompts;
    }

    /// Many busy cycles while one prompt stays open keep one id and no
    /// handle; many decisions keep the latest MAX_HANDLES handles.
    #[test]
    fn what_is_kept_stays_bounded() {
        let mut prompts = Prompts::new();
        let open = issued(&mut prompts, 0xff);
        for n in 0..20_000u32 {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&n.to_be_bytes());
            let id = prompts.issue(bytes).unwrap();
            let busy = format!(r#"{{"prompt":"{}","busy":true}}"#, id.hex());
            assert_eq!(prompts.accept(&id, &busy), Ok(Decision::Busy));
        }
        assert_eq!(prompts.retained(), (1, 0));
        let named = |n: usize| format!("{n:064x}");
        let reject = |id: &PromptId, handle: &str| {
            format!(
                r#"{{"prompt":"{}","handle":"{handle}","approve":false,"choices":{{}}}}"#,
                id.hex()
            )
        };
        for n in 0..MAX_HANDLES + 100 {
            let id = issued(&mut prompts, 1);
            assert_eq!(
                prompts.accept(&id, &reject(&id, &named(n))),
                Ok(Decision::Reject)
            );
        }
        assert_eq!(prompts.retained(), (1, MAX_HANDLES));
        // The latest are refused again; one dropped from the window isn't.
        let id = issued(&mut prompts, 1);
        assert_eq!(
            prompts.accept(&id, &reject(&id, &named(MAX_HANDLES + 99))),
            Err(Crossed)
        );
        let id = issued(&mut prompts, 1);
        assert_eq!(prompts.accept(&id, &reject(&id, &named(100))), Err(Crossed));
        let id = issued(&mut prompts, 1);
        assert_eq!(
            prompts.accept(&id, &reject(&id, &named(0))),
            Ok(Decision::Reject)
        );
        assert_eq!(prompts.retained(), (1, MAX_HANDLES));
        let _ = open;
        // A handle named again is the latest again, from a fresh state: the
        // window filled, its oldest named again (crossed), one new handle,
        // and the oldest is still refused.
        let mut prompts = Prompts::new();
        for n in 0..MAX_HANDLES {
            let id = issued(&mut prompts, 1);
            assert_eq!(
                prompts.accept(&id, &reject(&id, &named(n))),
                Ok(Decision::Reject)
            );
        }
        for (n, expected) in [
            (0, Err(Crossed)),
            (MAX_HANDLES, Ok(Decision::Reject)),
            (0, Err(Crossed)),
        ] {
            let id = issued(&mut prompts, 1);
            assert_eq!(
                prompts.accept(&id, &reject(&id, &named(n))),
                expected,
                "{n}"
            );
        }
        assert_eq!(prompts.retained(), (0, MAX_HANDLES));
    }

    #[test]
    fn a_recheck_is_two_booleans() {
        assert_eq!(
            Recheck::parse(r#"{"live":true,"agent":false}"#),
            Ok(Recheck {
                live: true,
                agent: false
            })
        );
        for text in [
            r#"{"live":true}"#,
            r#"{"live":1,"agent":false}"#,
            r#"{"live":true,"agent":false,"x":1}"#,
            "[]",
        ] {
            assert_eq!(Recheck::parse(text), Err(Crossed), "{text}");
        }
    }
}
