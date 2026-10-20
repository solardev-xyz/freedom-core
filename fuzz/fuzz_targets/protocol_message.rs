//! fc-protocol's message decoder and secret fields, on one JSON payload.
//!
//! - `Message::decode` takes the whole input as a frame's payload, and an
//!   error response's body is parsed as its consumer would.
//! - `SecretBytes::from_raw` takes the input as one raw JSON token, and
//!   every member of a message's params, result or data. A field it
//!   accepts is canonical padded base64 of at most 256 KiB: encoding the
//!   bytes again gives back exactly the token.

#![no_main]

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use fc_protocol::message::Message;
use fc_protocol::secret::{MAX_SECRET_BYTES, SecretBytes};
use libfuzzer_sys::fuzz_target;
use serde_json::value::RawValue;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = Message::decode(data) {
        match message {
            Message::Request {
                params: Some(raw), ..
            }
            | Message::Event {
                data: Some(raw), ..
            }
            | Message::Response {
                outcome: Ok(raw), ..
            } => {
                if let Ok(members) = serde_json::from_str::<BTreeMap<String, &RawValue>>(raw.get())
                {
                    members.values().for_each(|raw| secret(raw));
                }
            }
            Message::Response {
                outcome: Err(error),
                ..
            } => {
                let _ = error.parse();
            }
            _ => {}
        }
    }
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(raw) = serde_json::from_str::<&RawValue>(text)
    {
        secret(raw);
    }
});

fn secret(raw: &RawValue) {
    let Ok(secret) = SecretBytes::from_raw(raw) else {
        return;
    };
    assert!(secret.as_bytes().len() <= MAX_SECRET_BYTES);
    let token = raw.get();
    let inner = token
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .expect("an accepted secret field is a JSON string");
    assert_eq!(
        STANDARD.encode(secret.as_bytes()),
        inner,
        "an accepted secret field isn't canonical base64"
    );
}
