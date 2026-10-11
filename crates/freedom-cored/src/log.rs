//! JSON-lines logging to stderr, which main forwards to its own log.
//! Never log request or response bodies: only method names, IDs, durations
//! and error codes (design 0001).

use std::io::Write;

fn write(level: &str, message: &str, mut fields: serde_json::Value) {
    if !fields.is_object() {
        fields = serde_json::json!({});
    }
    if let Some(map) = fields.as_object_mut() {
        map.insert("level".into(), level.into());
        map.insert("msg".into(), message.into());
    }
    let mut stderr = std::io::stderr().lock();
    // Logging must never take the process down.
    let _ = serde_json::to_writer(&mut stderr, &fields);
    let _ = stderr.write_all(b"\n");
}

pub fn info(message: &str, fields: serde_json::Value) {
    write("info", message, fields);
}

pub fn warn(message: &str, fields: serde_json::Value) {
    write("warn", message, fields);
}

pub fn error(message: &str, fields: serde_json::Value) {
    write("error", message, fields);
}
