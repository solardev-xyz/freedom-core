//! JSON text read as `JSON.parse` reads it, for the values the signers take
//! (design 0002, Values): serde_json gives the structure, and every number
//! that isn't an exact integer is read again from its own spelling with
//! Rust's correctly rounded parser.
//!
//! serde_json's default parser rounds approximately, and its
//! `float_roundtrip` parser still misrounds some valid spellings: an integer
//! significand padded with zeros and a compensating exponent
//! (`45035996273704965` and 752 zeros, then `e-753`, is 2^52 + ½, which
//! `JSON.parse` rounds to 2^52), and halfway values below the smallest
//! subnormal (2^-1075 is 0 in JavaScript). A typed-data integer read
//! another way than ethers reads it would be signed as another value than
//! the approval UI shows (#87).

use fc_json::index::{Index, Kind, Value as Spanned};
use serde_json::{Number, Value};

use crate::Error;

fn invalid() -> Error {
    Error::Value("JSON".into())
}

/// Parses `text` as serde_json does, with each number that serde_json
/// doesn't hold as an exact integer read as `JSON.parse` reads it: the
/// double nearest its spelling, ties to even.
pub fn parse_json(text: &str) -> Result<Value, Error> {
    let mut value: Value = serde_json::from_str(text).map_err(|_| invalid())?;
    if has_inexact(&value) {
        // serde_json accepted the text, so the index's grammar (V8's, which
        // nests deeper) accepts it too.
        let index = Index::new(text).map_err(|_| invalid())?;
        correct(&mut value, index.root())?;
    }
    Ok(value)
}

/// Whether any number in `value` is held as a double: a spelling with a
/// fraction or an exponent, or an integer past 64 bits.
fn has_inexact(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.is_f64(),
        Value::Array(items) => items.iter().any(has_inexact),
        Value::Object(map) => map.values().any(has_inexact),
        Value::Null | Value::Bool(_) | Value::String(_) => false,
    }
}

/// Rereads every double in `value` from the span the same text gave it, in
/// one walk of the whole value. serde_json keeps a duplicate key's last
/// value, so a member is matched with the key's last span.
fn correct(value: &mut Value, spanned: Spanned<'_, '_>) -> Result<(), Error> {
    match value {
        Value::Number(n) if n.is_f64() => {
            if spanned.kind() != Kind::Number {
                return Err(invalid());
            }
            let exact: f64 = spanned.raw().parse().map_err(|_| invalid())?;
            *n = Number::from_f64(exact).ok_or_else(invalid)?;
        }
        Value::Array(items) => {
            if spanned.kind() != Kind::Array {
                return Err(invalid());
            }
            let mut children = spanned.children();
            for item in items.iter_mut() {
                correct(item, children.next().ok_or_else(invalid)?)?;
            }
        }
        Value::Object(map) => {
            if spanned.kind() != Kind::Object {
                return Err(invalid());
            }
            let mut last = std::collections::HashMap::new();
            for (key, member) in spanned.members() {
                let key: String = serde_json::from_str(key.raw()).map_err(|_| invalid())?;
                last.insert(key, member);
            }
            for (key, member) in map.iter_mut() {
                correct(member, *last.get(key).ok_or_else(invalid)?)?;
            }
        }
        Value::Number(_) | Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_take_their_correctly_rounded_value() {
        let one = |text: &str| parse_json(text).unwrap();
        // Exact integers stay as serde_json holds them.
        assert_eq!(
            one("9007199254740993"),
            Value::from(9_007_199_254_740_993u64)
        );
        assert_eq!(one("-5"), Value::from(-5));
        // A double's spelling is reread.
        assert_eq!(
            one("4503599627370496.5").as_f64(),
            Some(4_503_599_627_370_496.0)
        );
        let padded = format!("45035996273704965{}e-753", "0".repeat(752));
        assert_eq!(one(&padded).as_f64(), Some(4_503_599_627_370_496.0));
        assert_eq!(
            one(&format!("-{padded}")).as_f64(),
            Some(-4_503_599_627_370_496.0)
        );
        // Nested, in arrays, and under a duplicate key: the last one.
        let nested = format!(r#"{{"a":[1,{{"b":{padded}}}],"c":0.5,"c":{padded}}}"#);
        let value = one(&nested);
        assert_eq!(value["a"][1]["b"].as_f64(), Some(4_503_599_627_370_496.0));
        assert_eq!(value["c"].as_f64(), Some(4_503_599_627_370_496.0));
        // What serde_json refuses stays refused.
        assert!(parse_json("1e400").is_err());
        assert!(parse_json(r#""\ud800""#).is_err());
        assert!(parse_json("{").is_err());
    }
}
