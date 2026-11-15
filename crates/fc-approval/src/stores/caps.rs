//! `x402-permissions.json` (the reference's `x402/permissions.js`): its
//! codec, and the caps' operations (X402-1), with the asset's key in
//! lowercase ([`crate::x402::asset_key`], `x402-asset-case`).
//!
//! `origin → "<chainId>:<asset>" → { capAmount, spentAmount, createdAt,
//! expiresAt }`, amounts as decimal strings, times in wall-clock seconds.
//! The reference drops expired caps as it reads the file
//! (`compactExpired`), in memory, so the file loses them at its next write.

use fc_evm::U256;
use serde_json::Value;

use super::{
    Applied, Effect, JsString, JsValue, MAX_KEYS, Refused, Unreadable, object, parse, props,
    remove, text_of,
};
use crate::js;
use crate::x402::{Tuple, atomic, tuple};

/// The x402 cap store.
#[derive(Debug, Clone, PartialEq)]
pub struct CapStore {
    entries: JsValue,
}

impl Default for CapStore {
    fn default() -> Self {
        CapStore { entries: object() }
    }
}

impl CapStore {
    pub fn new() -> Self {
        CapStore::default()
    }

    /// The store as its file's bytes give it at `now_s` (the wall clock, in
    /// seconds), as the reference's `compactExpired` reads it: every cap
    /// for which `record?.expiresAt > now` holds, in the file's order, and
    /// every origin left with one. JS's coercions apply: an origin's caps
    /// are `Object.entries` of whatever the origin holds (an array's by
    /// index, nothing of a string's or a number's), and `expiresAt` goes
    /// through `ToNumber` (a numeric string is its number; a missing or
    /// non-numeric one is `NaN`, and the cap is dropped).
    ///
    /// A file past [`MAX_KEYS`] origins is unreadable however many of them
    /// compaction would drop. Where the reference's load throws (an
    /// origin's caps `null`, an `expiresAt` that can't be converted), and
    /// so reads the store as empty, the file is unreadable
    /// ([`Unreadable::LoadFails`]).
    pub fn load(bytes: &[u8], now_s: u64) -> Result<Self, Unreadable> {
        let file = parse(bytes)?;
        if props(&file).len() > MAX_KEYS {
            return Err(Unreadable::TooManyKeys);
        }
        Ok(CapStore {
            entries: compact(&file, now_s)?,
        })
    }

    /// The caps live at `now_s`, as `getAllPermissions` lists them from the
    /// store in memory: the reference's own compaction, kept caps' values
    /// as they are (an `Infinity` included, which its text would write as
    /// `null`).
    pub fn live(&self, now_s: u64) -> CapStore {
        CapStore {
            entries: compact(&self.entries, now_s).unwrap_or_else(|_| object()),
        }
    }

    pub fn text(&self) -> Result<String, Refused> {
        text_of(&self.entries)
    }

    /// Every cap as the file holds it: its origin, its `"<chainId>:<asset>"`
    /// key and its record, in the file's order.
    pub fn caps(&self) -> impl Iterator<Item = (&str, &str, &JsValue)> {
        props(&self.entries).iter().flat_map(|(origin, caps)| {
            props(caps)
                .iter()
                .map(move |(key, record)| (origin.as_str(), key.as_str(), record))
        })
    }
}

/// `compactExpired`: every cap for which `record?.expiresAt > now` holds,
/// in order, and every origin left with one.
fn compact(file: &JsValue, now_s: u64) -> Result<JsValue, Unreadable> {
    let now = now_s as f64;
    let mut entries = object();
    for (origin, caps) in props(file) {
        let mut active = object();
        for (key, record) in own_entries(caps)? {
            if live(&record, now)? {
                active.set(key, record);
            }
        }
        if !props(&active).is_empty() {
            entries.set(origin.clone(), active);
        }
    }
    Ok(entries)
}

/// A charge taken from a cap: given back to that cap alone
/// ([`CapStore::refund`]). The daemon pairs it with the cap's generation,
/// so a cap granted again since gets nothing back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Charge {
    pub origin: String,
    pub key: String,
    pub amount: String,
}

/// Why [`CapStore::narrow`] changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NarrowRefusal {
    /// No cap under the key.
    NoCap,
    /// A field that wouldn't narrow the cap: equal, wider, or not
    /// comparable with the cap's own value.
    NotNarrower,
}

/// A cap as a lookup reads it: its amounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cap {
    pub cap: U256,
    pub spent: U256,
}

impl CapStore {
    fn record(&self, origin: &str, key: &str) -> Option<&JsValue> {
        self.entries.get(origin)?.get(key)
    }

    /// The cap under `origin` and `key` (a [`crate::x402::asset_key`]) if it answers at
    /// `now_s` (`getPermission`): `createdAt <= now < expiresAt`, each
    /// through `ToNumber` (`NaN` answers nothing), so a wall clock set
    /// before `createdAt` expires it (`x402-clock-back`); and both amounts
    /// decimal digit strings, as the core writes them. Anything else
    /// answers nothing (*inferred*: the reference's `BigInt` takes more).
    pub fn active(&self, origin: &str, key: &str, now_s: u64) -> Option<Cap> {
        let record = self.record(origin, key)?;
        let JsValue::Object(_) = record else {
            return None;
        };
        let now = now_s as f64;
        let number = |field: &str| {
            record
                .get(field)
                .and_then(|value| js::to_number(value).ok())
                .unwrap_or(f64::NAN)
        };
        if !(number("createdAt") <= now && now < number("expiresAt")) {
            return None;
        }
        let amount = |field: &str| record.get(field).and_then(JsValue::as_str).and_then(atomic);
        Some(Cap {
            cap: amount("capAmount")?,
            spent: amount("spentAmount")?,
        })
    }

    /// `findCoveringPermission(origin, accepts)`: the first entry, in the
    /// seller's order, whose tuple an active cap covers, with what is left
    /// of it at least the entry's amount. An entry with a cap whose amount
    /// isn't atomic units ends the search with none, as the reference's
    /// `BigInt` throws there or its `charge` then refuses.
    pub fn covering(&self, origin: &str, accepts: &[Value], now_s: u64) -> Option<(usize, Tuple)> {
        for (index, accept) in accepts.iter().enumerate() {
            let Some(tuple) = tuple(accept) else {
                continue;
            };
            let Some(cap) = self.active(origin, &tuple.key(), now_s) else {
                continue;
            };
            let amount = atomic(&tuple.amount)?;
            let next = cap.spent.checked_add(&amount);
            if next.is_some_and(|next| next <= cap.cap) {
                return Some((index, tuple));
            }
        }
        None
    }

    /// `grant(origin, chainId, asset, capAmount, windowSeconds)`: a new cap,
    /// or one replacing the cap under the same key, `spentAmount` `"0"` and
    /// its window from `now_s`. `key` is a [`crate::x402::asset_key`]. Refused (none)
    /// for a `capAmount` that isn't decimal digits or a window that isn't a
    /// positive finite number, as the reference throws.
    pub fn grant(
        &mut self,
        origin: &str,
        key: &str,
        cap_amount: &str,
        window_seconds: f64,
        now_s: u64,
    ) -> Applied<Option<JsValue>> {
        if atomic(cap_amount).is_none() || !(window_seconds.is_finite() && window_seconds > 0.0) {
            return Applied::new(None, Effect::Unchanged);
        }
        let created = now_s as f64;
        let mut record = object();
        record.set("capAmount", JsValue::string(cap_amount));
        record.set("spentAmount", JsValue::string("0"));
        record.set("createdAt", JsValue::Number(created));
        record.set("expiresAt", JsValue::Number(created + window_seconds));
        let mut caps = match self.entries.get(origin) {
            Some(caps @ JsValue::Object(_)) => caps.clone(),
            _ => object(),
        };
        caps.set(key, record.clone());
        self.entries.set(origin, caps);
        Applied::new(Some(record), Effect::Widening)
    }

    /// `charge(origin, chainId, asset, amount)`: `amount` added to the
    /// cap's `spentAmount` if the cap answers at `now_s` and the sum stays
    /// within `capAmount`. A charge narrows the cap.
    pub fn charge(
        &mut self,
        origin: &str,
        key: &str,
        amount: &str,
        now_s: u64,
    ) -> Applied<Option<Charge>> {
        let not = Applied::new(None, Effect::Unchanged);
        let (Some(cap), Some(taken)) = (self.active(origin, key, now_s), atomic(amount)) else {
            return not;
        };
        let Some(next) = cap
            .spent
            .checked_add(&taken)
            .filter(|next| *next <= cap.cap)
        else {
            return not;
        };
        self.set_spent(origin, key, next);
        Applied::new(
            Some(Charge {
                origin: origin.to_owned(),
                key: key.to_owned(),
                amount: amount.to_owned(),
            }),
            Effect::Narrowing,
        )
    }

    /// `refund(charge)`: the charge given back to its cap, never below
    /// zero, whether or not the cap has expired since. Whether the cap is
    /// still the one charged is the daemon's to know (its generation).
    pub fn refund(&mut self, charge: &Charge) -> Applied<bool> {
        let record = self.record(&charge.origin, &charge.key);
        let spent = record
            .and_then(|record| record.get("spentAmount"))
            .and_then(JsValue::as_str)
            .and_then(atomic);
        let (Some(spent), Some(amount)) = (spent, atomic(&charge.amount)) else {
            return Applied::new(false, Effect::Unchanged);
        };
        let left = saturating_sub(spent, amount);
        if left == spent {
            return Applied::new(true, Effect::Unchanged);
        }
        self.set_spent(&charge.origin, &charge.key, left);
        Applied::new(true, Effect::Widening)
    }

    /// `{ ...record, spentAmount }`: replaced where it stands.
    fn set_spent(&mut self, origin: &str, key: &str, spent: U256) {
        if let Some(record) = self
            .entries
            .get_mut(origin)
            .and_then(|caps| caps.get_mut(key))
        {
            record.set("spentAmount", JsValue::string(spent.to_decimal()));
        }
    }

    /// `updatePermission(origin, chainId, asset, { capAmount?, windowSeconds? })`:
    /// the amount replaced, and `expiresAt` set to `createdAt +
    /// windowSeconds`; `spentAmount` kept. Refused (none) for a cap that
    /// isn't there, an amount that isn't decimal digits, a window that
    /// isn't a positive finite number, or a `createdAt` that isn't a
    /// number. It widens when the amount rises or the window ends later,
    /// and narrows otherwise. Widening needs a decision (`x402-widen`):
    /// no method reaches it before X402-2.
    pub fn update(
        &mut self,
        origin: &str,
        key: &str,
        cap_amount: Option<&str>,
        window_seconds: Option<f64>,
    ) -> Applied<Option<JsValue>> {
        let not = Applied::new(None, Effect::Unchanged);
        let Some(record) = self
            .record(origin, key)
            .filter(|r| matches!(r, JsValue::Object(_)))
        else {
            return not;
        };
        let mut next = record.clone();
        let mut widens = false;
        if let Some(cap_amount) = cap_amount {
            let Some(new) = atomic(cap_amount) else {
                return not;
            };
            let old = record
                .get("capAmount")
                .and_then(JsValue::as_str)
                .and_then(atomic);
            widens |= old.is_none_or(|old| new > old);
            next.set("capAmount", JsValue::string(cap_amount));
        }
        if let Some(window) = window_seconds {
            let Some(JsValue::Number(created)) = record.get("createdAt") else {
                return not;
            };
            if !(window.is_finite() && window > 0.0) {
                return not;
            }
            let expires = created + window;
            let old = record
                .get("expiresAt")
                .and_then(|value| js::to_number(value).ok())
                .unwrap_or(f64::NAN);
            // Later, or against an `expiresAt` that isn't a number.
            widens |= !matches!(
                expires.partial_cmp(&old),
                Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
            );
            next.set("expiresAt", JsValue::Number(expires));
        }
        if &next == record {
            return Applied::new(Some(next), Effect::Unchanged);
        }
        if let Some(slot) = self.entries.get_mut(origin).and_then(|c| c.get_mut(key)) {
            *slot = next.clone();
        }
        let effect = if widens {
            Effect::Widening
        } else {
            Effect::Narrowing
        };
        Applied::new(Some(next), effect)
    }

    /// A narrowing of the cap under `origin` and `key` (core #392, from the
    /// activity pane): `cap_amount` (decimal digits) strictly below the
    /// cap's `capAmount`, and `window_seconds` making `createdAt +
    /// window_seconds` strictly before its `expiresAt`, each when given. The
    /// record changes as `updatePermission` changes it: `capAmount`
    /// replaced, `expiresAt` set to `createdAt + windowSeconds`, the rest
    /// kept, in place.
    ///
    /// Refused, with the store unchanged, for no cap there
    /// ([`NarrowRefusal::NoCap`]), and for a field equal to the cap's, wider,
    /// or one the cap's values can't be compared with: an amount that isn't
    /// decimal digits, a `createdAt` that isn't a number, an `expiresAt`
    /// `ToNumber` makes `NaN` ([`NarrowRefusal::NotNarrower`]). The cap may
    /// be expired, or its clock set back: narrowing it changes nothing it
    /// answers.
    pub fn narrow(
        &mut self,
        origin: &str,
        key: &str,
        cap_amount: Option<&str>,
        window_seconds: Option<u64>,
    ) -> Result<Applied<Option<JsValue>>, NarrowRefusal> {
        let record = self
            .record(origin, key)
            .filter(|record| matches!(record, JsValue::Object(_)))
            .ok_or(NarrowRefusal::NoCap)?;
        let mut next = record.clone();
        if let Some(text) = cap_amount {
            let new = atomic(text).ok_or(NarrowRefusal::NotNarrower)?;
            let old = record
                .get("capAmount")
                .and_then(JsValue::as_str)
                .and_then(atomic)
                .ok_or(NarrowRefusal::NotNarrower)?;
            if new >= old {
                return Err(NarrowRefusal::NotNarrower);
            }
            next.set("capAmount", JsValue::string(text));
        }
        if let Some(window) = window_seconds {
            let Some(JsValue::Number(created)) = record.get("createdAt") else {
                return Err(NarrowRefusal::NotNarrower);
            };
            let old = record
                .get("expiresAt")
                .and_then(|value| js::to_number(value).ok())
                .unwrap_or(f64::NAN);
            let expires = created + window as f64;
            // Strictly sooner: `NaN` on either side is refused.
            let sooner = expires.partial_cmp(&old) == Some(std::cmp::Ordering::Less);
            if window == 0 || !sooner {
                return Err(NarrowRefusal::NotNarrower);
            }
            next.set("expiresAt", JsValue::Number(expires));
        }
        if cap_amount.is_none() && window_seconds.is_none() {
            return Err(NarrowRefusal::NotNarrower);
        }
        if let Some(slot) = self.entries.get_mut(origin).and_then(|c| c.get_mut(key)) {
            *slot = next.clone();
        }
        Ok(Applied::new(Some(next), Effect::Narrowing))
    }

    /// `revoke(origin, chainId, asset)`: the cap dropped, and its origin
    /// with its last cap. Whether there was one.
    pub fn revoke(&mut self, origin: &str, key: &str) -> Applied<bool> {
        let Some(caps) = self.entries.get_mut(origin) else {
            return Applied::new(false, Effect::Unchanged);
        };
        if remove(caps, key).is_none() {
            return Applied::new(false, Effect::Unchanged);
        }
        if props(caps).is_empty() {
            remove(&mut self.entries, origin);
        }
        Applied::new(true, Effect::Narrowing)
    }

    /// `revokeAllForOrigin(origin)`: every cap of the origin dropped.
    pub fn revoke_all(&mut self, origin: &str) -> Applied<bool> {
        if remove(&mut self.entries, origin).is_none() {
            return Applied::new(false, Effect::Unchanged);
        }
        Applied::new(true, Effect::Narrowing)
    }
}

/// `a - b`, or zero below it, as the reference clamps a refund.
fn saturating_sub(a: U256, b: U256) -> U256 {
    if b >= a {
        return U256::ZERO;
    }
    let (x, y) = (a.to_be_bytes(), b.to_be_bytes());
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(x[i]) - i16::from(y[i]) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        out[i] = d as u8;
    }
    U256::from_be_slice(&out).unwrap_or(U256::ZERO)
}

/// `Object.entries(value)` of an origin's caps: an object's own properties,
/// an array's items by index, a string's code units (none of which is a
/// record); none of a number or a boolean. `null` throws.
fn own_entries(value: &JsValue) -> Result<Vec<(JsString, JsValue)>, Unreadable> {
    Ok(match value {
        JsValue::Null | JsValue::Undefined => return Err(Unreadable::LoadFails),
        JsValue::Object(props) => props.clone(),
        JsValue::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, item)| (JsString::from(index.to_string()), item.clone()))
            .collect(),
        // A string's units are strings, whose `expiresAt` is undefined: none
        // is kept.
        JsValue::String(_) | JsValue::Number(_) | JsValue::Bool(_) => Vec::new(),
    })
}

/// `record?.expiresAt > now`, by JS's relational comparison: only an
/// object has an own `expiresAt`, which goes through `ToNumber`; `NaN`
/// compares false.
fn live(record: &JsValue, now: f64) -> Result<bool, Unreadable> {
    let JsValue::Object(_) = record else {
        return Ok(false);
    };
    let Some(expires) = record.get("expiresAt") else {
        return Ok(false);
    };
    let expires = js::to_number(expires).map_err(|_| Unreadable::LoadFails)?;
    Ok(expires > now)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const NOW_S: u64 = 1_762_000_000;

    /// A file of `origins` origins, each holding `caps` as its JSON text.
    fn file(origins: usize, caps: &str) -> String {
        let entries: Vec<String> = (0..origins)
            .map(|index| format!("\"https://site{index}.example\": {caps}"))
            .collect();
        format!("{{{}}}", entries.join(","))
    }

    fn expired() -> String {
        format!(
            "{{\"8453:0xa\": {{\"capAmount\": \"1\", \"spentAmount\": \"0\", \"createdAt\": 1, \"expiresAt\": {NOW_S}}}}}"
        )
    }

    const SITE: &str = "https://paid.example";

    fn granted(cap: &str, now_s: u64) -> (CapStore, String) {
        let key = crate::x402::asset_key(8453.0, "0xAbC");
        let mut store = CapStore::new();
        assert_eq!(
            store.grant(SITE, &key, cap, 60.0, now_s).effect,
            Effect::Widening
        );
        (store, key)
    }

    #[test]
    fn charges_within_the_cap_and_its_window() {
        let (mut store, key) = granted("100", NOW_S);
        assert_eq!(key, "8453:0xabc");
        // A clock set back before createdAt: nothing answers.
        assert_eq!(store.active(SITE, &key, NOW_S - 1), None);
        assert_eq!(store.charge(SITE, &key, "1", NOW_S - 1).value, None);
        let charged = store.charge(SITE, &key, "60", NOW_S);
        assert_eq!(charged.effect, Effect::Narrowing);
        assert!(charged.value.is_some());
        assert_eq!(store.charge(SITE, &key, "41", NOW_S).value, None);
        assert_eq!(store.charge(SITE, &key, "0x1", NOW_S).value, None);
        assert!(store.charge(SITE, &key, "40", NOW_S + 59).value.is_some());
        assert_eq!(store.active(SITE, &key, NOW_S + 60), None);
        let refund = store.refund(&charged.value.unwrap());
        assert_eq!((refund.value, refund.effect), (true, Effect::Widening));
        assert!(store.text().unwrap().contains("\"spentAmount\": \"40\""));
        // Never below zero.
        let big = Charge {
            origin: SITE.into(),
            key: key.clone(),
            amount: "1000".into(),
        };
        assert!(store.refund(&big).value);
        assert!(store.text().unwrap().contains("\"spentAmount\": \"0\""));
        assert_eq!(store.refund(&big).effect, Effect::Unchanged);
        assert_eq!(store.grant(SITE, &key, "1.5", 60.0, NOW_S).value, None);
        assert_eq!(store.grant(SITE, &key, "1", 0.0, NOW_S).value, None);
    }

    #[test]
    fn covering_in_the_seller_s_order() {
        let (store, _) = granted("100", NOW_S);
        let entry = |asset: &str, amount: &str| serde_json::json!({ "network": "eip155:8453", "asset": asset, "amount": amount });
        let pick = |accepts: &[Value]| store.covering(SITE, accepts, NOW_S).map(|(i, _)| i);
        assert_eq!(pick(&[entry("0xabc", "100")]), Some(0));
        assert_eq!(
            pick(&[entry("0xabc", "101"), entry("0xABC", "100")]),
            Some(1)
        );
        assert_eq!(pick(&[entry("0xdef", "1"), entry("0xabc", "1")]), Some(1));
        // An amount the charge can't take ends the search.
        assert_eq!(pick(&[entry("0xabc", "0x1"), entry("0xabc", "1")]), None);
        assert_eq!(
            store.covering("https://other.example", &[entry("0xabc", "1")], NOW_S),
            None
        );
    }

    #[test]
    fn updates_widen_or_narrow_and_revokes_narrow() {
        let (mut store, key) = granted("100", NOW_S);
        assert_eq!(
            store.update(SITE, &key, Some("50"), None).effect,
            Effect::Narrowing
        );
        assert_eq!(
            store.update(SITE, &key, Some("51"), None).effect,
            Effect::Widening
        );
        assert_eq!(
            store.update(SITE, &key, None, Some(30.0)).effect,
            Effect::Narrowing
        );
        assert_eq!(
            store.update(SITE, &key, None, Some(31.0)).effect,
            Effect::Widening
        );
        assert_eq!(
            store.update(SITE, &key, Some("51"), Some(31.0)).effect,
            Effect::Unchanged
        );
        assert_eq!(store.update(SITE, "1:0xabc", Some("1"), None).value, None);
        assert_eq!(store.update(SITE, &key, Some("x"), None).value, None);
        assert_eq!(store.revoke(SITE, "1:0xabc").effect, Effect::Unchanged);
        assert_eq!(store.revoke(SITE, &key).effect, Effect::Narrowing);
        assert_eq!(store.text().unwrap(), "{}");
        assert_eq!(store.revoke_all(SITE).effect, Effect::Unchanged);
        let (mut store, _) = granted("1", NOW_S);
        assert_eq!(store.revoke_all(SITE).effect, Effect::Narrowing);
        assert_eq!(store.text().unwrap(), "{}");
    }

    /// A narrowing lowers the amount, shortens the window, or both, each
    /// strictly; anything equal or wider, on either field, changes nothing.
    #[test]
    fn a_narrowing_only_narrows() {
        let (store, key) = granted("100", NOW_S);
        let text = store.text().unwrap();
        let narrowed = |amount: Option<&str>, window: Option<u64>| {
            let mut next = store.clone();
            let result = next.narrow(SITE, &key, amount, window);
            (result, next)
        };
        for (amount, window) in [
            (Some("100"), None),
            (Some("101"), None),
            (None, Some(60)),
            (None, Some(61)),
            (None, Some(0)),
            (Some("99"), Some(60)),
            (Some("100"), Some(59)),
            (Some("x"), None),
            (Some(""), None),
            (None, None),
        ] {
            let (result, next) = narrowed(amount, window);
            assert_eq!(
                result,
                Err(NarrowRefusal::NotNarrower),
                "{amount:?} {window:?}"
            );
            assert_eq!(next.text().unwrap(), text, "{amount:?} {window:?}");
        }
        let (result, next) = narrowed(Some("99"), None);
        let applied = result.unwrap();
        assert_eq!(applied.effect, Effect::Narrowing);
        let record = applied.value.unwrap();
        assert_eq!(
            record.get("capAmount").and_then(JsValue::as_str),
            Some("99")
        );
        assert_eq!(
            record.get("expiresAt"),
            Some(&JsValue::Number((NOW_S + 60) as f64))
        );
        assert_eq!(
            next.active(SITE, &key, NOW_S).unwrap().cap,
            U256::from_u64(99)
        );
        // In place, as updatePermission writes it.
        assert_eq!(next.text().unwrap(), text.replace("\"100\"", "\"99\""));
        let (result, next) = narrowed(None, Some(59));
        assert_eq!(result.unwrap().effect, Effect::Narrowing);
        assert!(next.active(SITE, &key, NOW_S + 58).is_some());
        assert!(next.active(SITE, &key, NOW_S + 59).is_none());
        let (result, next) = narrowed(Some("0"), Some(1));
        assert_eq!(result.unwrap().effect, Effect::Narrowing);
        let cap = next.active(SITE, &key, NOW_S).unwrap();
        assert_eq!((cap.cap, cap.spent), (U256::ZERO, U256::ZERO));
        // Another cap, another origin, or a record that isn't one: none.
        let mut other = store.clone();
        assert_eq!(
            other.narrow(SITE, "1:0xabc", Some("1"), None),
            Err(NarrowRefusal::NoCap)
        );
        assert_eq!(
            other.narrow("https://other.example", &key, Some("1"), None),
            Err(NarrowRefusal::NoCap)
        );
        let odd = "{\"o\": {\"1:0xa\": \"not a record\"}}";
        let mut odd = CapStore::load(odd.as_bytes(), NOW_S).unwrap();
        assert_eq!(
            odd.narrow("o", "1:0xa", Some("0"), None),
            Err(NarrowRefusal::NoCap)
        );
    }

    /// Values the cap holds that a narrowing can't be compared with refuse
    /// it; an expired cap, or one behind a clock set back, still narrows.
    #[test]
    fn a_narrowing_compares_with_what_the_cap_holds() {
        let cap = |amount: &str, created: &str, expires: &str| {
            let text = format!(
                "{{\"o\": {{\"1:0xa\": {{\"capAmount\": {amount}, \"spentAmount\": \"0\", \"createdAt\": {created}, \"expiresAt\": {expires}}}}}}}"
            );
            CapStore::load(text.as_bytes(), 100).unwrap()
        };
        let narrow = |mut store: CapStore, amount: Option<&str>, window: Option<u64>| {
            store.narrow("o", "1:0xa", amount, window).map(|a| a.effect)
        };
        let refused = Err(NarrowRefusal::NotNarrower);
        assert_eq!(
            narrow(cap("\"0x10\"", "1", "1000"), Some("1"), None),
            refused
        );
        assert_eq!(narrow(cap("10", "1", "1000"), Some("1"), None), refused);
        assert_eq!(
            narrow(cap("\"10\"", "\"1\"", "1000"), None, Some(5)),
            refused
        );
        assert_eq!(
            narrow(cap("\"10\"", "1", "\"1000\""), None, Some(5)),
            Ok(Effect::Narrowing)
        );
        // An `expiresAt` that isn't a number: the cap was dropped as read.
        assert_eq!(
            narrow(cap("\"10\"", "1", "\"abc\""), None, Some(5)),
            Err(NarrowRefusal::NoCap)
        );
        assert_eq!(
            narrow(cap("\"10\"", "1e400", "1e400"), None, Some(5)),
            refused
        );
        // A leading zero in the file is its number.
        assert_eq!(
            narrow(cap("\"010\"", "1", "1000"), Some("9"), None),
            Ok(Effect::Narrowing)
        );
        assert_eq!(
            narrow(cap("\"010\"", "1", "1000"), Some("10"), None),
            refused
        );
        // A narrowing reads no clock: a cap created after now (200 > 100)
        // narrows too.
        assert_eq!(
            narrow(cap("\"10\"", "200", "300"), Some("5"), Some(50)),
            Ok(Effect::Narrowing)
        );
    }

    #[test]
    fn the_key_bound_counts_before_compaction() {
        // Exactly 4,096 origins, every cap expired: read, and empty.
        let exact = CapStore::load(file(MAX_KEYS, &expired()).as_bytes(), NOW_S).unwrap();
        assert_eq!(exact.caps().count(), 0);
        assert_eq!(exact.text().unwrap(), "{}");
        // One more: unreadable, though compaction would leave none.
        assert_eq!(
            CapStore::load(file(MAX_KEYS + 1, &expired()).as_bytes(), NOW_S),
            Err(Unreadable::TooManyKeys)
        );
        // Origins whose caps aren't records, which compaction drops too.
        assert_eq!(
            CapStore::load(file(MAX_KEYS, "\"not caps\"").as_bytes(), NOW_S)
                .unwrap()
                .caps()
                .count(),
            0
        );
        assert_eq!(
            CapStore::load(file(MAX_KEYS + 1, "\"not caps\"").as_bytes(), NOW_S),
            Err(Unreadable::TooManyKeys)
        );
        // A repeated origin is one key, as JSON.parse holds it.
        let mut repeated = file(MAX_KEYS, &expired());
        repeated.insert_str(1, &format!("\"https://site0.example\": {},", expired()));
        assert!(CapStore::load(repeated.as_bytes(), NOW_S).is_ok());
    }

    #[test]
    fn expiry_coerced_as_js_compares_it() {
        let cap = |expires: &str| {
            format!(
                "{{\"o\": {{\"1:0xa\": {{\"capAmount\": \"1\", \"spentAmount\": \"0\", \"createdAt\": 1, \"expiresAt\": {expires}}}}}}}"
            )
        };
        let live = |expires: &str| {
            CapStore::load(cap(expires).as_bytes(), 100).map(|store| store.caps().count() == 1)
        };
        assert_eq!(live("\"101\""), Ok(true));
        assert_eq!(live("\"100\""), Ok(false));
        assert_eq!(live("[101]"), Ok(true));
        assert_eq!(live("\" 0x65 \""), Ok(true));
        assert_eq!(live("1e400"), Ok(true));
        assert_eq!(live("\"abc\""), Ok(false));
        assert_eq!(live("null"), Ok(false));
        assert_eq!(live("{}"), Ok(false));
        assert_eq!(live("{\"toString\": 1}"), Err(Unreadable::LoadFails));
        // An origin's caps as an array: its records by index.
        let array = "{\"o\": [{\"capAmount\": \"1\", \"spentAmount\": \"0\", \"createdAt\": 1, \"expiresAt\": 101}]}";
        let store = CapStore::load(array.as_bytes(), 100).unwrap();
        assert_eq!(
            store
                .caps()
                .map(|(origin, key, _)| (origin, key))
                .collect::<Vec<_>>(),
            [("o", "0")]
        );
        assert_eq!(
            CapStore::load(b"{\"o\": null}", 100),
            Err(Unreadable::LoadFails)
        );
    }
}
