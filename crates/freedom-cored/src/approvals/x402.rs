//! x402 payments in the daemon (design 0012, "x402"; X402-1): the caps in
//! `x402-permissions.json`, the `x402-payment` token, and the authorization
//! the core builds and signs itself.
//!
//! - `x402.authorize { account, detection: { tab, id, url }, requirements,
//!   accept_index?, grant?, authorization }` (`shell`): the paid URL's
//!   origin is the cap's key (Q11). With `{ token }`, an `x402-payment`
//!   token pays exactly the entry (`accept_index`) and the grant it binds;
//!   with `{ cap: { agent, attributable } }`, the first entry an active cap
//!   covers is paid (`findCoveringPermission`), never for a tab in Agent
//!   custody or a request main couldn't attribute. The core builds the
//!   payload as `@x402/evm` 2.28.0 builds it (`fc_approval::x402`), with a
//!   nonce from the OS's RNG and `validBefore` from the wall clock, and
//!   signs it inline. **A cap is charged before the signature,** written
//!   first: a charge the file lacks signs nothing (`x402-at-sign`). A
//!   token's payment writes its grant after the signature, then charges a
//!   cap that covers it, as `sign-flow.js` does. The reply is `{ payload,
//!   reservation, accept_index, charged, grant? }`: `payload` the JSON
//!   main base64-encodes into the header.
//! - `x402.settle { reservation, outcome }` (`shell`): `withheld` gives the
//!   charge back to the cap it was taken from, if that cap still stands
//!   (not revoked, not granted again: its generation); `sent` keeps it.
//!   Either way the reservation is spent.
//! - Both answer `not_moved` until `x402` is in `grant_moved`, and change
//!   nothing: main still writes the file.
//!
//! Each change sends one `approval.changed { store: "x402", key }`.

use std::collections::{HashMap, VecDeque};

use fc_approval::stores::{CapStore, Charge, StoreKind};
use fc_approval::x402::{self, Payment, Requirements};
use fc_keys::Secp256k1Key;
use fc_vault::state::VaultState;
use rand_core::TryRng;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    Approvals, Clocks, ErrorBody, Kind, Minter, Request, invalid, json_reply, not_authorized,
    not_moved, object, refusal, secret_reply, string,
};
use crate::rng::OsRng;

/// The methods this module serves.
pub const METHODS: [&str; 2] = ["x402.authorize", "x402.settle"];

/// Reservations kept for `x402.settle`, the oldest dropped: a dropped
/// one's charge stands (*inferred*: as a Safe approval's count).
pub const MAX_RESERVATIONS: usize = 64;

/// A charge a reservation holds, and the generation of the cap it was taken
/// from.
#[derive(Debug)]
struct Held {
    charge: Charge,
    generation: u64,
}

/// What the daemon keeps beside the cap file: each cap's generation, which
/// tells a cap from one granted again under the same key (within one
/// second, its `createdAt` is the same), and the reservations.
#[derive(Default)]
pub(super) struct X402State {
    reservations: VecDeque<(Zeroizing<String>, Option<Held>)>,
    generations: HashMap<(String, String), u64>,
    last_generation: u64,
}

impl std::fmt::Debug for X402State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402State")
            .field("reservations", &self.reservations.len())
            .finish_non_exhaustive()
    }
}

impl X402State {
    /// Every cap read from the file is a cap of its own.
    pub(super) fn loaded(&mut self, store: &CapStore) {
        self.generations.clear();
        let caps: Vec<(String, String)> = store
            .caps()
            .map(|(origin, key, _)| (origin.to_owned(), key.to_owned()))
            .collect();
        for (origin, key) in caps {
            self.granted(&origin, &key);
        }
    }

    fn granted(&mut self, origin: &str, key: &str) -> u64 {
        self.last_generation += 1;
        self.generations
            .insert((origin.to_owned(), key.to_owned()), self.last_generation);
        self.last_generation
    }

    fn generation(&self, origin: &str, key: &str) -> Option<u64> {
        self.generations
            .get(&(origin.to_owned(), key.to_owned()))
            .copied()
    }

    pub(super) fn revoked(&mut self, origin: &str, key: Option<&str>) {
        self.generations
            .retain(|(o, k), _| o != origin || key.is_some_and(|key| key != k));
    }

    fn reserve(&mut self, held: Option<Held>) -> Result<Zeroizing<String>, ErrorBody> {
        let mut bytes = Zeroizing::new([0u8; 16]);
        OsRng
            .try_fill_bytes(&mut *bytes)
            .map_err(|_| crate::vault::internal())?;
        let id = Zeroizing::new(fc_evm::to_hex(&*bytes)[2..].to_owned());
        if self.reservations.len() == MAX_RESERVATIONS {
            self.reservations.pop_front();
        }
        self.reservations.push_back((id.clone(), held));
        Ok(id)
    }

    fn take(&mut self, id: &str) -> Option<Option<Held>> {
        let at = self
            .reservations
            .iter()
            .position(|(held, _)| held.as_bytes() == id.as_bytes())?;
        self.reservations.remove(at).map(|(_, held)| held)
    }
}

/// Signs a payment's digest. Every x402 signature goes through here, so a
/// test counts them (`FREEDOM_CORED_TEST_X402_SIGN_MARKER`; a no-op
/// without the `testhooks` feature).
fn sign(key: &Secp256k1Key, digest: &[u8; 32]) -> Result<[u8; 65], fc_evm::Error> {
    crate::testhooks::x402_signing();
    fc_evm::sign_digest(key.signing_key(), digest)
}

/// How the payment is authorized.
enum Authority {
    Token(Zeroizing<String>),
    Cap,
}

impl Approvals {
    /// `x402.authorize` and `x402.settle`. A presented token is burnt
    /// however the request ends, as `sign.*` burns one.
    pub fn x402_request(
        &mut self,
        state: &VaultState,
        id: u64,
        method: &str,
        params: &Value,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        match method {
            "x402.authorize" => {
                let presented = super::presented_token(params, true);
                let reply = self.x402_authorize(state, id, params, clocks);
                if let Some(token) = presented {
                    self.tokens.discard(&token);
                }
                reply
            }
            "x402.settle" => self.x402_settle(id, params),
            _ => Err(invalid("unknown method")),
        }
    }

    fn x402_authorize(
        &mut self,
        state: &VaultState,
        id: u64,
        params: &Value,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let fields = object(
            params,
            &["account", "detection", "requirements", "authorization"],
            &["accept_index", "grant"],
        )?;
        if !self.grants.moved(StoreKind::X402) {
            return Err(not_moved(StoreKind::X402));
        }
        let account = super::account(fields.get("account"), "account")?;
        let detection = object(&fields["detection"], &["tab", "id", "url"], &[])?;
        let origin = x402::cap_key(string(detection, "url")?)
            .ok_or_else(|| invalid("detection.url: x402 pays an http or https resource"))?;
        let requirements =
            Requirements::parse(&fields["requirements"]).map_err(|e| invalid(e.to_string()))?;
        let wall_s = clocks.wall_ms / 1000;
        let form = object(&fields["authorization"], &[], &["token", "cap"])?;
        let (authority, index) = match (form.get("token"), form.get("cap")) {
            (Some(_), None) => {
                let token = Zeroizing::new(string(form, "token")?.to_owned());
                let index = fields
                    .get("accept_index")
                    .and_then(Value::as_u64)
                    .and_then(|index| usize::try_from(index).ok())
                    .filter(|index| *index < requirements.accepts.len())
                    .ok_or_else(|| invalid("accept_index: no such entry"))?;
                (Authority::Token(token), index)
            }
            (None, Some(cap)) => {
                // Under a cap the core picks the entry, and no grant comes.
                if fields.contains_key("accept_index") || fields.contains_key("grant") {
                    return Err(invalid(
                        "accept_index and grant come only with an x402-payment token",
                    ));
                }
                let cap = object(cap, &["agent", "attributable"], &[])?;
                let flag = |name: &str| {
                    cap[name]
                        .as_bool()
                        .ok_or_else(|| invalid(format!("cap.{name}: expected a boolean")))
                };
                let (agent, attributable) = (flag("agent")?, flag("attributable")?);
                if agent {
                    return Err(not_authorized(
                        "custody",
                        "a cap pays nothing for a tab in Agent custody",
                    ));
                }
                if !attributable {
                    return Err(not_authorized(
                        "no_rule",
                        "a cap pays only for a request main attributes to a live tab",
                    ));
                }
                let store = self.grants.view::<CapStore>(wall_s);
                let (index, _) = store
                    .covering(&origin, requirements.accepts, wall_s)
                    .ok_or_else(|| not_authorized("cap", "no active cap covers this payment"))?;
                (Authority::Cap, index)
            }
            _ => {
                return Err(invalid(
                    "authorization: expected an x402-payment token or a cap",
                ));
            }
        };
        let accept = requirements.accepts[index].clone();
        let payment = Payment::new(requirements, index).map_err(|e| invalid(e.to_string()))?;
        let tuple = payment.tuple();
        // The token, after the public work: exactly this entry and grant,
        // for this tab, detection, URL and account.
        if let Authority::Token(token) = &authority {
            let mut payload = json!({
                "detection": fields["detection"],
                "accept_index": index,
                "accept": accept,
            });
            if let Some(grant) = fields.get("grant") {
                payload["grant"] = grant.clone();
            }
            self.tokens
                .spend_as(
                    Minter::Shell,
                    token,
                    &Request {
                        kind: Kind::X402Payment,
                        account: fields.get("account"),
                        payload: &payload,
                        page: None,
                    },
                    clocks.vault_ms,
                )
                .map_err(refusal)?;
        }
        // The key, for the address the authorization names; wiped on drop.
        let key = state
            .user_wallet(account)
            .map_err(crate::vault::locked_or_internal)?;
        let from = fc_evm::address_of(key.signing_key());
        let mut nonce = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(&mut *nonce)
            .map_err(|_| crate::vault::internal())?;
        let built = payment
            .build(&from, wall_s, &nonce)
            .map_err(|e| invalid(e.to_string()))?;
        // A cap's charge is written before anything is signed: one the file
        // lacks is not applied, and nothing is signed (`x402-at-sign`).
        let mut held = None;
        if let Authority::Cap = authority {
            let tuple = tuple
                .as_ref()
                .ok_or_else(|| not_authorized("cap", "no active cap covers this payment"))?;
            held = Some(
                self.charge(&origin, tuple, wall_s, true)?
                    .ok_or_else(|| not_authorized("cap", "no active cap covers this payment"))?,
            );
        }
        let signature = sign(&key, &built.digest).map_err(|_| crate::vault::internal())?;
        drop(key);
        let payload = built.payload(&signature);
        let mut durable = true;
        let mut grant_reply = None;
        if let Authority::Token(_) = authority {
            // The grant that came with the payment, as bound, after its
            // signature; then a cap that covers the payment is charged, the
            // one just granted included. The payment stands either way.
            if let (Some(grant), Some(tuple)) =
                (fields.get("grant").filter(|g| !g.is_null()), &tuple)
            {
                let (reply, flushed) = self.x402_grant(&origin, tuple, grant, wall_s);
                durable &= flushed;
                grant_reply = Some(reply);
            }
            if let Some(tuple) = &tuple {
                match self.charge(&origin, tuple, wall_s, false) {
                    Ok(charged) => held = charged,
                    // A narrowing that wasn't saved stands in memory; the
                    // reservation can't give it back.
                    Err(_) => durable = false,
                }
            }
        }
        let charged = held.is_some();
        if let Some(held) = &held {
            durable &= held.1;
        }
        let reservation = self.x402.reserve(held.map(|(held, _)| held))?;
        let payload = serde_json::value::RawValue::from_string(payload)
            .map_err(|_| crate::vault::internal())?;
        let mut reply = json!({
            "payload": payload,
            "reservation": reservation.as_str(),
            "accept_index": index,
            "charged": charged,
        });
        if let Some(grant) = grant_reply {
            reply["grant"] = grant;
        }
        if !durable {
            reply["durable"] = json!(false);
        }
        secret_reply(id, &reply, 0)
    }

    /// Charges the cap covering `tuple`'s amount. `before_signing`: the
    /// charge is applied only once written (`x402-at-sign`); otherwise, as
    /// any narrowing, it stands in memory when its write fails. The charge
    /// and whether its write was flushed.
    fn charge(
        &mut self,
        origin: &str,
        tuple: &x402::Tuple,
        wall_s: u64,
        before_signing: bool,
    ) -> Result<Option<(Held, bool)>, ErrorBody> {
        let key = tuple.key();
        let Some(generation) = self.x402.generation(origin, &key) else {
            return Ok(None);
        };
        let written = self.write::<CapStore, _>(origin, |store| {
            let mut applied = store.charge(origin, &key, &tuple.amount, wall_s);
            if before_signing && applied.value.is_some() {
                applied.effect = fc_approval::stores::Effect::Widening;
            }
            applied
        })?;
        Ok(written
            .value
            .map(|charge| (Held { charge, generation }, written.durable)))
    }

    /// The grant a token bound: `{ cap_amount, window_seconds }` for the
    /// paid entry's chain and asset, under the paid URL's origin. Its
    /// reply, and whether its write was flushed.
    fn x402_grant(
        &mut self,
        origin: &str,
        tuple: &x402::Tuple,
        grant: &Value,
        wall_s: u64,
    ) -> (Value, bool) {
        let key = tuple.key();
        let cap = grant
            .get("cap_amount")
            .and_then(Value::as_str)
            .unwrap_or("");
        let window = grant
            .get("window_seconds")
            .and_then(Value::as_f64)
            .unwrap_or(f64::NAN);
        let written = self.write::<CapStore, _>(origin, |store| {
            store.grant(origin, &key, cap, window, wall_s)
        });
        match written {
            Ok(written) if written.value.is_some() => {
                self.x402.granted(origin, &key);
                let mut reply = json!({ "added": true });
                if !written.durable {
                    reply["durable"] = json!(false);
                }
                (reply, written.durable)
            }
            Ok(_) => (json!({ "added": false, "reason": "invalid" }), true),
            Err(error) => {
                let reason = if error.code == fc_protocol::error::ErrorCode::Storage {
                    "not_saved"
                } else {
                    "bounds"
                };
                (json!({ "added": false, "reason": reason }), true)
            }
        }
    }

    fn x402_settle(&mut self, id: u64, params: &Value) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let fields = object(params, &["reservation", "outcome"], &[])?;
        if !self.grants.moved(StoreKind::X402) {
            return Err(not_moved(StoreKind::X402));
        }
        let withheld = match string(fields, "outcome")? {
            "withheld" => true,
            "sent" => false,
            _ => return Err(invalid("outcome: expected withheld or sent")),
        };
        let held = self
            .x402
            .take(string(fields, "reservation")?)
            .ok_or_else(|| invalid("reservation: unknown"))?;
        let Some(held) = held.filter(|_| withheld) else {
            return json_reply(id, &json!({ "refunded": false }));
        };
        // Only to the cap it was taken from: not one revoked or granted
        // again since.
        let Held { charge, generation } = held;
        if self.x402.generation(&charge.origin, &charge.key) != Some(generation) {
            return json_reply(id, &json!({ "refunded": false }));
        }
        let origin = charge.origin.clone();
        // A widening: one the file lacks isn't applied, and the charge
        // stands.
        let written = self.write::<CapStore, _>(&origin, |store| store.refund(&charge))?;
        let mut reply = json!({ "refunded": written.value });
        if !written.durable {
            reply["durable"] = json!(false);
        }
        json_reply(id, &reply)
    }
}
