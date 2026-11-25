//! SW-1's hold on the feed store (design 0015, "SW-1 in the core"): the
//! swarm thread's one copy of `swarm-feeds.json`, through which every
//! change goes, whoever asks for it (a method machine's
//! [`super::StoreWrite::Feeds`], the chrome's `swarm.identities`, a
//! permission manifest's projection).
//!
//! **The hold.** A raw SOC's machine runs SW-1 again, with the feed-grant
//! check, in the step that hands the signature to the vault, and asks for
//! the signature with [`super::SignSoc::hold`] naming the site's key. From
//! that ask until the vault answers, or the request ends (its cancel or
//! deadline), the thread holds the key here ([`Keeper::hold`],
//! [`Keeper::release`]). While a hold stands, the keeper defers exactly the
//! changes the design lists, those that could change the re-check's answer:
//! - another site's identity taking the held publisher index: a set with an
//!   explicit index ([`FeedChange::SetOriginEntry`], which the store's API
//!   keeps for parity and no method calls today);
//! - a change of the site's active identity: an activate, a set of the
//!   site's own entry, or a create or ensure that activates;
//! - a revoke of the site's feed grant.
//!
//! Every other change goes on. Deferred changes apply in their order once
//! no hold blocks them; one whose write fails fails for its own caller, and
//! the store stays as it was.
//!
//! **Allocation never repeats an index** (deviation `index-allocation`,
//! [`super::super::stores::feeds`]): a new publisher index is past every
//! stored one, so an allocation can't hand out a held index and is never
//! deferred.
//!
//! **Writes are durable before memory changes** (0013): a change is made on
//! a copy, the copy's text written with the caller's durable write, and the
//! copy kept only once the write succeeded. The write is synchronous on the
//! swarm thread (0001's `fsx::replace`), so no machine step ever sees a
//! change that isn't on disk, and none lands between a re-check and its
//! hold.

use std::collections::VecDeque;

use fc_json::{JsString, JsValue};

use crate::stores::StoreError;
use crate::stores::feeds::{APP_SCOPED, FeedChange, FeedStore};
use crate::stores::manifests::Projection;

/// A hold's handle, the swarm thread's (one per signature it waits for).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HoldId(pub u64);

/// A change's caller, the swarm thread's handle for whom to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ticket(pub u64);

/// A change made.
#[derive(Debug, Clone, PartialEq)]
pub struct ChangeAnswer {
    /// The store operation's answer.
    pub value: JsValue,
    /// What a permission manifest lets go of (`notifyManifestMutation`).
    pub detach: Option<Projection>,
}

/// Why a change wasn't made. Either way the store is as it was.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChangeError {
    /// The store refused it.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Its durable write failed, with the write's text.
    #[error("the feed store's write failed: {0}")]
    Write(JsString),
}

impl ChangeError {
    /// The text a caller reads: the reference's own refusal, `store_full`
    /// past the store's bound (design 0015, Budgets), or the write's.
    pub fn message(&self) -> JsString {
        match self {
            ChangeError::Store(StoreError::Thrown(thrown)) => {
                JsString::from(thrown.message.as_str())
            }
            ChangeError::Store(StoreError::Full) => JsString::from("store_full"),
            ChangeError::Write(text) => text.clone(),
        }
    }
}

/// What became of a change handed to [`Keeper::change`].
#[derive(Debug, Clone, PartialEq)]
pub enum Ran {
    /// Made, or refused, now.
    Applied(Result<ChangeAnswer, ChangeError>),
    /// Waiting for a hold to end: its answer comes from [`Keeper::release`].
    Deferred,
}

/// A held key: the site, and the app-scoped index its active identity had
/// when the hold began.
#[derive(Debug, Clone, PartialEq)]
struct Hold {
    id: HoldId,
    key: JsString,
    index: Option<JsValue>,
}

/// The feed store and SW-1's holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Keeper {
    store: FeedStore,
    holds: Vec<Hold>,
    deferred: VecDeque<(Ticket, FeedChange)>,
}

impl Keeper {
    pub fn new(store: FeedStore) -> Keeper {
        Keeper {
            store,
            holds: Vec::new(),
            deferred: VecDeque::new(),
        }
    }

    /// The store as it stands: what every request reads.
    pub fn store(&self) -> &FeedStore {
        &self.store
    }

    /// Holds standing.
    pub fn holds(&self) -> usize {
        self.holds.len()
    }

    /// Changes waiting for a hold to end.
    pub fn deferred(&self) -> usize {
        self.deferred.len()
    }

    /// Whether a standing hold defers `change`.
    pub fn defers(&self, change: &FeedChange) -> bool {
        self.holds
            .iter()
            .any(|hold| blocks(hold, change, &self.store))
    }

    /// Makes `change` now, or defers it while a hold could see it. `write`
    /// is the durable write of the store's text.
    pub fn change(
        &mut self,
        ticket: Ticket,
        change: FeedChange,
        now_ms: u64,
        write: &mut impl FnMut(&str) -> Result<(), JsString>,
    ) -> Ran {
        if self.defers(&change) {
            self.deferred.push_back((ticket, change));
            return Ran::Deferred;
        }
        Ran::Applied(self.apply(&change, now_ms, write))
    }

    /// Starts a hold on `key`, for the signature the thread now waits for.
    pub fn hold(&mut self, id: HoldId, key: JsString) {
        let index = self
            .store
            .active_origin_identity(&key)
            .filter(|identity| crate::stores::is_str(identity.get("mode"), APP_SCOPED))
            .and_then(|identity| match identity.get("publisherKeyIndex") {
                Some(index @ JsValue::Number(_)) => Some(index.clone()),
                _ => None,
            });
        self.holds.push(Hold { id, key, index });
    }

    /// Ends hold `id` (the vault answered, or the request ended), then makes
    /// the deferred changes no other hold blocks, in their order: the first
    /// one still blocked keeps its place and those after it. Answers each
    /// change made, for its caller.
    pub fn release(
        &mut self,
        id: HoldId,
        now_ms: u64,
        write: &mut impl FnMut(&str) -> Result<(), JsString>,
    ) -> Vec<(Ticket, Result<ChangeAnswer, ChangeError>)> {
        self.holds.retain(|hold| hold.id != id);
        let mut answers = Vec::new();
        while let Some((_, front)) = self.deferred.front() {
            if self.defers(front) {
                break;
            }
            let Some((ticket, change)) = self.deferred.pop_front() else {
                break;
            };
            answers.push((ticket, self.apply(&change, now_ms, write)));
        }
        answers
    }

    /// The change on a copy, written, then kept.
    fn apply(
        &mut self,
        change: &FeedChange,
        now_ms: u64,
        write: &mut impl FnMut(&str) -> Result<(), JsString>,
    ) -> Result<ChangeAnswer, ChangeError> {
        let mut next = self.store.clone();
        let changed = change.apply(&mut next, now_ms)?;
        if let Some(text) = &changed.write {
            write(text).map_err(ChangeError::Write)?;
        }
        self.store = next;
        Ok(ChangeAnswer {
            value: changed.value,
            detach: changed.detach,
        })
    }
}

/// Whether `hold` defers `change`: the design's three kinds, and nothing
/// else.
fn blocks(hold: &Hold, change: &FeedChange, store: &FeedStore) -> bool {
    let own = |key: &JsString| *key == hold.key;
    // `options.activate`, as the store reads it.
    let activate = |options: &JsValue| options.get("activate").cloned();
    match change {
        // The site's own entry set: its active identity is replaced.
        FeedChange::SetOriginEntry { key, .. } if own(key) => true,
        // Another site's identity at the held index: a set with an
        // explicit, app-scoped index equal to it.
        FeedChange::SetOriginEntry { data, .. } => hold.index.as_ref().is_some_and(|held| {
            crate::stores::is_str(data.get("identityMode"), APP_SCOPED)
                && data
                    .get("publisherKeyIndex")
                    .is_some_and(|index| crate::stores::strict_equals(index, held))
        }),
        FeedChange::ActivateIdentity { key, .. } => own(key),
        // A create activates unless `activate` is false and the site has an
        // active identity (a held site always has one).
        FeedChange::CreateAppScopedIdentity { key, options, .. }
        | FeedChange::CreateAppScopedIdentityAt { key, options, .. } => {
            own(key)
                && (activate(options) != Some(JsValue::Bool(false))
                    || !store.has_identity_mode(key))
        }
        // An ensure activates only with `activate: true`, or for a site
        // without an active identity.
        FeedChange::EnsureAntWalletIdentity { key, options, .. } => {
            own(key)
                && (activate(options) == Some(JsValue::Bool(true))
                    || !store.has_identity_mode(key))
        }
        FeedChange::RevokeFeedAccess { key, .. } => own(key),
        FeedChange::AllocatePublisherKeyIndex
        | FeedChange::GrantFeedAccess { .. }
        | FeedChange::SetFeed { .. }
        | FeedChange::UpdateFeedReference { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::stores::feeds::Source;

    const NOW: u64 = 1_767_225_600_123;

    fn store(text: &str) -> FeedStore {
        FeedStore::load(Some(text.as_bytes()), NOW, |_| false).store
    }

    fn key(s: &str) -> JsString {
        JsString::from(s)
    }

    /// Site `a` at app-scoped index 0, with its feed grant; the counter at
    /// 0, behind the held index (F-8).
    fn held_world() -> Keeper {
        Keeper::new(store(
            r#"{"version":2,"nextPublisherKeyIndex":0,"origins":{"a":{"activeIdentityId":"app-scoped:0","identities":{"app-scoped:0":{"id":"app-scoped:0","mode":"app-scoped","publisherKeyIndex":0},"bee-wallet":{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null}},"feedGranted":true,"grantedAt":1,"feeds":{}},"b":{"activeIdentityId":"bee-wallet","identities":{"bee-wallet":{"id":"bee-wallet","mode":"bee-wallet","publisherKeyIndex":null}},"feedGranted":true,"grantedAt":1,"feeds":{}}}}"#,
        ))
    }

    fn ok(_: &str) -> Result<(), JsString> {
        Ok(())
    }

    fn js(text: &str) -> JsValue {
        fc_json::parse(text).unwrap()
    }

    #[test]
    fn a_hold_defers_only_the_listed_changes() {
        let mut k = held_world();
        k.hold(HoldId(1), key("a"));
        let a = key("a");
        let b = key("b");
        let deferred = [
            FeedChange::SetOriginEntry {
                key: b.clone(),
                data: js(r#"{"identityMode":"app-scoped","publisherKeyIndex":0}"#),
            },
            FeedChange::SetOriginEntry {
                key: a.clone(),
                data: js(r#"{"identityMode":"bee-wallet"}"#),
            },
            FeedChange::ActivateIdentity {
                key: a.clone(),
                identity_id: js(r#""bee-wallet""#),
                source: Source::User,
            },
            FeedChange::CreateAppScopedIdentity {
                key: a.clone(),
                options: JsValue::Undefined,
                source: Source::User,
            },
            FeedChange::EnsureAntWalletIdentity {
                key: a.clone(),
                options: js(r#"{"activate":true}"#),
                source: Source::User,
            },
            FeedChange::RevokeFeedAccess {
                key: a.clone(),
                source: Source::User,
            },
        ];
        for change in &deferred {
            assert!(k.defers(change), "{change:?}");
        }
        let goes_on = [
            // Another index, or an allocated one.
            FeedChange::SetOriginEntry {
                key: b.clone(),
                data: js(r#"{"identityMode":"app-scoped","publisherKeyIndex":1}"#),
            },
            FeedChange::SetOriginEntry {
                key: b.clone(),
                data: js(r#"{"identityMode":"app-scoped"}"#),
            },
            FeedChange::AllocatePublisherKeyIndex,
            FeedChange::CreateAppScopedIdentity {
                key: b.clone(),
                options: JsValue::Undefined,
                source: Source::User,
            },
            // Not activating, or another site's.
            FeedChange::CreateAppScopedIdentity {
                key: a.clone(),
                options: js(r#"{"activate":false}"#),
                source: Source::User,
            },
            FeedChange::EnsureAntWalletIdentity {
                key: a.clone(),
                options: JsValue::Undefined,
                source: Source::User,
            },
            FeedChange::ActivateIdentity {
                key: b.clone(),
                identity_id: js(r#""bee-wallet""#),
                source: Source::User,
            },
            FeedChange::RevokeFeedAccess {
                key: b.clone(),
                source: Source::User,
            },
            FeedChange::GrantFeedAccess {
                key: a.clone(),
                source: Source::User,
            },
            FeedChange::SetFeed {
                key: a.clone(),
                name: key("blog"),
                data: js(r#"{"topic":"t"}"#),
            },
        ];
        for change in &goes_on {
            assert!(!k.defers(change), "{change:?}");
        }
    }

    #[test]
    fn deferred_changes_apply_in_order_once_no_hold_blocks_them() {
        let mut k = held_world();
        k.hold(HoldId(1), key("a"));
        k.hold(HoldId(2), key("a"));
        let revoke = FeedChange::RevokeFeedAccess {
            key: key("a"),
            source: Source::User,
        };
        let activate = FeedChange::ActivateIdentity {
            key: key("a"),
            identity_id: js(r#""bee-wallet""#),
            source: Source::User,
        };
        assert_eq!(k.change(Ticket(1), revoke, NOW, &mut ok), Ran::Deferred);
        assert_eq!(k.change(Ticket(2), activate, NOW, &mut ok), Ran::Deferred);
        // Another change goes on meanwhile.
        let grant_b = FeedChange::GrantFeedAccess {
            key: key("b"),
            source: Source::User,
        };
        assert!(matches!(
            k.change(Ticket(3), grant_b, NOW, &mut ok),
            Ran::Applied(Ok(_))
        ));
        // One hold ends; the other still blocks both.
        assert!(k.release(HoldId(1), NOW, &mut ok).is_empty());
        assert!(k.store().has_feed_grant(&key("a")));
        let answers = k.release(HoldId(2), NOW, &mut ok);
        let tickets: Vec<Ticket> = answers.iter().map(|(t, _)| *t).collect();
        assert_eq!(tickets, [Ticket(1), Ticket(2)]);
        assert!(!k.store().has_feed_grant(&key("a")));
        assert_eq!(
            k.store()
                .active_origin_identity(&key("a"))
                .and_then(|i| i.get("id").cloned()),
            Some(js(r#""bee-wallet""#))
        );
        assert_eq!((k.holds(), k.deferred()), (0, 0));
    }

    #[test]
    fn a_failed_write_changes_nothing() {
        let mut k = held_world();
        let before = k.store().clone();
        let mut fail = |_: &str| Err(JsString::from("disk full"));
        let revoke = FeedChange::RevokeFeedAccess {
            key: key("a"),
            source: Source::User,
        };
        let Ran::Applied(Err(err)) = k.change(Ticket(1), revoke, NOW, &mut fail) else {
            panic!("a failed write")
        };
        assert_eq!(err.message(), "disk full");
        assert_eq!(*k.store(), before);
        // A refused change writes nothing.
        let mut wrote = false;
        let refused = FeedChange::ActivateIdentity {
            key: key("a"),
            identity_id: js(r#""nope""#),
            source: Source::User,
        };
        let Ran::Applied(Err(err)) = k.change(Ticket(2), refused, NOW, &mut |_: &str| {
            wrote = true;
            Ok(())
        }) else {
            panic!("refused")
        };
        assert_eq!(err.message(), "Publisher identity not found: nope");
        assert!(!wrote);
        assert_eq!(*k.store(), before);
    }
}
