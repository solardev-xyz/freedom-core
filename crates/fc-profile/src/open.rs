//! `resolveProfile`'s choice of profile, for `freedom-cored profile open`
//! (design 0013, 5.1): main parses argv, the `x-freedom-profile:` URL and the
//! environment, and passes what they name; this picks the profile in the
//! reference's order, registers it if needed, and marks it opened.
//!
//! What stays in main (`--profile-dir`, `FREEDOM_TEST_USER_DATA`, finding a
//! dev checkout) never reaches here.

use fc_json::JsValue;

use crate::catalog::{
    Ensured, Error, Options, Store, ensure_profile, find_index, load_catalog, profiles,
};
use crate::ids::{DEFAULT_PROFILE_ID, sanitize_value};
use crate::js::{self, prop};
use crate::{PROFILES_DIR, Style};

/// The profile `--runtime` (automation) opens.
pub const AUTOMATION_PROFILE_ID: &str = "automation";

/// What main's launch named, each `None` when absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenArgs {
    /// `--profile <id>`. Empty counts as absent, as `||` has it.
    pub profile: Option<String>,
    /// An `x-freedom-profile:` switch, with the id its URL names (empty when
    /// it names none, or more than one switch came).
    pub switch: Option<String>,
    /// `FREEDOM_PROFILE`. Empty counts as absent.
    pub env_profile: Option<String>,
    /// `--runtime`.
    pub runtime: bool,
}

/// The profile chosen.
#[derive(Debug, Clone, PartialEq)]
pub struct Opened {
    /// A switch to a profile already open: main hands over and exits.
    pub switch_only: bool,
    /// Its `profile.json`'s `id` and `displayName`, as `resolveProfile`
    /// returns them.
    pub id: JsValue,
    pub display_name: JsValue,
    /// Its directory, the catalog record's `dir`: main's `userData`.
    pub user_data_dir: String,
    pub catalog_path: String,
    /// Its `profile.json`, as written.
    pub metadata: JsValue,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OpenOutcome {
    Opened(Opened),
    /// An `x-freedom-profile:` switch to a profile that isn't registered or
    /// isn't open (`PROFILE_SWITCH_REJECTED`), with the reference's
    /// message. Nothing was written.
    SwitchRefused(String),
}

/// `resolveProfile`, from the catalog on: the choice is `--profile`, then a
/// switch (only to a registered profile that is open: `is_open(id, dir)`),
/// then `FREEDOM_PROFILE`, then `automation` for `--runtime` or the profile
/// opened last, then `default` or the first registered, then `default`.
/// A first run registers `default` first. Each opening but a switch sets
/// `lastOpenedAt` to `now`.
pub fn open(
    store: &mut dyn Store,
    app_root: &str,
    opts: &Options,
    args: &OpenArgs,
    now: &str,
    is_open: &mut dyn FnMut(&str, &str) -> bool,
) -> Result<OpenOutcome, Error> {
    let style = opts.style;
    // Read without failing, as the reference's helpers catch: an unreadable
    // catalog fails below, in ensure_profile.
    let catalog = load_catalog(store, app_root, style).ok();
    let records: &[JsValue] = catalog.as_ref().map_or(&[], profiles);

    let explicit = args.profile.as_deref().filter(|p| !p.is_empty());
    let switch_id = match (&args.switch, explicit) {
        (Some(id), None) => {
            let record = if id.is_empty() {
                None
            } else {
                find_index(records, id).map(|index| &records[index])
            };
            let dir = record.map(|record| prop(record, "dir"));
            let Some(dir) = dir.filter(JsValue::truthy) else {
                return Ok(OpenOutcome::SwitchRefused(
                    "Refused an x-freedom-profile switch to an unknown profile".into(),
                ));
            };
            let open = matches!(&dir, JsValue::String(dir) if is_open(id, dir));
            if !open {
                return Ok(OpenOutcome::SwitchRefused(format!(
                    "Refused an x-freedom-profile switch to \"{id}\", which is not open"
                )));
            }
            Some(id.clone())
        }
        _ => None,
    };

    let input = if let Some(id) = explicit.or(switch_id.as_deref()) {
        js::string(id)
    } else if let Some(id) = args.env_profile.as_deref().filter(|p| !p.is_empty()) {
        js::string(id)
    } else {
        let chosen = if args.runtime {
            js::string(AUTOMATION_PROFILE_ID)
        } else {
            last_opened(records)
        };
        js::or(chosen, || {
            js::or(fallback(records), || js::string(DEFAULT_PROFILE_ID))
        })
    };
    let id = sanitize_value(&input).map_err(|e| match e {
        Error::Malformed { .. } => Error::Malformed {
            path: crate::catalog::catalog_path(app_root, style),
        },
        other => other,
    })?;

    let opts = Options {
        default_profile_dir: Some(
            opts.default_profile_dir
                .clone()
                .filter(|dir| !dir.is_empty())
                .unwrap_or_else(|| default_profile_dir(app_root, opts.dev, style)),
        ),
        ..opts.clone()
    };
    if id != DEFAULT_PROFILE_ID && records.is_empty() {
        ensure_profile(store, app_root, &opts, DEFAULT_PROFILE_ID, false, now)?;
    }
    let Ensured {
        catalog_path,
        record,
        metadata,
    } = ensure_profile(store, app_root, &opts, &id, switch_id.is_none(), now)?;
    let user_data_dir = match record.get("dir") {
        Some(JsValue::String(dir)) => dir.as_str().to_owned(),
        _ => return Err(Error::Malformed { path: catalog_path }),
    };
    Ok(OpenOutcome::Opened(Opened {
        switch_only: switch_id.is_some(),
        id: prop(&metadata, "id"),
        display_name: prop(&metadata, "displayName"),
        user_data_dir,
        catalog_path,
        metadata,
    }))
}

/// The resolver's `defaultProfileDir`: `Profiles/default` in a dev build,
/// the app root itself in a packaged one.
pub(crate) fn default_profile_dir(app_root: &str, dev: bool, style: Style) -> String {
    if dev {
        style.join(&[app_root, PROFILES_DIR, DEFAULT_PROFILE_ID])
    } else {
        app_root.to_owned()
    }
}

/// `resolveLastOpenedProfileId`: the id of the record with the greatest
/// `lastOpenedAt` (by `>`; the first of equals), `null` for none.
fn last_opened(records: &[JsValue]) -> JsValue {
    let mut last: Option<(JsValue, JsValue)> = None;
    for record in records {
        if js::nullish(record) {
            continue;
        }
        let id = prop(record, "id");
        let opened = prop(record, "lastOpenedAt");
        if !id.truthy() || !opened.truthy() {
            continue;
        }
        let newer = match &last {
            None => true,
            Some((_, best)) => js::greater(&opened, best),
        };
        if newer {
            last = Some((id, opened));
        }
    }
    last.map_or(JsValue::Null, |(id, _)| id)
}

/// `resolveFallbackProfileId`: `default` while it is registered, otherwise
/// the first record's id, `null` for none.
fn fallback(records: &[JsValue]) -> JsValue {
    let ids: Vec<JsValue> = records
        .iter()
        .filter(|record| !js::nullish(record))
        .map(|record| prop(record, "id"))
        .filter(JsValue::truthy)
        .collect();
    if ids.iter().any(|id| js::is_str(id, DEFAULT_PROFILE_ID)) {
        return js::string(DEFAULT_PROFILE_ID);
    }
    ids.into_iter().next().unwrap_or(JsValue::Null)
}
