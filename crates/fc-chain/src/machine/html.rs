//! `chain.html` (design 0006, `chain.html`): the `web3:` handler's read of
//! a contract's `html()` document, as a read on this machine, then today's
//! checks of the answer (`onchain-html.js`) with fc-dweb's codec: the size
//! check before any decode, ethers' ABI string rules, the UTF-8 check, the
//! 8 MiB cap and the hash; and the class the gate starts from.
//!
//! Everything the answer sizes is reserved against the request before it
//! is allocated (design 0005, Bounds): the string `JSON.parse` would make,
//! when its text has escapes; the decode's one buffer, which becomes the
//! document; and the trust's index. The document stays charged until its
//! reply is made.

use fc_dweb::{
    Class, HTML_SELECTOR, HtmlDocument, HtmlError, classify_trust, decode_html, decode_html_room,
};
use fc_json::index::Index;

use super::budget::Charge;
use super::config::quote;
use super::ctx::{Over, Req, reserve, within};
use super::error::{Prop, Thrown};
use super::read::{ReadAnswer, ReadOptions, read};

/// The `code` of today's error for a document over the limit
/// (`onchain-html.js`): main answers 413 for a core error with it, and for
/// nothing else.
pub const HTML_TOO_LARGE_CODE: &str = "ONCHAIN_APP_TOO_LARGE";

/// A document, and what the gate starts from.
#[derive(Debug)]
pub(crate) struct HtmlAnswer {
    pub html: String,
    /// `keccak256(utf8(html))`.
    pub hash: [u8; 32],
    pub source: &'static str,
    pub verified: bool,
    /// The read's trust label, with endpoint references.
    pub trust: Option<String>,
    pub class: Class,
    /// The document's charge, held until its reply is made.
    pub charge: Charge,
}

/// `handleOnchainAppRequest`'s read and decode: `eth_call` of `html()` at
/// `latest` on `contract` (the address as `ethers.getAddress` gives it,
/// which the driver checks), with trust, interactive for `origin`.
pub(crate) async fn html(req: &Req, contract: &str, origin: String) -> Result<HtmlAnswer, Thrown> {
    // `[{ to: app.address, data: HTML_SELECTOR }, 'latest']`, as
    // JSON.stringify writes it: the address's units, then its JSON (at most
    // six bytes a unit), then the params around it.
    let _params_room = reserve!(req.ctx, contract.len().saturating_mul(14) + 64);
    let params = format!(
        r#"[{{"to":{},"data":"{HTML_SELECTOR}"}},"latest"]"#,
        quote(contract)
    );
    let options = ReadOptions {
        include_trust: true,
        origin: Some(origin),
        ..ReadOptions::default()
    };
    let ReadAnswer {
        result,
        source,
        verified,
        trust,
    } = read(req, "eth_call", &params, &options).await?;
    // `chainResult?.result`: its JSON text, none for `undefined`.
    let json = result.as_deref().map_or("", |text| text.json());
    let (document, charge) = within!(decode(req, json)).map_err(html_error)?;
    // The answer's text goes before anything more is reserved.
    drop(result);
    let class = match trust.as_deref() {
        Some(text) => {
            let _index = reserve!(req.ctx, Index::heap_needed(text).unwrap_or(0));
            let index = Index::new(text).ok();
            classify_trust(index.as_ref().map(Index::root), verified)
        }
        None => classify_trust(None, verified),
    };
    Ok(HtmlAnswer {
        html: document.html,
        hash: document.hash,
        source,
        verified,
        trust,
        class,
        charge,
    })
}

/// The answer's `result` decoded as `decodeHtmlInWorker` does, from its
/// JSON text (empty for `undefined`), each allocation reserved first. The
/// document comes with its charge; `Err(Over)` when a reservation crosses
/// the budget.
fn decode(req: &Req, json: &str) -> Result<Result<(HtmlDocument, Charge), HtmlError>, Over> {
    // `typeof result !== 'string'`: `undefined`, or any other JSON value.
    let Some(inner) = json
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    else {
        return Ok(Err(HtmlError::Malformed));
    };
    // The string `JSON.parse` made: the text between the quotes when it has
    // no escape, else its units decoded into a buffer of the text's length,
    // which no escape decodes longer than it is written. A lone surrogate
    // becomes U+FFFD, which no check tells apart from it: one UTF-16 unit
    // to the size check, and no hex digit.
    let unescaped;
    let mut _unescaped_room = None;
    let text = if inner.contains('\\') {
        let Ok(index_room) = Index::heap_needed(json) else {
            return Ok(Err(HtmlError::Malformed));
        };
        let room = req.ctx.reserve(json.len().saturating_add(index_room))?;
        let Ok(index) = Index::new(json) else {
            return Ok(Err(HtmlError::Malformed));
        };
        let mut out = String::with_capacity(json.len());
        out.extend(char::decode_utf16(index.root().units()).map(|c| c.unwrap_or('\u{fffd}')));
        unescaped = out;
        _unescaped_room = Some(room);
        unescaped.as_str()
    } else {
        inner
    };
    let room = match decode_html_room(text) {
        Ok(room) => room,
        Err(error) => return Ok(Err(error)),
    };
    let mut charge = req.ctx.reserve(room)?;
    let document = match decode_html(text) {
        Ok(document) => document,
        Err(error) => return Ok(Err(error)),
    };
    // The buffer it was cut from, now the document's: within the room.
    charge.settle(document.html.capacity()).map_err(|()| Over)?;
    Ok(Ok((document, charge)))
}

/// Today's error for an answer that isn't served: its texts are
/// `onchain-html.js`'s, or ethers' short messages where ethers threw.
fn html_error(error: HtmlError) -> Thrown {
    let thrown = Thrown::error(&error.to_string());
    match error {
        HtmlError::TooLarge => thrown.with("code", Prop::string(HTML_TOO_LARGE_CODE)),
        _ => thrown,
    }
}
