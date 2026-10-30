//! Dweb transports for Freedom (design 0006, step 2): the request logic of
//! freedom-browser's `bzz:`, `ipfs:` and `ipns:` protocol handlers, and the
//! `web3:` handler's `html()` codec, with their behavior byte for byte.
//! `vectors/dweb.json`, produced by the pinned JS, is the contract.
//!
//! - **Plans** ([`open`]): a request becomes a [`Plan`] (a fetch, a
//!   redirect or an error), or a name to resolve first ([`Pending`]). That
//!   covers the URL and host canonicalization ([`cid_v0_to_v1_base32`],
//!   [`cid_v1_b58btc_to_base32`], [`ipns_mh_to_cid_v1_base36`], the
//!   name-host classifiers), the header policies, the retry and timer
//!   tables ([`retry`], [`timers`]) and the status mapping.
//! - **Response operations** ([`canonicalize_redirect`],
//!   [`strip_page_state`], [`strip_decoded_encoding`], [`SmallText`]): pure
//!   functions over a [`ResponseHead`], and a decider over the body's
//!   chunks.
//! - **`html()`** ([`decode_html`], [`classify`]): the size precheck, ethers'
//!   ABI string rules, the UTF-8 check, the 8 MiB cap, the hash and the
//!   gate's class. A caller that reserves memory before it is allocated
//!   (the chain machine's `chain.html`) learns the decode's one allocation
//!   first ([`decode_html_room`]) and classifies the trust as text, in
//!   place ([`classify_trust`]).
//! - **Verify plans** (design 0009): with verification on, a fetch for an
//!   external backend becomes a [`Verify`] plan, unless its content can't
//!   be verified (an encrypted Swarm reference, a DNSLink name, another
//!   inlined key type), when it stays a fetch, or, in strict mode, a 403.
//!   `vectors/dweb-verify-plans.json` is the contract.
//! - **Validation** ([`validate_plan`]): what main checks before it dials.
//!   It has no reference; its vectors are the design's.
//!
//! Where the core differs from today by design (each pinned by vectors):
//! `body-idle` (a 60 s bound on a pending read, in every plan),
//! `native-page-state` (`strip_page_state` runs on the native IPFS node's
//! answers too, which today pass unstripped), `plan-paths` (validation
//! refuses some targets today's handlers dial, judging paths as decoded
//! too) and `plan-headers` (validation refuses header values that aren't
//! RFC 9110 field values).
//!
//! The crate does no I/O: names are resolved, and bytes moved, by the caller.

mod bzz;
mod cid;
pub mod failure;
mod headers;
mod html;
mod ipfs;
mod js;
mod names;
mod open;
mod plan;
mod response;
pub mod store;
mod url;
mod validate;
pub mod verifier;
mod verify;

pub use bzz::{
    FORWARDED_REQUEST_HEADERS, SWARM_HEADERS, is_reference as is_swarm_reference,
    request_headers as bzz_request_headers,
};
pub use cid::{cid_v0_to_v1_base32, cid_v1_b58btc_to_base32, ipns_mh_to_cid_v1_base36};
pub use headers::Headers;
pub use html::{
    Class, HTML_SELECTOR, HtmlDocument, HtmlError, MAX_HTML_BYTES, classify, classify_trust,
    decode_html, decode_html_room, decode_html_value, exceeds_encoded_bound,
};
pub use ipfs::{
    KNOWN_GATEWAY_HOSTS, STRIPPED_REQUEST_HEADERS, is_navigation,
    request_headers as ipfs_request_headers,
};
pub use js::{decode_uri_component, is_js_whitespace, number as js_number};
pub use names::{
    Resolved, Resolver, Unplannable, is_dweb_name_host, is_ens_host, is_potential_ens_name,
    is_tezos_domain_host, join_published_path, name_system_label_for_host,
};
pub use open::{
    ANT_NOT_READY, GATEWAY_NOT_RUNNING, NATIVE_NOT_RUNNING, OpenError, Opening, Pending, Request,
    open,
};
pub use plan::{
    Ant, BODY_IDLE_MS, BZZ_HEADERS_MS, BZZ_RETRY_DELAYS_MS, BZZ_RETRY_STATUSES, Backend,
    ContentTrust, ErrorPlan, Fetch, Ipfs, NATIVE_HEADERS_MS, NATIVE_QUEUE_MS, Node, Plan, Redirect,
    ResponseOp, Retry, Root, Scheme, Timers, Trust, Verification, Verify, content_trust, retry,
    timers,
};
pub use response::{
    BZZ_REDIRECT_STATUSES, BodyAction, DECODED_ENCODING_HEADERS, PAGE_STATE_RESPONSE_HEADERS,
    Responded, ResponseHead, SMALL_TEXT_MAX, SmallText, SmallTextDecision, canonicalize_redirect,
    relabel, respond, rewrite_gateway_location, same_segment, small_text_length,
    strip_decoded_encoding, strip_page_state,
};
pub use validate::{ERROR_STATUSES, MAX_MESSAGE_UNITS, PlanRequest, Refusal, validate_plan};
pub use verify::{
    NameKind, STRICT_DNSLINK, STRICT_ENCRYPTED, STRICT_KEY, STRICT_MESSAGES, STRICT_OFF,
    STRICT_STATUS, STRICT_UNSUPPORTED, VERIFY_HEADERS_ANT, VERIFY_HEADERS_IPFS, canonical_cid,
    ipns_name_kind,
};
