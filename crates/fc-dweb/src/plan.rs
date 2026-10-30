//! Plans (design 0006, "Plans"): what main asks the node and how it treats
//! the answer, a redirect answered without a node, or an error.

use fc_json::JsValue;

/// The URL schemes `dweb.open` plans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Bzz,
    Ipfs,
    Ipns,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bzz => "bzz",
            Self::Ipfs => "ipfs",
            Self::Ipns => "ipns",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "bzz" => Some(Self::Bzz),
            "ipfs" => Some(Self::Ipfs),
            "ipns" => Some(Self::Ipns),
            _ => None,
        }
    }
}

/// The Ant main will use for a `bzz:` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ant {
    Bundled,
    External,
}

impl Ant {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bundled => "bundled",
            Self::External => "external",
        }
    }
}

/// The IPFS node main will use for an `ipfs:` or `ipns:` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipfs {
    Native,
    Gateway,
}

impl Ipfs {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Gateway => "gateway",
        }
    }
}

/// Whether an external backend's content is verified (design 0009,
/// Verify plans): on and supported, off, or on for a gateway the probe
/// found without raw blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verification {
    #[default]
    Off,
    On,
    Unsupported,
}

/// The backend main names in `dweb.open`, as a reference with no URL: its
/// mode, and whether it is up. A backend that isn't up keeps its mode, so
/// the answer names what isn't running. An external backend also carries
/// its verification and the profile's strict mode (0009).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Ant {
        mode: Ant,
        up: bool,
        verify: Verification,
        strict: bool,
    },
    Ipfs {
        mode: Ipfs,
        up: bool,
        verify: Verification,
        strict: bool,
    },
}

impl Backend {
    /// An Ant backend without verification or strict mode.
    pub const fn ant(mode: Ant, up: bool) -> Self {
        Self::Ant {
            mode,
            up,
            verify: Verification::Off,
            strict: false,
        }
    }

    /// An IPFS backend without verification or strict mode.
    pub const fn ipfs(mode: Ipfs, up: bool) -> Self {
        Self::Ipfs {
            mode,
            up,
            verify: Verification::Off,
            strict: false,
        }
    }

    /// `{ ant: "bundled" | "external", up }` or `{ ipfs: "native" |
    /// "gateway", up }`, as `dweb.open` carries it, and, for an external
    /// backend, the members 0009 adds, each present only as `true`:
    /// `verify`, `unsupported` (a gateway's only, never with `verify`) and
    /// `strict`. No other key.
    pub fn from_value(value: &JsValue) -> Option<Self> {
        let JsValue::Object(props) = value else {
            return None;
        };
        let up = match value.get("up") {
            Some(JsValue::Bool(up)) => *up,
            _ => return None,
        };
        let flag = |key: &str| match value.get(key) {
            None => Some(false),
            Some(JsValue::Bool(true)) => Some(true),
            Some(_) => None,
        };
        let (verify, unsupported, strict) =
            (flag("verify")?, flag("unsupported")?, flag("strict")?);
        if props.len() != 2 + usize::from(verify) + usize::from(unsupported) + usize::from(strict) {
            return None;
        }
        let verification = match (verify, unsupported) {
            (false, false) => Verification::Off,
            (true, false) => Verification::On,
            (false, true) => Verification::Unsupported,
            (true, true) => return None,
        };
        let backend = if let Some(mode) = value.get("ant") {
            let mode = match mode.as_str()? {
                "bundled" => Ant::Bundled,
                "external" => Ant::External,
                _ => return None,
            };
            if unsupported || ((verify || strict) && mode != Ant::External) {
                return None;
            }
            Self::Ant {
                mode,
                up,
                verify: verification,
                strict,
            }
        } else {
            let mode = match value.get("ipfs")?.as_str()? {
                "native" => Ipfs::Native,
                "gateway" => Ipfs::Gateway,
                _ => return None,
            };
            if (verify || unsupported || strict) && mode != Ipfs::Gateway {
                return None;
            }
            Self::Ipfs {
                mode,
                up,
                verify: verification,
                strict,
            }
        };
        Some(backend)
    }

    /// The backend as `dweb.open` carries it: the node, `up`, then
    /// `verify`, `unsupported` and `strict` where they are true.
    pub fn to_value(self) -> JsValue {
        let (node, mode, up, verify, strict) = match self {
            Self::Ant {
                mode,
                up,
                verify,
                strict,
            } => ("ant", mode.as_str(), up, verify, strict),
            Self::Ipfs {
                mode,
                up,
                verify,
                strict,
            } => ("ipfs", mode.as_str(), up, verify, strict),
        };
        let mut props = vec![
            (node, JsValue::string(mode.to_owned())),
            ("up", JsValue::Bool(up)),
        ];
        match verify {
            Verification::On => props.push(("verify", JsValue::Bool(true))),
            Verification::Unsupported => props.push(("unsupported", JsValue::Bool(true))),
            Verification::Off => {}
        }
        if strict {
            props.push(("strict", JsValue::Bool(true)));
        }
        object(props)
    }

    /// Whether main can dial it now.
    pub fn up(self) -> bool {
        match self {
            Self::Ant { up, .. } | Self::Ipfs { up, .. } => up,
        }
    }

    /// Whether its content is verified (0009).
    pub fn verification(self) -> Verification {
        match self {
            Self::Ant { verify, .. } | Self::Ipfs { verify, .. } => verify,
        }
    }

    /// Whether the profile's strict mode is on (0009, Strict mode).
    pub fn strict(self) -> bool {
        match self {
            Self::Ant { strict, .. } | Self::Ipfs { strict, .. } => strict,
        }
    }

    /// The same backend with strict mode off: what validation ties a
    /// plan's target to, strict mode being checked on its own.
    pub(crate) fn without_strict(self) -> Self {
        match self {
            Self::Ant {
                mode, up, verify, ..
            } => Self::Ant {
                mode,
                up,
                verify,
                strict: false,
            },
            Self::Ipfs {
                mode, up, verify, ..
            } => Self::Ipfs {
                mode,
                up,
                verify,
                strict: false,
            },
        }
    }

    pub(crate) fn serves(self, scheme: Scheme) -> bool {
        matches!(
            (self, scheme),
            (Self::Ant { .. }, Scheme::Bzz) | (Self::Ipfs { .. }, Scheme::Ipfs | Scheme::Ipns)
        )
    }

    pub(crate) fn is_gateway(self) -> bool {
        matches!(
            self,
            Self::Ipfs {
                mode: Ipfs::Gateway,
                ..
            }
        )
    }
}

/// The plan's reference to the node: main maps it to the backend it named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Node {
    Ant,
    Ipfs,
}

impl Node {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ant => "ant",
            Self::Ipfs => "ipfs",
        }
    }
}

/// When main tries the request again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retry {
    /// Statuses that are tried again.
    pub statuses: Vec<u16>,
    /// Whether a thrown error is tried again.
    pub on_error: bool,
    /// Attempts in all, the first included.
    pub attempts: u32,
    /// The wait before each attempt after the first.
    pub delays_ms: Vec<u32>,
}

/// The request's clocks. `None` is no bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timers {
    /// Waiting for the node to take the request.
    pub queue_ms: Option<u32>,
    /// Waiting for the response headers, per attempt.
    pub headers_ms: Option<u32>,
    /// A read pending with no bytes (deviation `body-idle`).
    pub body_idle_ms: u32,
}

/// The response operations main runs, in order (design 0006, "Response
/// operations").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseOp {
    StripDecodedEncoding,
    StripPageState,
    CanonicalizeRedirect,
    SmallText,
}

impl ResponseOp {
    pub const ALL: [Self; 4] = [
        Self::StripDecodedEncoding,
        Self::StripPageState,
        Self::CanonicalizeRedirect,
        Self::SmallText,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::StripDecodedEncoding => "strip_decoded_encoding",
            Self::StripPageState => "strip_page_state",
            Self::CanonicalizeRedirect => "canonicalize_redirect",
            Self::SmallText => "small_text",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.as_str() == name)
    }
}

/// What the content's bytes rest on, for display only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentTrust {
    /// The bundled Ant validates the chunks it fetches; the native IPFS
    /// node hash-checks blocks.
    NodeAsserted,
    /// An external Ant, or an IPFS path gateway.
    Unverified,
    /// Every byte checked against the root (0009, Labels): a verify plan's
    /// promise.
    Verified,
    /// Checked, from a root an IPNS record or a feed's node asserts is the
    /// latest (0009, Labels).
    LatestAsserted,
}

impl ContentTrust {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NodeAsserted => "node_asserted",
            Self::Unverified => "unverified",
            Self::Verified => "verified",
            Self::LatestAsserted => "latest_asserted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    /// The name's trust level from naming; `None` for a hash host.
    pub name: Option<String>,
    pub content: ContentTrust,
}

/// What main asks the node, and how it treats the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    pub node: Node,
    /// The node-relative request target, as an HTTP client sends it.
    pub path: String,
    /// Lowercase names, sorted, as `Headers` iterates them.
    pub headers: Vec<(String, String)>,
    pub retry: Retry,
    pub timers: Timers,
    pub response: Vec<ResponseOp>,
    pub trust: Trust,
}

/// The reference a verify plan's walk starts from (0009, Verify plans).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Root {
    /// 64 hex digits.
    Swarm(String),
    /// A CIDv1 in lowercase base32.
    Ipfs(String),
    /// A libp2p-key name with an inlined Ed25519 key or a sha2-256
    /// multihash.
    Ipns(String),
}

impl Root {
    /// The key the plan writes it under.
    pub fn key(&self) -> &'static str {
        match self {
            Self::Swarm(_) => "swarm",
            Self::Ipfs(_) => "ipfs",
            Self::Ipns(_) => "ipns",
        }
    }

    pub fn reference(&self) -> &str {
        match self {
            Self::Swarm(r) | Self::Ipfs(r) | Self::Ipns(r) => r,
        }
    }
}

/// A verified fetch (0009, Verify plans): the root, the path below it, the
/// request's query, the headers the bundled node reads, and the backend's
/// tables, applied to each piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verify {
    pub node: Node,
    pub root: Root,
    /// Below the root: empty, or starting with `/`.
    pub path: String,
    /// The request URL's query, with its `?`, or empty.
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub retry: Retry,
    pub timers: Timers,
    pub response: Vec<ResponseOp>,
    pub trust: Trust,
}

/// A redirect answered without a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub status: u16,
    pub location: String,
    pub headers: Vec<(String, String)>,
}

/// An error answered without a node: a JSON body `{ code, message }`, with
/// the status as the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorPlan {
    pub status: u16,
    pub message: String,
}

impl ErrorPlan {
    pub(crate) fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// The response body: `JSON.stringify({ code, message })`.
    pub fn body(&self) -> String {
        object(vec![
            ("code", number(self.status)),
            ("message", JsValue::string(self.message.clone())),
        ])
        .stringify()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Fetch(Fetch),
    /// 0009's verified fetch, for `dweb.verify`.
    Verify(Verify),
    Redirect(Redirect),
    Error(ErrorPlan),
}

fn number(value: impl Into<f64>) -> JsValue {
    JsValue::Number(value.into())
}

fn object(props: Vec<(&str, JsValue)>) -> JsValue {
    JsValue::Object(props.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

fn pairs(headers: &[(String, String)]) -> JsValue {
    JsValue::Array(
        headers
            .iter()
            .map(|(n, v)| {
                JsValue::Array(vec![JsValue::string(n.clone()), JsValue::string(v.clone())])
            })
            .collect(),
    )
}

fn optional(value: Option<u32>) -> JsValue {
    value.map_or(JsValue::Null, number)
}

fn retry_value(retry: &Retry) -> JsValue {
    object(vec![
        (
            "statuses",
            JsValue::Array(retry.statuses.iter().map(|&s| number(s)).collect()),
        ),
        ("on_error", JsValue::Bool(retry.on_error)),
        ("attempts", number(retry.attempts)),
        (
            "delays_ms",
            JsValue::Array(retry.delays_ms.iter().map(|&d| number(d)).collect()),
        ),
    ])
}

fn timers_value(timers: &Timers) -> JsValue {
    object(vec![
        ("queue_ms", optional(timers.queue_ms)),
        ("headers_ms", optional(timers.headers_ms)),
        ("body_idle_ms", number(timers.body_idle_ms)),
    ])
}

fn response_value(response: &[ResponseOp]) -> JsValue {
    JsValue::Array(
        response
            .iter()
            .map(|op| JsValue::string(op.as_str().to_owned()))
            .collect(),
    )
}

fn trust_value(trust: &Trust) -> JsValue {
    object(vec![
        (
            "name",
            trust.name.clone().map_or(JsValue::Null, JsValue::string),
        ),
        (
            "content",
            JsValue::string(trust.content.as_str().to_owned()),
        ),
    ])
}

impl Plan {
    /// The plan as `dweb.open` returns it (design 0006, "Plans").
    pub fn to_value(&self) -> JsValue {
        match self {
            Self::Fetch(fetch) => object(vec![(
                "fetch",
                object(vec![
                    ("node", JsValue::string(fetch.node.as_str().to_owned())),
                    ("path", JsValue::string(fetch.path.clone())),
                    ("headers", pairs(&fetch.headers)),
                    ("retry", retry_value(&fetch.retry)),
                    ("timers", timers_value(&fetch.timers)),
                    ("response", response_value(&fetch.response)),
                    ("trust", trust_value(&fetch.trust)),
                ]),
            )]),
            Self::Verify(verify) => object(vec![(
                "verify",
                object(vec![
                    ("node", JsValue::string(verify.node.as_str().to_owned())),
                    (
                        "root",
                        object(vec![(
                            verify.root.key(),
                            JsValue::string(verify.root.reference().to_owned()),
                        )]),
                    ),
                    ("path", JsValue::string(verify.path.clone())),
                    ("query", JsValue::string(verify.query.clone())),
                    ("headers", pairs(&verify.headers)),
                    ("retry", retry_value(&verify.retry)),
                    ("timers", timers_value(&verify.timers)),
                    ("response", response_value(&verify.response)),
                    ("trust", trust_value(&verify.trust)),
                ]),
            )]),
            Self::Redirect(redirect) => object(vec![(
                "redirect",
                object(vec![
                    ("status", number(redirect.status)),
                    ("location", JsValue::string(redirect.location.clone())),
                    ("headers", pairs(&redirect.headers)),
                ]),
            )]),
            Self::Error(error) => object(vec![(
                "error",
                object(vec![
                    ("status", number(error.status)),
                    ("code", number(error.status)),
                    ("message", JsValue::string(error.message.clone())),
                ]),
            )]),
        }
    }

    /// [`Plan::to_value`] as JSON text.
    pub fn to_json(&self) -> String {
        self.to_value().stringify()
    }
}

// ---------------------------------------------------------------------------
// Today's values, per scheme and backend

/// `bzz-protocol.js` `RETRY_DELAYS_MS`: about 50 s of back-off in all.
pub const BZZ_RETRY_DELAYS_MS: [u32; 9] = [500, 1000, 2000, 3000, 5000, 5000, 10000, 10000, 15000];
/// `bzz-protocol.js` `RETRYABLE_STATUSES`.
pub const BZZ_RETRY_STATUSES: [u16; 4] = [500, 502, 503, 504];
/// `bzz-protocol.js` `ATTEMPT_TIMEOUT_MS`: to the headers, per attempt.
pub const BZZ_HEADERS_MS: u32 = 30_000;
/// `freedom-ipfs-native-node.js` `REQUEST_QUEUE_TIMEOUT_MS`.
pub const NATIVE_QUEUE_MS: u32 = 15_000;
/// `freedom-ipfs-native-node.js` `ATTEMPT_TIMEOUT_MS`.
pub const NATIVE_HEADERS_MS: u32 = 30_000;
/// Design 0006, deviation `body-idle`: new for every backend.
pub const BODY_IDLE_MS: u32 = 60_000;

/// The retry table: `bzz:` retries, IPFS doesn't.
pub fn retry(backend: Backend) -> Retry {
    match backend {
        Backend::Ant { .. } => Retry {
            statuses: BZZ_RETRY_STATUSES.to_vec(),
            on_error: true,
            attempts: 1 + BZZ_RETRY_DELAYS_MS.len() as u32,
            delays_ms: BZZ_RETRY_DELAYS_MS.to_vec(),
        },
        Backend::Ipfs { .. } => Retry {
            statuses: Vec::new(),
            on_error: false,
            attempts: 1,
            delays_ms: Vec::new(),
        },
    }
}

/// The timer table. The external IPFS gateway has no bound to the headers,
/// only the page's abort.
pub fn timers(backend: Backend) -> Timers {
    match backend {
        Backend::Ant { .. } => Timers {
            queue_ms: None,
            headers_ms: Some(BZZ_HEADERS_MS),
            body_idle_ms: BODY_IDLE_MS,
        },
        Backend::Ipfs {
            mode: Ipfs::Native, ..
        } => Timers {
            queue_ms: Some(NATIVE_QUEUE_MS),
            headers_ms: Some(NATIVE_HEADERS_MS),
            body_idle_ms: BODY_IDLE_MS,
        },
        Backend::Ipfs {
            mode: Ipfs::Gateway,
            ..
        } => Timers {
            queue_ms: None,
            headers_ms: None,
            body_idle_ms: BODY_IDLE_MS,
        },
    }
}

/// The content label for a backend.
pub fn content_trust(backend: Backend) -> ContentTrust {
    match backend {
        Backend::Ant {
            mode: Ant::External,
            ..
        }
        | Backend::Ipfs {
            mode: Ipfs::Gateway,
            ..
        } => ContentTrust::Unverified,
        Backend::Ant {
            mode: Ant::Bundled, ..
        }
        | Backend::Ipfs {
            mode: Ipfs::Native, ..
        } => ContentTrust::NodeAsserted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(text: &str) -> Option<Backend> {
        Backend::from_value(&fc_json::parse(text).ok()?)
    }

    #[test]
    fn backends_read_strictly() {
        assert_eq!(
            backend(r#"{"ipfs":"gateway","up":false}"#),
            Some(Backend::ipfs(Ipfs::Gateway, false))
        );
        assert_eq!(
            backend(r#"{"up":true,"ant":"external"}"#),
            Some(Backend::ant(Ant::External, true))
        );
        assert_eq!(
            backend(r#"{"ant":"external","up":true,"verify":true,"strict":true}"#),
            Some(Backend::Ant {
                mode: Ant::External,
                up: true,
                verify: Verification::On,
                strict: true
            })
        );
        assert_eq!(
            backend(r#"{"ipfs":"gateway","up":true,"unsupported":true}"#)
                .map(Backend::verification),
            Some(Verification::Unsupported)
        );
        // Written in the order 0009 gives: the node, up, then the flags.
        let text = r#"{"ipfs":"gateway","up":true,"unsupported":true,"strict":true}"#;
        assert_eq!(
            backend(text).map(|b| b.to_value().stringify()).as_deref(),
            Some(text)
        );
        for text in [
            r#"{"ant":"absent","up":false}"#,
            r#"{"ant":"bundled"}"#,
            r#"{"ant":"bundled","up":"true"}"#,
            r#"{"ant":"bundled","up":true,"ipfs":"native"}"#,
            r#"{"ipfs":"Native","up":true}"#,
            r#"{"node":"ant","up":true}"#,
            r#"["ant","bundled"]"#,
            // 0009's members: only true, only on an external backend,
            // unsupported only on a gateway and never with verify.
            r#"{"ant":"external","up":true,"verify":false}"#,
            r#"{"ant":"bundled","up":true,"verify":true}"#,
            r#"{"ipfs":"native","up":true,"strict":true}"#,
            r#"{"ant":"external","up":true,"unsupported":true}"#,
            r#"{"ipfs":"gateway","up":true,"verify":true,"unsupported":true}"#,
            r#"{"ipfs":"gateway","up":true,"verify":true,"extra":true}"#,
        ] {
            assert_eq!(backend(text), None, "{text}");
        }
    }
}
