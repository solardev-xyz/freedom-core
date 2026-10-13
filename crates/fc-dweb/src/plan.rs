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

/// The backend main names in `dweb.open`, as a reference with no URL: its
/// mode, and whether it is up. A backend that isn't up keeps its mode, so
/// the answer names what isn't running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Ant { mode: Ant, up: bool },
    Ipfs { mode: Ipfs, up: bool },
}

impl Backend {
    /// `{ ant: "bundled" | "external", up }` or `{ ipfs: "native" |
    /// "gateway", up }`, as `dweb.open` carries it: exactly those two keys.
    pub fn from_value(value: &JsValue) -> Option<Self> {
        let JsValue::Object(props) = value else {
            return None;
        };
        let up = match value.get("up") {
            Some(JsValue::Bool(up)) => *up,
            _ => return None,
        };
        if props.len() != 2 {
            return None;
        }
        if let Some(mode) = value.get("ant") {
            return match mode.as_str()? {
                "bundled" => Some(Self::Ant {
                    mode: Ant::Bundled,
                    up,
                }),
                "external" => Some(Self::Ant {
                    mode: Ant::External,
                    up,
                }),
                _ => None,
            };
        }
        match value.get("ipfs")?.as_str()? {
            "native" => Some(Self::Ipfs {
                mode: Ipfs::Native,
                up,
            }),
            "gateway" => Some(Self::Ipfs {
                mode: Ipfs::Gateway,
                up,
            }),
            _ => None,
        }
    }

    /// The backend as `dweb.open` carries it.
    pub fn to_value(self) -> JsValue {
        let (node, mode, up) = match self {
            Self::Ant { mode, up } => ("ant", mode.as_str(), up),
            Self::Ipfs { mode, up } => ("ipfs", mode.as_str(), up),
        };
        object(vec![
            (node, JsValue::String(mode.to_owned())),
            ("up", JsValue::Bool(up)),
        ])
    }

    /// Whether main can dial it now.
    pub fn up(self) -> bool {
        match self {
            Self::Ant { up, .. } | Self::Ipfs { up, .. } => up,
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
}

impl ContentTrust {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NodeAsserted => "node_asserted",
            Self::Unverified => "unverified",
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
            ("message", JsValue::String(self.message.clone())),
        ])
        .stringify()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Fetch(Fetch),
    Redirect(Redirect),
    Error(ErrorPlan),
}

fn number(value: impl Into<f64>) -> JsValue {
    JsValue::Number(value.into())
}

fn object(props: Vec<(&str, JsValue)>) -> JsValue {
    JsValue::Object(props.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

fn pairs(headers: &[(String, String)]) -> JsValue {
    JsValue::Array(
        headers
            .iter()
            .map(|(n, v)| {
                JsValue::Array(vec![JsValue::String(n.clone()), JsValue::String(v.clone())])
            })
            .collect(),
    )
}

fn optional(value: Option<u32>) -> JsValue {
    value.map_or(JsValue::Null, number)
}

impl Plan {
    /// The plan as `dweb.open` returns it (design 0006, "Plans").
    pub fn to_value(&self) -> JsValue {
        match self {
            Self::Fetch(fetch) => object(vec![(
                "fetch",
                object(vec![
                    ("node", JsValue::String(fetch.node.as_str().to_owned())),
                    ("path", JsValue::String(fetch.path.clone())),
                    ("headers", pairs(&fetch.headers)),
                    (
                        "retry",
                        object(vec![
                            (
                                "statuses",
                                JsValue::Array(
                                    fetch.retry.statuses.iter().map(|&s| number(s)).collect(),
                                ),
                            ),
                            ("on_error", JsValue::Bool(fetch.retry.on_error)),
                            ("attempts", number(fetch.retry.attempts)),
                            (
                                "delays_ms",
                                JsValue::Array(
                                    fetch.retry.delays_ms.iter().map(|&d| number(d)).collect(),
                                ),
                            ),
                        ]),
                    ),
                    (
                        "timers",
                        object(vec![
                            ("queue_ms", optional(fetch.timers.queue_ms)),
                            ("headers_ms", optional(fetch.timers.headers_ms)),
                            ("body_idle_ms", number(fetch.timers.body_idle_ms)),
                        ]),
                    ),
                    (
                        "response",
                        JsValue::Array(
                            fetch
                                .response
                                .iter()
                                .map(|op| JsValue::String(op.as_str().to_owned()))
                                .collect(),
                        ),
                    ),
                    (
                        "trust",
                        object(vec![
                            (
                                "name",
                                fetch
                                    .trust
                                    .name
                                    .clone()
                                    .map_or(JsValue::Null, JsValue::String),
                            ),
                            (
                                "content",
                                JsValue::String(fetch.trust.content.as_str().to_owned()),
                            ),
                        ]),
                    ),
                ]),
            )]),
            Self::Redirect(redirect) => object(vec![(
                "redirect",
                object(vec![
                    ("status", number(redirect.status)),
                    ("location", JsValue::String(redirect.location.clone())),
                    ("headers", pairs(&redirect.headers)),
                ]),
            )]),
            Self::Error(error) => object(vec![(
                "error",
                object(vec![
                    ("status", number(error.status)),
                    ("code", number(error.status)),
                    ("message", JsValue::String(error.message.clone())),
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
            Some(Backend::Ipfs {
                mode: Ipfs::Gateway,
                up: false
            })
        );
        assert_eq!(
            backend(r#"{"up":true,"ant":"external"}"#),
            Some(Backend::Ant {
                mode: Ant::External,
                up: true
            })
        );
        for text in [
            r#"{"ant":"absent","up":false}"#,
            r#"{"ant":"bundled"}"#,
            r#"{"ant":"bundled","up":"true"}"#,
            r#"{"ant":"bundled","up":true,"ipfs":"native"}"#,
            r#"{"ipfs":"Native","up":true}"#,
            r#"{"node":"ant","up":true}"#,
            r#"["ant","bundled"]"#,
        ] {
            assert_eq!(backend(text), None, "{text}");
        }
    }
}
