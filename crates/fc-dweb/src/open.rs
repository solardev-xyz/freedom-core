//! `dweb.open`'s planning: from a request to a plan, or to a name to
//! resolve first.

use crate::headers::Headers;
use crate::names::{Mapped, Resolved, Resolver, Unplannable, map_resolution, trust_level};
use crate::plan::{
    Backend, ErrorPlan, Fetch, Ipfs, Node, Plan, ResponseOp, Scheme, Trust, content_trust, retry,
    timers,
};
use crate::{bzz, ipfs, url};

/// A request as main hands it to `dweb.open`.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The URL as Chromium hands it to the handler.
    pub url: &'a str,
    pub method: &'a str,
    /// The request's headers, in order.
    pub headers: &'a [(String, String)],
    pub backend: Backend,
}

/// A request the core can't plan: the caller's mistake, not the page's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    #[error("not a bzz:, ipfs: or ipns: URL")]
    Scheme,
    #[error("the backend doesn't serve the URL's scheme")]
    Backend,
}

/// What `open` makes of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opening {
    Plan(Plan),
    /// A name host: resolve [`Pending::name`], then [`Pending::finish`].
    Resolve(Pending),
}

/// A plan waiting for a name's resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub(crate) scheme: Scheme,
    pub(crate) host: String,
    pub(crate) pathname: String,
    pub(crate) search: String,
    pub(crate) backend: Backend,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) small_text: bool,
}

impl Pending {
    /// The name to resolve: the URL's hostname as the handler reads it.
    pub fn name(&self) -> &str {
        &self.host
    }

    /// The resolver the handler asks for it.
    pub fn resolver(&self) -> Resolver {
        Resolver::for_name(&self.host)
    }

    /// The plan, given what the resolver did.
    pub fn finish(self, resolved: Resolved<'_>) -> Result<Plan, Unplannable> {
        let namespace = self.scheme.as_str();
        let mapped = map_resolution(
            namespace,
            &self.host,
            &self.pathname,
            &self.search,
            resolved,
        )?;
        Ok(match mapped {
            Mapped::Failure(status, message) => Plan::Error(ErrorPlan::new(status, message)),
            Mapped::Target(target) => fetch_plan(
                self.scheme,
                self.backend,
                &target,
                self.headers,
                self.small_text,
                trust_level(resolved),
            ),
        })
    }
}

/// Plans a request, as the `bzz:`, `ipfs:` and `ipns:` handlers would
/// answer it.
pub fn open(request: &Request<'_>) -> Result<Opening, OpenError> {
    let scheme = url::scheme(request.url)
        .and_then(|name| Scheme::from_name(&name))
        .ok_or(OpenError::Scheme)?;
    if !request.backend.serves(scheme) {
        return Err(OpenError::Backend);
    }
    let headers = Headers::from_pairs(
        request
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str())),
    );
    Ok(match scheme {
        Scheme::Bzz => bzz::open(request, &headers),
        Scheme::Ipfs | Scheme::Ipns => ipfs::open(scheme, request, &headers),
    })
}

/// A fetch for a node-relative target (`/<namespace>/<ref>…`), or the
/// node's absence as an error.
pub(crate) fn fetch_plan(
    scheme: Scheme,
    backend: Backend,
    target: &str,
    headers: Vec<(String, String)>,
    small_text: bool,
    name_trust: Option<String>,
) -> Plan {
    if backend.is_absent() {
        return Plan::Error(absent(scheme));
    }
    let node = match scheme {
        Scheme::Bzz => Node::Ant,
        Scheme::Ipfs | Scheme::Ipns => Node::Ipfs,
    };
    let mut response = match backend {
        Backend::Ant(_) => vec![ResponseOp::CanonicalizeRedirect, ResponseOp::StripPageState],
        Backend::Ipfs(Ipfs::Gateway) => vec![
            ResponseOp::StripDecodedEncoding,
            ResponseOp::StripPageState,
            ResponseOp::CanonicalizeRedirect,
        ],
        Backend::Ipfs(_) => vec![ResponseOp::StripPageState],
    };
    // The gateway's length is stripped before this rule could read it,
    // so it never fires there.
    if small_text && backend == Backend::Ipfs(Ipfs::Native) {
        response.push(ResponseOp::SmallText);
    }
    Plan::Fetch(Fetch {
        node,
        path: url::normalize_target(target).unwrap_or_else(|| target.to_owned()),
        headers,
        retry: retry(backend),
        timers: timers(backend),
        response,
        trust: Trust {
            name: name_trust,
            content: content_trust(backend),
        },
    })
}

/// The node isn't there: `bzz:` says so before resolving, IPFS at dispatch.
pub(crate) fn absent(scheme: Scheme) -> ErrorPlan {
    match scheme {
        Scheme::Bzz => ErrorPlan::new(503, "Swarm node is not ready"),
        Scheme::Ipfs | Scheme::Ipns => ErrorPlan::new(503, "freedom-ipfs node is not running"),
    }
}
