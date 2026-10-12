//! A quorum leg: the resolver calls, CCIP-Read at the pinned block, and
//! classification (design 0004, Classification).

use super::*;

/// A call the resolver makes on a leg (`callResolver`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resolver {
    /// `universalResolverCall`: the UR's `resolve`, with CCIP-Read.
    Ur,
    /// `nameNftResolverCall`: a WNS/GNS registry's own record.
    NameNft(NameSystem),
    /// `universalResolverReverseCall`: the UR's `reverse`, as an agreement
    /// value `(outcome, detail)`.
    UrReverse { coin_type: u64 },
    /// `nameNftReverseResolverCall`: a registry's `reverseResolve`.
    NameNftReverse(NameSystem),
}

/// Why a call failed, with what classification and agreement need.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CallError {
    Rpc(RpcError),
    /// ethers refused the call's arguments or its answer. The text is the
    /// identity ethers' message would give it (design 0004, Errors).
    Invalid(String),
    /// `CCIP sender does not match the Universal Resolver`.
    SenderMismatch,
    /// Every gateway failed: `CCIP_GATEWAY_FAILED`.
    GatewaysFailed,
    /// `CCIP recursion limit exceeded`.
    RecursionLimit,
    /// The leg's deadline.
    Timeout,
    /// A NameNFT call the adapter doesn't support.
    Unsupported(String),
}

/// A failed call, with the call that failed (the callback, after
/// CCIP-Read).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Failure {
    error: CallError,
    to: [u8; 20],
    data: Vec<u8>,
}

impl CallError {
    /// The revert data the resolver reads: ethers' extracted data, else
    /// the node's `data` string (`getRevertData`).
    pub(crate) fn revert_source(&self) -> Option<String> {
        match self {
            CallError::Rpc(RpcError::CallException {
                data: Some(data), ..
            }) => Some(rpc::hex(data)),
            CallError::Rpc(RpcError::CallException {
                node: Some(node), ..
            }) => node
                .data_string()
                .filter(|d| d.len() >= 10)
                .map(str::to_owned),
            _ => None,
        }
    }

    pub(crate) fn selector(&self) -> Option<String> {
        self.revert_source()
            .map(|s| s.get(..10).unwrap_or("").to_ascii_lowercase())
    }

    /// The `Error(string)` reason ethers decodes from revert data.
    pub(crate) fn reason(&self) -> Option<String> {
        let CallError::Rpc(RpcError::CallException {
            data: Some(data), ..
        }) = self
        else {
            return None;
        };
        if data.get(..4)? != [0x08, 0xc3, 0x79, 0xa0] || data.len() % 32 != 4 {
            return None;
        }
        match crate::abi::decode(&[Kind::String], &data[4..])
            .ok()?
            .into_iter()
            .next()?
        {
            Ok(Value::String(reason)) => Some(reason),
            _ => None,
        }
    }

    pub(crate) fn reason_names(&self, names: &[&str]) -> bool {
        self.reason().is_some_and(|reason| {
            let lower = reason.to_ascii_lowercase();
            names.iter().any(|n| lower.contains(n))
        })
    }

    /// `isResolverNotFoundError`: the selector, or an `Error(string)`
    /// reason naming the error (what the reference's message match sees).
    pub(crate) fn resolver_not_found(&self) -> bool {
        matches!(
            self.selector().as_deref(),
            Some("0x77209fe8" | "0x1e9535f2")
        ) || self.reason_names(&["resolvernotfound", "resolvernotcontract"])
    }

    /// `isReverseAddressMismatchError`.
    pub(crate) fn reverse_mismatch(&self) -> bool {
        self.selector().as_deref() == Some("0xef9c03ce")
            || self.reason_names(&["reverseaddressmismatch"])
    }

    /// The core's provider-failure rules (design 0004, Classification).
    pub(crate) fn provider_failure(&self) -> bool {
        match self {
            CallError::Timeout => true,
            CallError::Rpc(error) => match error {
                RpcError::Transport(_)
                | RpcError::Http(_)
                | RpcError::NotJson
                | RpcError::MissingResponse
                | RpcError::MalformedError
                | RpcError::BadResult => true,
                RpcError::CallException {
                    node: Some(node), ..
                } if node.code() == Some(-32603.0) => true,
                // Rule 5, then revert evidence (code 3 or a revert message,
                // which is how spelunkData found it): not a failure.
                RpcError::BadRevert { node, .. } => node.code() == Some(-32603.0),
                RpcError::CallException { data: Some(_), .. } => false,
                RpcError::CallException {
                    data: None,
                    node: Some(node),
                } => node_failure(node),
                RpcError::CallException {
                    data: None,
                    node: None,
                }
                | RpcError::Coalesce(_) => false,
            },
            _ => false,
        }
    }

    /// Display text: the short message, sanitized (design 0004, Errors).
    pub(crate) fn display(&self) -> String {
        crate::ethers::sanitize(&self.short_message())
    }

    pub(crate) fn short_message(&self) -> String {
        match self {
            CallError::Rpc(RpcError::Transport(Transport::Timeout)) | CallError::Timeout => {
                "timeout".into()
            }
            CallError::Rpc(RpcError::Transport(_)) => "network error".into(),
            CallError::Rpc(RpcError::Http(status)) => format!("server response {status}"),
            CallError::Rpc(RpcError::NotJson) => "response body is not valid JSON".into(),
            CallError::Rpc(RpcError::MissingResponse) => "missing response for request".into(),
            CallError::Rpc(RpcError::MalformedError) => "invalid error response".into(),
            CallError::Rpc(RpcError::BadRevert { .. }) => "invalid BytesLike value".into(),
            CallError::Rpc(RpcError::BadResult) => "invalid result".into(),
            CallError::Rpc(RpcError::Coalesce(_)) => "could not coalesce error".into(),
            CallError::Rpc(RpcError::CallException { data: None, .. }) => {
                "missing revert data".into()
            }
            CallError::Rpc(RpcError::CallException {
                data: Some(data), ..
            }) => match self.reason() {
                Some(reason) => format!(
                    "execution reverted: {}",
                    JsValue::String(reason).stringify()
                ),
                None if data.is_empty() => {
                    "execution reverted (no data present; likely require(false) occurred".into()
                }
                None => "execution reverted (unknown custom error)".into(),
            },
            // ethers' own messages (decode failures, deferred field
            // errors) show their short part; the core's internal markers
            // show the class.
            CallError::Invalid(message)
                if message.ends_with(&format!(", version={})", crate::ethers::VERSION))
                    || message.starts_with("deferred error") =>
            {
                crate::ethers::short_of(message).to_owned()
            }
            CallError::Invalid(_) => "could not decode result data".into(),
            CallError::SenderMismatch => "CCIP sender does not match the Universal Resolver".into(),
            CallError::GatewaysFailed => {
                "CCIP gateways unavailable or returned invalid data".into()
            }
            CallError::RecursionLimit => "CCIP recursion limit exceeded".into(),
            CallError::Unsupported(message) => message.clone(),
        }
    }
}

impl Failure {
    /// The agreement identity of an encoded reverse error: what ethers'
    /// composed message is built from (design 0004, Errors).
    pub(crate) fn identity(&self) -> String {
        match &self.error {
            CallError::Rpc(RpcError::CallException { data, .. }) => {
                crate::ethers::call_exception(data.as_deref(), &self.to, &self.data)
            }
            // ethers' own message, as the reference's error carries it.
            CallError::Invalid(message) => message.clone(),
            CallError::Rpc(RpcError::BadRevert { value, .. }) => {
                crate::ethers::invalid_bytes_like(value)
            }
            other => other.short_message(),
        }
    }
}

/// Rules 6–8: the node's own error, without revert evidence (−32603 is
/// rule 5, checked first).
pub(crate) fn node_failure(node: &rpc::NodeError) -> bool {
    let code = node.code();
    let message = node.message();
    let lower = message.to_ascii_lowercase();
    let revert_shaped = node.data_string().is_some_and(|d| {
        let hex = d.strip_prefix("Reverted ").unwrap_or(d);
        hex.len() % 2 == 0 && rpc::hex_string(hex).is_some()
    });
    if matches!(code, Some(c) if c == 3.0 || c == -32015.0)
        || revert_shaped
        || lower.contains("revert")
    {
        return false;
    }
    const CODES: [f64; 6] = [-32001.0, -32002.0, -32005.0, -32007.0, -32008.0, 429.0];
    if code.is_some_and(|c| CODES.contains(&c)) {
        return true;
    }
    const PATTERNS: [&str; 19] = [
        "header not found",
        "missing trie node",
        "unknown block",
        "block not found",
        "historical state",
        "state not available",
        "state is not available",
        "pruned",
        "limit exceeded",
        "request limit reached",
        "too many requests",
        "request count exceeded",
        "compute units",
        "no response",
        "502",
        "503",
        "504",
        "429",
        "timeout",
    ];
    PATTERNS.iter().any(|p| lower.contains(p))
        || lower.contains("rate limit")
        || lower.contains("ratelimit")
        || lower.contains("rate-limit")
}

/// A leg's outcome (`runQuorumLeg`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Leg {
    Data {
        resolved: Vec<u8>,
    },
    NotFound {
        reason: &'static str,
        error: Option<CallError>,
    },
    Error(CallError),
}

/// `callUniversalResolver` at a pinned block: the first call, then up to
/// 10 CCIP-Read rounds. `Ok` is the raw answer once ethers' whole-result
/// decode accepted it; field errors stay with the caller.
pub(crate) async fn ur_call(
    ctx: &Ctx,
    provider: &mut Provider,
    call: Vec<u8>,
    (kinds, method, signature): (&[Kind], &str, &str),
    block: &str,
    used_gateway: &RefCell<bool>,
) -> Result<Vec<u8>, Failure> {
    let decoded = |result: &JsValue| -> Result<Vec<u8>, CallError> {
        let raw = rpc::call_result(result).map_err(CallError::Rpc)?;
        ur::decode_result(kinds, &raw)
            .map_err(|_| CallError::Invalid(crate::ethers::bad_result(&raw, method, signature)))?;
        Ok(raw)
    };
    let fail = |error: CallError, to: [u8; 20], data: &[u8]| Failure {
        error,
        to,
        data: data.to_vec(),
    };
    let first = Method::Call {
        to: ur::UNIVERSAL_RESOLVER,
        data: call.clone(),
        block: block.into(),
    };
    let (mut error, mut to, mut data) = match provider.send(ctx, &first).await {
        Ok(result) => return decoded(&result).map_err(|e| fail(e, ur::UNIVERSAL_RESOLVER, &call)),
        Err(e) => (CallError::Rpc(e), ur::UNIVERSAL_RESOLVER, call),
    };
    for _round in 0..10 {
        let Some(source) = error.revert_source() else {
            return Err(fail(error, to, &data));
        };
        if !source.to_ascii_lowercase().starts_with("0x556f1830") {
            return Err(fail(error, to, &data));
        }
        // `abi.decode(…, '0x' + data.slice(10))`, with ethers' messages.
        let lookup = match rpc::hex_string(&source) {
            Some(bytes) => {
                ur::decode_offchain_lookup_explained_within(&bytes, ctx.bounds().decode_bytes)
                    .map_err(|message| fail(CallError::Invalid(message), to, &data))?
            }
            None => {
                let value = format!("0x{}", source.get(10..).unwrap_or(""));
                return Err(fail(
                    CallError::Invalid(crate::ethers::invalid_bytes_like(&value)),
                    to,
                    &data,
                ));
            }
        };
        if lookup.sender != ur::UNIVERSAL_RESOLVER {
            return Err(fail(CallError::SenderMismatch, to, &data));
        }
        *used_gateway.borrow_mut() = true;
        let response = ccip_read_fetch(ctx, &lookup)
            .await
            .map_err(|e| fail(e, to, &data))?;
        let callback = ur::encode_callback(lookup.callback, &response, &lookup.extra_data);
        // Deviation `request-size`: a callback over the frame fails the leg as
        // the gateways failing would.
        if !ctx.bounds().fits(&[&rpc::hex(&callback)]) {
            return Err(fail(CallError::GatewaysFailed, to, &data));
        }
        let next = Method::Call {
            to: lookup.sender,
            data: callback.clone(),
            block: block.into(),
        };
        match provider.send(ctx, &next).await {
            Ok(result) => return decoded(&result).map_err(|e| fail(e, lookup.sender, &callback)),
            Err(e) => (error, to, data) = (CallError::Rpc(e), lookup.sender, callback),
        }
    }
    Err(fail(CallError::RecursionLimit, to, &data))
}

pub(crate) const CCIP_TIMEOUT_MS: Ms = 15_000;

/// `ccipReadFetch`: each URL in order, 15 s each, until one answers hex.
pub(crate) async fn ccip_read_fetch(
    ctx: &Ctx,
    lookup: &ur::OffchainLookup,
) -> Result<Vec<u8>, CallError> {
    // Deviation `ccip-urls`: the first 32 URLs.
    for (index, template) in lookup.urls.iter().enumerate().take(ctx.bounds().ccip_urls) {
        // A URL that won't decode throws out of the loop where the JS
        // iteration reaches it.
        let template = template
            .as_ref()
            .map_err(|_| CallError::Invalid(crate::ethers::deferred(index)))?;
        let Some(request) =
            crate::ccip::gateway_request(template, &lookup.sender, &lookup.call_data)
        else {
            continue;
        };
        // Deviation `request-size`: a request over the frame is never sent;
        // that gateway fails.
        if !ctx
            .bounds()
            .fits(&[&request.url, request.body.as_deref().unwrap_or("")])
        {
            continue;
        }
        let fetch = ctx.rt.request(Request::Gateway {
            url: request.url,
            body: request.body,
        });
        if let Either::Left(Answer::Gateway { status, body }) =
            race(fetch, ctx.rt.sleep(CCIP_TIMEOUT_MS)).await
            && (200..300).contains(&status)
            && ctx.bounds().answer_fits(body.len())
            && let Some(data) = crate::ccip::parse_gateway_response(&body)
        {
            return Ok(data);
        }
    }
    Err(CallError::GatewaysFailed)
}

/// `nodeFromResolverCallData`: 36 bytes or more, the node after the
/// selector.
pub(crate) fn node_of(call_data: &[u8]) -> Result<[u8; 32], CallError> {
    if call_data.len() < 36 {
        return Err(CallError::Unsupported("Invalid resolver call data".into()));
    }
    ur::node_from_call(call_data)
        .ok_or_else(|| CallError::Unsupported("Invalid resolver call data".into()))
}

pub(crate) fn label(system: NameSystem) -> &'static str {
    match system {
        NameSystem::Ens => "ENS",
        NameSystem::Wns => "WNS",
        NameSystem::Gns => "GNS",
    }
}

/// A plain contract call at the pinned block (NameNFT calls never use
/// CCIP-Read), its single result decoded with `kind`.
pub(crate) async fn contract_call(
    ctx: &Ctx,
    provider: &mut Provider,
    to: [u8; 20],
    data: Vec<u8>,
    kind: Kind,
    block: &str,
) -> Result<Value, CallError> {
    let method = Method::Call {
        to,
        data,
        block: block.into(),
    };
    let result = provider.send(ctx, &method).await.map_err(CallError::Rpc)?;
    let raw = rpc::call_result(&result).map_err(CallError::Rpc)?;
    let fields = ur::decode_result(&[kind], &raw)
        .map_err(|_| CallError::Invalid(format!("result|{}", rpc::hex(&raw))))?;
    match fields.into_iter().next() {
        Some(Ok(value)) => Ok(value),
        _ => Err(CallError::Invalid(
            "deferred error during ABI decoding triggered accessing index 0".into(),
        )),
    }
}

/// `dnsEncode(name, 255)`'s failure as the leg carries it: ethers' own
/// message for a label over the limit, the one a normalized name can reach.
fn dns_error(name: &str, error: &crate::Error) -> CallError {
    match error {
        crate::Error::LabelTooLong(limit) => CallError::Invalid(label_message(name, *limit)),
        other => CallError::Invalid(format!("dns|{other}")),
    }
}

fn label_message(name: &str, limit: usize) -> String {
    crate::ethers::make_error(
        &format!(
            "label {} exceeds {limit} bytes",
            crate::ethers::string(name)
        ),
        "INVALID_ARGUMENT",
        &[
            ("argument", crate::ethers::string("name")),
            ("value", crate::ethers::string(name)),
        ],
    )
}

/// ethers' message when `universalResolverCall`'s `dnsEncode(name, 255)`
/// refuses `name`, or `None` when it encodes.
pub(crate) fn label_too_long(name: &str) -> Option<String> {
    match crate::dns_encode(name, 255) {
        Err(crate::Error::LabelTooLong(limit)) => Some(label_message(name, limit)),
        _ => None,
    }
}

/// One leg's call (`callResolver(provider, name, callData, overrides)`):
/// the agreement bytes, or a failure for the leg's classification.
pub(crate) async fn resolver_call(
    ctx: &Ctx,
    provider: &mut Provider,
    resolver: Resolver,
    name: &str,
    call_data: &[u8],
    block: &str,
    used_gateway: &RefCell<bool>,
) -> Result<Vec<u8>, CallError> {
    match resolver {
        Resolver::Ur => {
            let dns = crate::dns_encode(name, 255).map_err(|e| dns_error(name, &e))?;
            let raw = ur_call(
                ctx,
                provider,
                ur::encode_resolve(&dns, call_data),
                (
                    &[Kind::Bytes, Kind::Address],
                    "resolve",
                    "resolve(bytes,bytes)",
                ),
                block,
                used_gateway,
            )
            .await
            .map_err(|f| f.error)?;
            match ur::decode_result(&[Kind::Bytes, Kind::Address], &raw)
                .ok()
                .as_deref()
            {
                Some([Ok(Value::Bytes(resolved)), Ok(Value::Address(_))]) => Ok(resolved.clone()),
                _ => Err(CallError::Invalid(
                    "deferred error during ABI decoding triggered accessing index 0".into(),
                )),
            }
        }
        Resolver::UrReverse { coin_type } => {
            let Some(address) = rpc::hex_string(name).and_then(|b| <[u8; 20]>::try_from(b).ok())
            else {
                return Err(CallError::Invalid(format!("address|{name}")));
            };
            let kinds = [Kind::String, Kind::Address, Kind::Address];
            let outcome = ur_call(
                ctx,
                provider,
                ur::encode_reverse(&address, coin_type),
                (&kinds, "reverse", "reverse(bytes,uint256)"),
                block,
                used_gateway,
            )
            .await;
            match outcome {
                Ok(raw) => match ur::decode_result(&kinds, &raw)
                    .ok()
                    .and_then(|f| f.into_iter().next())
                {
                    Some(Ok(Value::String(primary))) if !primary.is_empty() => Ok(
                        ur::encode_reverse_outcome(ur::ReverseOutcome::Name, &primary),
                    ),
                    Some(Ok(Value::String(_))) => {
                        Ok(ur::encode_reverse_outcome(ur::ReverseOutcome::NoRecord, ""))
                    }
                    // `const [name] = …`: reading a failed field throws.
                    _ => Ok(ur::encode_reverse_outcome(
                        ur::ReverseOutcome::Error,
                        &crate::ethers::deferred(0),
                    )),
                },
                // `universalResolverReverseCall`'s catch, in its order.
                Err(failure)
                    if failure.error.provider_failure()
                        || failure.error == CallError::GatewaysFailed =>
                {
                    Err(failure.error)
                }
                Err(failure) if failure.error.resolver_not_found() => {
                    Ok(ur::encode_reverse_outcome(ur::ReverseOutcome::NoRecord, ""))
                }
                Err(failure) if failure.error.reverse_mismatch() => {
                    let claimed = failure
                        .error
                        .revert_source()
                        .and_then(|s| rpc::hex_string(&s))
                        .and_then(|d| ur::reverse_mismatch_claimed_name(&d));
                    Ok(ur::encode_reverse_outcome(
                        ur::ReverseOutcome::Mismatch,
                        claimed.as_deref().unwrap_or(""),
                    ))
                }
                Err(failure) => Ok(ur::encode_reverse_outcome(
                    ur::ReverseOutcome::Error,
                    &failure.identity(),
                )),
            }
        }
        Resolver::NameNft(system) => {
            let Some(registry) = system.registry() else {
                return Err(CallError::Unsupported(format!(
                    "No NameNFT contract configured for {}",
                    label(system)
                )));
            };
            let node = node_of(call_data)?;
            match call_data.get(..4) {
                Some(selector) if selector == ur::CONTENTHASH => {
                    match contract_call(
                        ctx,
                        provider,
                        registry,
                        ur::contenthash_call(&node),
                        Kind::Bytes,
                        block,
                    )
                    .await?
                    {
                        Value::Bytes(contenthash) => {
                            Ok(crate::abi::encode(&[crate::abi::Token::Dynamic(
                                &contenthash,
                            )]))
                        }
                        _ => Err(CallError::Invalid("contenthash".into())),
                    }
                }
                Some(selector) if selector == ur::ADDR => match contract_call(
                    ctx,
                    provider,
                    registry,
                    ur::addr_call(&node),
                    Kind::Address,
                    block,
                )
                .await?
                {
                    Value::Address(address) => Ok(crate::abi::encode(&[crate::abi::Token::Word(
                        crate::abi::word_from_address(&address),
                    )])),
                    _ => Err(CallError::Invalid("addr".into())),
                },
                _ => Err(CallError::Unsupported(format!(
                    "Unsupported {} resolver selector: {}",
                    label(system),
                    rpc::hex(call_data.get(..4).unwrap_or(&[]))
                ))),
            }
        }
        Resolver::NameNftReverse(system) => {
            let Some(registry) = system.registry() else {
                return Err(CallError::Unsupported(format!(
                    "No NameNFT contract configured for {}",
                    label(system)
                )));
            };
            let Some(address) = call_data
                .get(16..36)
                .and_then(|b| <[u8; 20]>::try_from(b).ok())
            else {
                return Err(CallError::Invalid("reverseResolve".into()));
            };
            match contract_call(
                ctx,
                provider,
                registry,
                ur::reverse_resolve_call(&address),
                Kind::String,
                block,
            )
            .await?
            {
                Value::String(claimed) => Ok(crate::abi::encode(&[crate::abi::Token::Dynamic(
                    claimed.as_bytes(),
                )])),
                _ => Err(CallError::Invalid("reverseResolve".into())),
            }
        }
    }
}

/// `runQuorumLeg`.
pub(crate) async fn run_leg(
    ctx: &Ctx,
    endpoint: &str,
    lookup: &Lookup<'_>,
    block: &str,
    timeout: f64,
) -> Leg {
    let mut provider = Provider::new(endpoint);
    let used_gateway = RefCell::new(false);
    let call = resolver_call(
        ctx,
        &mut provider,
        lookup.resolver,
        lookup.name,
        lookup.call_data,
        block,
        &used_gateway,
    );
    let error = match with_timeout(ctx, timeout, call).await {
        Ok(Ok(resolved)) => {
            ctx.mark_success(endpoint);
            return Leg::Data { resolved };
        }
        Ok(Err(error)) => error,
        Err(()) if *used_gateway.borrow() => {
            ctx.mark_success(endpoint);
            return Leg::Error(CallError::Timeout);
        }
        Err(()) => CallError::Timeout,
    };
    if error == CallError::GatewaysFailed {
        ctx.mark_success(endpoint);
        return Leg::Error(error);
    }
    if error.resolver_not_found() {
        ctx.mark_success(endpoint);
        return Leg::NotFound {
            reason: "NO_RESOLVER",
            error: None,
        };
    }
    if error.provider_failure() {
        ctx.mark_failure(endpoint);
        return Leg::Error(error);
    }
    ctx.mark_success(endpoint);
    Leg::NotFound {
        reason: "NO_CONTENTHASH",
        error: Some(error),
    }
}
