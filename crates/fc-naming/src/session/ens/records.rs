//! The record drivers: content, address and reverse.

use super::*;

/// `doResolveEnsContent`.
pub(crate) async fn content(
    ctx: &Ctx,
    machine: &crate::session::machine::Shared,
    normalized: &str,
) -> Result<JsValue, Thrown> {
    let node = crate::namehash(normalized).map_err(|e| Thrown::new(e.to_string()))?;
    let call_data = ur::contenthash_call(&node);
    let system = NameSystem::for_name(normalized);
    let id = system.id();
    let resolver = if system.registry().is_some() {
        Resolver::NameNft(system)
    } else {
        Resolver::Ur
    };
    let lookup = Lookup {
        name: normalized,
        call_data: &call_data,
        system: id,
        resolver,
        prefetch: true,
    };
    let consensus = consensus_resolve(ctx, machine, &lookup).await?;
    let trust = consensus.trust().clone();
    let head = |kind: &str| {
        vec![
            ("type", s(kind)),
            ("name", s(normalized)),
            ("system", s(id)),
        ]
    };
    let store = |result: JsValue| cache(ctx, Store::Content, normalized, result);
    match consensus {
        Consensus::Conflict { groups, .. } => {
            let mut fields = head("conflict");
            fields.extend([("trust", trust), ("groups", groups)]);
            Ok(store(obj(fields)))
        }
        Consensus::NotFound { reason, error, .. } => {
            let mut fields = vec![
                ("type", s("not_found")),
                ("reason", s(reason)),
                ("name", s(normalized)),
                ("system", s(id)),
                ("trust", trust),
            ];
            if let Some(error) = &error {
                fields.push(("error", s(&error.display())));
            }
            let out = obj(fields);
            if reason == "NO_CONTENTHASH" && error.is_some() {
                return Ok(out);
            }
            Ok(store(out))
        }
        Consensus::Data { resolved, .. } => {
            let unsupported = |bytes: &[u8], trust: JsValue| {
                obj(vec![
                    ("type", s("unsupported")),
                    ("reason", s("UNSUPPORTED_CONTENTHASH_FORMAT")),
                    ("name", s(normalized)),
                    ("system", s(id)),
                    ("contentHash", s(&rpc::hex(bytes))),
                    ("trust", trust),
                ])
            };
            let inner = match crate::abi::decode(&[Kind::Bytes], &resolved)
                .ok()
                .and_then(|f| f.into_iter().next())
            {
                Some(Ok(Value::Bytes(bytes))) => bytes,
                _ => return Ok(store(unsupported(&resolved, trust))),
            };
            if inner.is_empty() {
                return Ok(store(obj(vec![
                    ("type", s("not_found")),
                    ("reason", s("EMPTY_CONTENTHASH")),
                    ("name", s(normalized)),
                    ("system", s(id)),
                    ("trust", trust),
                ])));
            }
            match crate::parse_contenthash(&inner) {
                None => Ok(store(unsupported(&inner, trust))),
                Some(content) => {
                    let mut fields = head("ok");
                    fields.extend([
                        ("codec", s(content.codec)),
                        ("protocol", s(content.protocol)),
                        ("uri", s(&content.uri())),
                        ("decoded", s(&content.decoded)),
                        ("trust", trust),
                    ]);
                    Ok(store(obj(fields)))
                }
            }
        }
    }
}

/// `ensCoinType`: `Err` is today's thrown "Invalid ENS destination chain ID".
pub(crate) fn coin_type(chain_id: f64) -> Result<u64, Thrown> {
    const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
    if !(chain_id.fract() == 0.0 && chain_id.abs() <= MAX_SAFE)
        || chain_id < 1.0
        || chain_id >= 2_147_483_648.0
    {
        return Err(Thrown::new("Invalid ENS destination chain ID"));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let chain = chain_id as u64;
    Ok(if chain == 1 { 60 } else { chain + 0x8000_0000 })
}

pub(crate) fn no_address(normalized: &str) -> Vec<(&'static str, JsValue)> {
    vec![
        ("success", JsValue::Bool(false)),
        ("name", s(normalized)),
        ("reason", s("NO_ADDRESS")),
        (
            "error",
            s(&format!("No address record set for {normalized}")),
        ),
    ]
}

/// `doResolveEnsAddress`.
pub(crate) async fn address(
    ctx: &Ctx,
    machine: &crate::session::machine::Shared,
    normalized: &str,
    chain_id: u64,
) -> Result<JsValue, Thrown> {
    let key = chain_key(normalized, chain_id);
    let store = |result: JsValue| cache(ctx, Store::Address, &key, result);
    let node = crate::namehash(normalized).map_err(|e| Thrown::new(e.to_string()))?;
    let system = NameSystem::for_name(normalized);
    let id = system.id();
    if chain_id != 1 && system.registry().is_some() {
        return Ok(store(obj(vec![
            ("success", JsValue::Bool(false)),
            ("name", s(normalized)),
            ("system", s(id)),
            ("reason", s("CHAIN_UNSUPPORTED")),
            (
                "error",
                s(&format!(
                    "{} names resolve on Ethereum mainnet only — {normalized} has no address record for this network",
                    label(system)
                )),
            ),
        ])));
    }
    let multicoin = chain_id != 1;
    let call_data = if multicoin {
        #[allow(clippy::cast_precision_loss)]
        let coin = coin_type(chain_id as f64)?;
        ur::addr_multicoin_call(&node, coin)
    } else {
        ur::addr_call(&node)
    };
    let resolver = if system.registry().is_some() {
        Resolver::NameNft(system)
    } else {
        Resolver::Ur
    };
    let lookup = Lookup {
        name: normalized,
        call_data: &call_data,
        system: id,
        resolver,
        prefetch: false,
    };
    let consensus = consensus_resolve(ctx, machine, &lookup).await?;
    let trust = consensus.trust().clone();
    let failure = |reason: &str, error: Option<String>, trust: JsValue| {
        let mut fields = vec![
            ("success", JsValue::Bool(false)),
            ("name", s(normalized)),
            ("system", s(id)),
            ("reason", s(reason)),
        ];
        fields.push(("error", error.map_or(JsValue::Null, |e| s(&e))));
        fields.push(("trust", trust));
        obj(fields)
    };
    let none = |trust: JsValue| {
        let mut fields = no_address(normalized);
        fields.extend([("system", s(id)), ("trust", trust)]);
        obj(fields)
    };
    match consensus {
        Consensus::Conflict { groups, .. } => Ok(store(obj(vec![
            ("success", JsValue::Bool(false)),
            ("name", s(normalized)),
            ("system", s(id)),
            ("reason", s("CONFLICT")),
            ("trust", trust),
            ("groups", groups),
        ]))),
        Consensus::NotFound {
            reason: "NO_CONTENTHASH",
            error,
            ..
        } => Ok(store(failure(
            "RESOLUTION_ERROR",
            error.map(|e| e.display()),
            trust,
        ))),
        Consensus::NotFound { .. } => Ok(store(none(trust))),
        Consensus::Data { resolved, .. } => {
            if resolved.is_empty() {
                return Ok(store(none(trust)));
            }
            let kind = if multicoin {
                Kind::Bytes
            } else {
                Kind::Address
            };
            let decoded = crate::abi::decode(&[kind], &resolved)
                .ok()
                .and_then(|f| f.into_iter().next());
            let address: Option<[u8; 20]> = match decoded {
                Some(Ok(Value::Address(address))) => Some(address),
                Some(Ok(Value::Bytes(bytes))) if bytes.is_empty() => Some([0; 20]),
                Some(Ok(Value::Bytes(bytes))) => <[u8; 20]>::try_from(bytes.as_slice()).ok(),
                _ => None,
            };
            let Some(address) = address else {
                return Ok(store(failure(
                    "RESOLUTION_ERROR",
                    Some("Invalid EVM address record".into()),
                    trust,
                )));
            };
            if address == [0; 20] {
                return Ok(store(none(trust)));
            }
            Ok(store(obj(vec![
                ("success", JsValue::Bool(true)),
                ("name", s(normalized)),
                ("system", s(id)),
                ("address", s(&checksum(&address))),
                ("trust", trust),
            ])))
        }
    }
}

/// EIP-55, as ethers' `getAddress` writes it.
pub(crate) fn checksum(address: &[u8; 20]) -> String {
    use sha3::{Digest, Keccak256};
    let lower: String = address.iter().map(|b| format!("{b:02x}")).collect();
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::from("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        out.push(if c.is_ascii_alphabetic() && nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

pub(crate) fn no_reverse(address: &str, trust: Option<JsValue>) -> JsValue {
    let mut fields = vec![
        ("success", JsValue::Bool(false)),
        ("address", s(address)),
        ("reason", s("NO_REVERSE")),
        ("error", s(&format!("No primary name set for {address}"))),
    ];
    if let Some(trust) = trust {
        fields.push(("trust", trust));
    }
    obj(fields)
}

pub(crate) fn unverified_reverse(
    address: &str,
    system: NameSystem,
    claimed: Option<&str>,
    detail: Option<String>,
    trust: Option<JsValue>,
) -> JsValue {
    let mut fields = vec![
        ("success", JsValue::Bool(false)),
        ("address", s(address)),
        ("system", s(system.id())),
        ("reason", s("UNVERIFIED")),
        (
            "claimedName",
            claimed.filter(|c| !c.is_empty()).map_or(JsValue::Null, s),
        ),
        (
            "error",
            s(&detail.unwrap_or_else(|| {
                format!("Reverse record for {address} does not forward-verify")
            })),
        ),
    ];
    if let Some(trust) = trust {
        fields.push(("trust", trust));
    }
    obj(fields)
}

pub(crate) fn reverse_conflict(
    address: &str,
    system: NameSystem,
    groups: JsValue,
    trust: JsValue,
) -> JsValue {
    obj(vec![
        ("success", JsValue::Bool(false)),
        ("address", s(address)),
        ("system", s(system.id())),
        ("reason", s("CONFLICT")),
        (
            "error",
            s(&format!(
                "Providers disagreed about the reverse record for {address}"
            )),
        ),
        ("trust", trust),
        ("groups", groups),
    ])
}

/// `resolveEnsReverseWithMethod`: `Ok(None)` when unavailable.
pub(crate) async fn ens_reverse_with(
    ctx: &Ctx,
    machine: &crate::session::machine::Shared,
    method: &str,
    address: &str,
    coin_type: u64,
) -> Result<Option<JsValue>, Thrown> {
    if method == "colibri" {
        return colibri_reverse(ctx, address, coin_type).await.map(Some);
    }
    let lookup = Lookup {
        name: address,
        call_data: &[],
        system: "ens",
        resolver: Resolver::UrReverse { coin_type },
        prefetch: false,
    };
    let Some(outcome) = with_method(ctx, machine, method, &lookup).await? else {
        return Ok(None);
    };
    Ok(Some(match outcome {
        Consensus::Conflict { groups, trust } => {
            reverse_conflict(address, NameSystem::Ens, groups, trust)
        }
        Consensus::NotFound { trust, .. } => no_reverse(address, Some(trust)),
        Consensus::Data { resolved, trust } => {
            let decoded = crate::abi::decode(&[Kind::Uint256, Kind::String], &resolved).ok();
            let (status, detail) = match decoded.as_deref() {
                Some([Ok(Value::Uint256(word)), Ok(Value::String(detail))]) => {
                    (word[31], detail.clone())
                }
                _ => (0, String::new()),
            };
            match status {
                1 => obj(vec![
                    ("success", JsValue::Bool(true)),
                    ("address", s(address)),
                    ("name", s(&detail)),
                    ("system", s("ens")),
                    ("trust", trust),
                ]),
                2 => unverified_reverse(address, NameSystem::Ens, Some(&detail), None, Some(trust)),
                3 => obj(vec![
                    ("success", JsValue::Bool(false)),
                    ("address", s(address)),
                    ("system", s("ens")),
                    ("reason", s("RESOLUTION_ERROR")),
                    // The identity agreed on; the display text is its class.
                    ("error", s(&display_of(&detail))),
                    ("trust", trust),
                ]),
                _ => no_reverse(address, Some(trust)),
            }
        }
    }))
}

/// The display text for an agreement identity (ethers' composed message):
/// its class's short message, sanitized (design 0004, Errors).
pub(crate) fn display_of(identity: &str) -> String {
    crate::ethers::sanitize(crate::ethers::short_of(identity))
}

/// `resolveContractBackedReverseWithMethod`.
pub(crate) async fn contract_backed_reverse(
    ctx: &Ctx,
    machine: &crate::session::machine::Shared,
    method: &str,
    address: &str,
    ens: JsValue,
) -> Result<Option<JsValue>, Thrown> {
    if ens.get("reason") != Some(&s("NO_REVERSE")) {
        return Ok(Some(ens));
    }
    let Some(bytes) = rpc::hex_string(address).and_then(|b| <[u8; 20]>::try_from(b).ok()) else {
        return Ok(Some(ens));
    };
    let mut first_unverified: Option<JsValue> = None;
    let mut last_trust = ens.get("trust").cloned();
    for system in [NameSystem::Wns, NameSystem::Gns] {
        let call = ur::reverse_resolve_call(&bytes);
        let synthetic = format!(
            "reverse.{}",
            if system == NameSystem::Wns {
                "wei"
            } else {
                "gwei"
            }
        );
        let lookup = Lookup {
            name: &synthetic,
            call_data: &call,
            system: system.id(),
            resolver: Resolver::NameNftReverse(system),
            prefetch: false,
        };
        let Some(outcome) = with_method(ctx, machine, method, &lookup).await? else {
            return Ok(None);
        };
        last_trust = Some(outcome.trust().clone());
        let (resolved, reverse_trust) = match outcome {
            Consensus::Conflict { groups, trust } => {
                return Ok(Some(reverse_conflict(address, system, groups, trust)));
            }
            Consensus::NotFound { .. } => continue,
            Consensus::Data { resolved, trust } => (resolved, trust),
        };
        let claimed = match crate::abi::decode(&[Kind::String], &resolved)
            .ok()
            .and_then(|f| f.into_iter().next())
        {
            Some(Ok(Value::String(claimed))) => claimed,
            _ => {
                return Err(Thrown::new(format!(
                    "invalid {} reverse response",
                    label(system)
                )));
            }
        };
        if claimed.is_empty() {
            continue;
        }
        if NameSystem::for_name(&claimed) != system {
            first_unverified.get_or_insert_with(|| {
                unverified_reverse(
                    address,
                    system,
                    Some(&claimed),
                    Some(format!(
                        "Reverse record for {address} claims a non-{} name",
                        label(system)
                    )),
                    Some(reverse_trust.clone()),
                )
            });
            continue;
        }
        let mut forward_trust = None;
        if let Ok(normalized) = fast_normalize(crate::js_trim(&claimed))
            && let Ok(node) = crate::namehash(&normalized)
        {
            let forward_call = ur::addr_call(&node);
            let forward = Lookup {
                name: &normalized,
                call_data: &forward_call,
                system: system.id(),
                resolver: Resolver::NameNft(system),
                prefetch: false,
            };
            if let Ok(Some(outcome)) = with_method(ctx, machine, method, &forward).await {
                forward_trust = Some(outcome.trust().clone());
                if let Consensus::Data { resolved, trust } = outcome
                    && let Some(Ok(Value::Address(found))) =
                        crate::abi::decode(&[Kind::Address], &resolved)
                            .ok()
                            .and_then(|f| f.into_iter().next())
                    && rpc::hex(&found) == address
                {
                    return Ok(Some(obj(vec![
                        ("success", JsValue::Bool(true)),
                        ("address", s(address)),
                        ("name", s(&normalized)),
                        ("system", s(system.id())),
                        ("trust", trust),
                    ])));
                }
            }
        }
        first_unverified.get_or_insert_with(|| {
            unverified_reverse(
                address,
                system,
                Some(&claimed),
                None,
                Some(forward_trust.unwrap_or(reverse_trust)),
            )
        });
    }
    Ok(Some(
        first_unverified.unwrap_or_else(|| no_reverse(address, last_trust)),
    ))
}

/// `doResolveEnsReverse`.
pub(crate) async fn reverse(
    ctx: &Ctx,
    machine: &crate::session::machine::Shared,
    address: &str,
    chain_id: u64,
) -> Result<JsValue, Thrown> {
    #[allow(clippy::cast_precision_loss)]
    let coin = coin_type(chain_id as f64)?;
    let (order, prefer_verified) = {
        let state = ctx.state.borrow();
        (state.config.order.clone(), state.config.prefer_verified)
    };
    let key = chain_key(address, chain_id);
    let mut provisional: Option<JsValue> = None;
    let mut last_error: Option<Thrown> = None;
    for method in &order {
        let attempt = async {
            if method == "myotis" {
                return myotis_reverse(ctx, address, coin).await;
            }
            let Some(ens) = ens_reverse_with(ctx, machine, method, address, coin).await? else {
                return Ok(None);
            };
            if chain_id != 1 {
                return Ok(Some(ens));
            }
            contract_backed_reverse(ctx, machine, method, address, ens).await
        };
        let result = match attempt.await {
            Ok(Some(result)) => result,
            Ok(None) => continue,
            Err(error) if error.lifecycle => return Err(error),
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let level = result
            .get("trust")
            .and_then(|t| t.get("level"))
            .and_then(JsValue::as_str);
        let provisional_result =
            level == Some("unverified") || result.get("reason") == Some(&s("UNVERIFIED"));
        if prefer_verified && provisional_result {
            if provisional.is_none() {
                provisional = Some(result);
            }
            continue;
        }
        return Ok(cache(ctx, Store::Reverse, &key, result));
    }
    if let Some(result) = provisional {
        return Ok(cache(ctx, Store::Reverse, &key, result));
    }
    Err(last_error.unwrap_or_else(|| {
        Thrown::new(format!(
            "No enabled name-resolution method could reverse-resolve {address}"
        ))
    }))
}
