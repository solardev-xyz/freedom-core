//! Verified methods: whole Myotis and Colibri operations through main's
//! adapters (design 0004, Verified operations).

use super::*;

pub(crate) async fn verified(ctx: &Ctx, op: VerifiedOp) -> Verified {
    match ctx.rt.request(Request::Verified(op)).await {
        Answer::Verified(outcome) => outcome,
        _ => Verified::Failure("error".into()),
    }
}

/// `buildMyotisTrust`.
pub(crate) fn myotis_trust(finalized: bool, block: JsValue, system: &str) -> JsValue {
    let p2p = JsValue::Array(vec![s("myotis-p2p")]);
    obj(vec![
        ("level", s("verified")),
        ("system", s(system)),
        ("method", s("myotis")),
        (
            "finality",
            s(if finalized { "finalized" } else { "optimistic" }),
        ),
        (
            "proof",
            s(if finalized {
                "P2P light client (beacon-finalized, sync-committee proof)"
            } else {
                "P2P light client (optimistic beacon root — attested, not finalized)"
            }),
        ),
        ("block", block),
        ("agreed", p2p.clone()),
        ("dissented", JsValue::Array(Vec::new())),
        ("queried", p2p),
        (
            "quorum",
            obj(vec![
                ("k", JsValue::Number(1.0)),
                ("m", JsValue::Number(1.0)),
                ("achieved", JsValue::Bool(true)),
            ]),
        ),
    ])
}

/// `buildColibriTrust`: the prover as an endpoint reference ("" without one).
pub(crate) fn colibri_trust(ctx: &Ctx, system: &str) -> JsValue {
    let prover = ctx.state.borrow().config.prover.clone();
    let (host, zk) = match &prover {
        Some((endpoint, zk)) => (obj(vec![("ref", s(endpoint))]), *zk),
        None => (s(""), true),
    };
    obj(vec![
        ("level", s("verified")),
        ("system", s(system)),
        ("method", s("colibri")),
        ("prover", host.clone()),
        (
            "proof",
            s(if zk {
                "ZK sync-committee proof"
            } else {
                "Sync-committee proof"
            }),
        ),
        ("block", JsValue::Null),
        ("agreed", JsValue::Array(vec![host.clone()])),
        ("dissented", JsValue::Array(Vec::new())),
        ("queried", JsValue::Array(vec![host])),
        (
            "quorum",
            obj(vec![
                ("k", JsValue::Number(1.0)),
                ("m", JsValue::Number(1.0)),
                ("achieved", JsValue::Bool(true)),
            ]),
        ),
    ])
}

/// The error of an operation through `universalResolverCall`: for a name
/// `dnsEncode(name, 255)` refuses, an `invalid_argument` failure (ethers'
/// own argument check, which main reports without text) is that refusal,
/// whose message the reference keeps.
fn ur_error(outcome: &Verified, name: &str) -> Thrown {
    match (outcome, super::leg::label_too_long(name)) {
        (Verified::Failure(class), Some(message)) if class == "invalid_argument" => {
            Thrown::new(message)
        }
        _ => verifier_error(outcome),
    }
}

/// A verifier's thrown error, by its outcome.
pub(crate) fn verifier_error(outcome: &Verified) -> Thrown {
    match outcome {
        Verified::Failure(class) => Thrown::new(format!("verified call failed: {class}")),
        Verified::Revert(_) => Thrown::new("execution reverted"),
        Verified::Result(_) => Thrown::new("unexpected verified answer"),
    }
}

pub(crate) fn myotis_epoch(ctx: &Ctx) -> (bool, u64) {
    let state = ctx.state.borrow();
    (state.myotis_ready, state.myotis_epoch)
}

/// `tryMyotisPath` behind `resolveWithMethod('myotis')`: `Ok(None)` when
/// Myotis is disabled or not ready.
pub(crate) async fn myotis(ctx: &Ctx, lookup: &Lookup<'_>) -> Result<Option<Consensus>, Thrown> {
    if !ctx.state.borrow().config.myotis_enabled {
        return Ok(None);
    }
    let (ready, epoch) = myotis_epoch(ctx);
    if !ready {
        return Ok(None);
    }
    let system = NameSystem::for_name(lookup.name);
    let result = match lookup.resolver {
        Resolver::NameNft(system) | Resolver::NameNftReverse(system) => {
            myotis_contract(ctx, lookup.call_data, system)
                .await?
                .map(|(data, trust)| Consensus::Data {
                    resolved: data,
                    trust,
                })
        }
        Resolver::Ur => myotis_ens(ctx, lookup, system).await?,
        Resolver::UrReverse { .. } => None,
    };
    if myotis_epoch(ctx) != (true, epoch) {
        return Err(Thrown::lifecycle(
            "Myotis availability changed during verified read",
        ));
    }
    Ok(result)
}

/// `tryMyotisContractPath`: the raw result and its trust.
pub(crate) async fn myotis_contract(
    ctx: &Ctx,
    call_data: &[u8],
    system: NameSystem,
) -> Result<Option<(Vec<u8>, JsValue)>, Thrown> {
    let Some(to) = system.registry() else {
        return Ok(None);
    };
    let outcome = verified(
        ctx,
        VerifiedOp::MyotisCall {
            to,
            data: call_data.to_vec(),
        },
    )
    .await;
    let Verified::Result(result) = &outcome else {
        return Err(verifier_error(&outcome));
    };
    let data = result
        .get("resultHex")
        .and_then(JsValue::as_str)
        .and_then(rpc::hex_string)
        .ok_or_else(|| Thrown::new("Myotis contract call unavailable"))?;
    let block = result
        .get("optimisticBlockNumber")
        .cloned()
        .unwrap_or(JsValue::Null);
    Ok(Some((data, myotis_trust(false, block, system.id()))))
}

/// `tryMyotisEnsPath`: `Ok(None)` for a selector outside content and
/// address.
pub(crate) async fn myotis_ens(
    ctx: &Ctx,
    lookup: &Lookup<'_>,
    system: NameSystem,
) -> Result<Option<Consensus>, Thrown> {
    let selector = lookup.call_data.get(..4).unwrap_or(&[]);
    let multicoin = selector == ur::ADDR_MULTICOIN;
    let method = if selector == ur::CONTENTHASH {
        "contenthash"
    } else if selector == ur::ADDR || multicoin {
        "addr"
    } else {
        return Ok(None);
    };
    let coin_type = if multicoin {
        lookup.call_data.get(36..68).map_or(60, |word| {
            word[24..]
                .iter()
                .fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
        })
    } else {
        60
    };
    let op = VerifiedOp::MyotisRecord {
        method,
        name: Some(lookup.name.to_owned()),
        address: None,
        coin_type,
    };
    let outcome = verified(ctx, op).await;
    let Verified::Result(record) = &outcome else {
        return Err(ur_error(&outcome, lookup.name));
    };
    let finalized = record.get("verified") == Some(&JsValue::Bool(true));
    let block = record.get("blockNumber").cloned().unwrap_or(JsValue::Null);
    let trust = myotis_trust(finalized, block, system.id());
    let status = record.get("status").and_then(JsValue::as_str);
    let encode = |value: &[u8], dynamic: bool| {
        if dynamic {
            crate::abi::encode(&[crate::abi::Token::Dynamic(value)])
        } else {
            let mut word = [0u8; 20];
            if value.len() == 20 {
                word.copy_from_slice(value);
            }
            crate::abi::encode(&[crate::abi::Token::Word(crate::abi::word_from_address(
                &word,
            ))])
        }
    };
    let dynamic = method == "contenthash" || multicoin;
    if status == Some("noRecord") {
        return Ok(Some(Consensus::Data {
            resolved: encode(&[], dynamic),
            trust,
        }));
    }
    if status != Some("ok") {
        return Err(Thrown::new(format!("unexpected {method} record shape")));
    }
    let field = if method == "contenthash" {
        "dataHex"
    } else {
        "addressHex"
    };
    let value = record
        .get(field)
        .and_then(JsValue::as_str)
        .filter(|v| !v.is_empty())
        .and_then(rpc::hex_string)
        .ok_or_else(|| Thrown::new(format!("missing {method} value")))?;
    Ok(Some(Consensus::Data {
        resolved: encode(&value, dynamic),
        trust,
    }))
}

/// `tryColibriPath`.
pub(crate) async fn colibri(ctx: &Ctx, lookup: &Lookup<'_>) -> Result<Consensus, Thrown> {
    if ctx.state.borrow().config.prover.is_none() {
        return Err(Thrown::new("No Colibri prover configured for chain 1"));
    }
    let resolver = match lookup.resolver {
        Resolver::NameNft(_) => "name_nft",
        Resolver::NameNftReverse(_) => "name_nft_reverse",
        _ => "ur",
    };
    let op = VerifiedOp::ColibriResolve {
        name: lookup.name.to_owned(),
        call_data: lookup.call_data.to_vec(),
        resolver,
    };
    let trust = colibri_trust(ctx, lookup.system);
    match verified(ctx, op).await {
        Verified::Result(result) => {
            let data = result
                .get("resolvedData")
                .and_then(JsValue::as_str)
                .and_then(rpc::hex_string)
                .ok_or_else(|| Thrown::new("unexpected Colibri answer"))?;
            Ok(Consensus::Data {
                resolved: data,
                trust,
            })
        }
        Verified::Revert(data)
            if revert_names(
                &data,
                &["0x77209fe8", "0x1e9535f2"],
                &["resolvernotfound", "resolvernotcontract"],
            ) =>
        {
            Ok(Consensus::NotFound {
                reason: "NO_RESOLVER",
                error: None,
                trust,
            })
        }
        other if resolver == "ur" => Err(ur_error(&other, lookup.name)),
        other => Err(verifier_error(&other)),
    }
}

/// A proven revert's selector, or an `Error(string)` reason naming it.
pub(crate) fn revert_names(data: &[u8], selectors: &[&str], reasons: &[&str]) -> bool {
    let error = CallError::Rpc(RpcError::CallException {
        data: Some(data.to_vec()),
        node: None,
    });
    error
        .selector()
        .is_some_and(|sel| selectors.contains(&sel.as_str()))
        || error.reason_names(reasons)
}

/// `tryColibriReverse`.
pub(crate) async fn colibri_reverse(
    ctx: &Ctx,
    address: &str,
    coin_type: u64,
) -> Result<JsValue, Thrown> {
    let trust = colibri_trust(ctx, "ens");
    match verified(
        ctx,
        VerifiedOp::ColibriReverse {
            address: address.to_owned(),
            coin_type,
        },
    )
    .await
    {
        Verified::Result(result) => match result
            .get("name")
            .and_then(JsValue::as_str)
            .filter(|n| !n.is_empty())
        {
            Some(name) => Ok(obj(vec![
                ("success", JsValue::Bool(true)),
                ("address", s(address)),
                ("name", s(name)),
                ("system", s("ens")),
                ("trust", trust),
            ])),
            None => Ok(no_reverse(address, Some(trust))),
        },
        Verified::Revert(data)
            if revert_names(
                &data,
                &["0x77209fe8", "0x1e9535f2"],
                &["resolvernotfound", "resolvernotcontract"],
            ) =>
        {
            Ok(no_reverse(address, Some(trust)))
        }
        Verified::Revert(data)
            if revert_names(&data, &["0xef9c03ce"], &["reverseaddressmismatch"]) =>
        {
            let claimed = ur::reverse_mismatch_claimed_name(&data);
            Ok(obj(vec![
                ("success", JsValue::Bool(false)),
                ("address", s(address)),
                ("system", s("ens")),
                ("reason", s("UNVERIFIED")),
                ("claimedName", claimed.map_or(JsValue::Null, |c| s(&c))),
                (
                    "error",
                    s(&format!(
                        "Reverse record for {address} does not forward-verify"
                    )),
                ),
                ("trust", trust),
            ]))
        }
        other => Err(verifier_error(&other)),
    }
}

/// `tryMyotisReverse` (`readMyotisReverse` inside the epoch guard).
pub(crate) async fn myotis_reverse(
    ctx: &Ctx,
    address: &str,
    coin_type: u64,
) -> Result<Option<JsValue>, Thrown> {
    if !ctx.state.borrow().config.myotis_enabled {
        return Ok(None);
    }
    let (ready, epoch) = myotis_epoch(ctx);
    if !ready {
        return Ok(None);
    }
    let result = read_myotis_reverse(ctx, address, coin_type).await?;
    if myotis_epoch(ctx) != (true, epoch) {
        return Err(Thrown::lifecycle(
            "Myotis availability changed during verified reverse read",
        ));
    }
    Ok(Some(result))
}

/// `readMyotisReverse`.
pub(crate) async fn read_myotis_reverse(
    ctx: &Ctx,
    address: &str,
    coin_type: u64,
) -> Result<JsValue, Thrown> {
    let op = VerifiedOp::MyotisRecord {
        method: "reverse",
        name: None,
        address: Some(address.to_owned()),
        coin_type,
    };
    let record = match verified(ctx, op).await {
        Verified::Result(record) => record,
        Verified::Revert(data)
            if revert_names(&data, &["0xef9c03ce"], &["reverseaddressmismatch"]) =>
        {
            let claimed = ur::reverse_mismatch_claimed_name(&data);
            return Ok(unverified_reverse(
                address,
                NameSystem::Ens,
                claimed.as_deref(),
                None,
                Some(myotis_trust(false, JsValue::Null, "ens")),
            ));
        }
        other => return Err(verifier_error(&other)),
    };
    let ens_trust = myotis_trust(
        record.get("verified") == Some(&JsValue::Bool(true)),
        record.get("blockNumber").cloned().unwrap_or(JsValue::Null),
        "ens",
    );
    let status = record.get("status").and_then(JsValue::as_str);
    if let (Some("ok"), Some(name)) = (
        status,
        record
            .get("name")
            .and_then(JsValue::as_str)
            .filter(|n| !n.is_empty()),
    ) {
        return Ok(obj(vec![
            ("success", JsValue::Bool(true)),
            ("address", s(address)),
            ("name", s(name)),
            ("system", s("ens")),
            ("trust", ens_trust),
        ]));
    }
    if status != Some("noRecord") {
        return Err(Thrown::new("unexpected reverse record shape"));
    }
    if coin_type != 60 {
        return Ok(no_reverse(address, Some(ens_trust)));
    }
    let Some(bytes) = rpc::hex_string(address).and_then(|b| <[u8; 20]>::try_from(b).ok()) else {
        return Ok(no_reverse(address, Some(ens_trust)));
    };
    let mut first_unverified: Option<JsValue> = None;
    let mut last_trust = ens_trust;
    for system in [NameSystem::Wns, NameSystem::Gns] {
        let Some((resolved, reverse_trust)) =
            myotis_contract(ctx, &ur::reverse_resolve_call(&bytes), system).await?
        else {
            continue;
        };
        last_trust = reverse_trust.clone();
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
            && let Ok(Some((data, trust))) =
                myotis_contract(ctx, &ur::addr_call(&node), system).await
        {
            forward_trust = Some(trust.clone());
            if let Some(Ok(Value::Address(found))) = crate::abi::decode(&[Kind::Address], &data)
                .ok()
                .and_then(|f| f.into_iter().next())
                && rpc::hex(&found) == address
            {
                return Ok(obj(vec![
                    ("success", JsValue::Bool(true)),
                    ("address", s(address)),
                    ("name", s(&normalized)),
                    ("system", s(system.id())),
                    ("trust", trust),
                ]));
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
    Ok(first_unverified.unwrap_or_else(|| no_reverse(address, Some(last_trust))))
}
