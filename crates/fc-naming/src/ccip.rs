//! EIP-3668 (CCIP-Read) gateway requests, as `ccip-fetch.js` builds and
//! checks them. The core builds and checks every URL; main only fetches
//! it, with the transport bounds (design 0003).

use url::{Host, Url};

/// How to call a gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayRequest {
    /// The expanded template, exactly as the JS hands it to its transport.
    pub url: String,
    pub method: Method,
    /// For POST: `JSON.stringify({ sender, data })`.
    pub body: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// Expands a URL template from an `OffchainLookup` and applies the gateway
/// policy: HTTPS only, no credentials, no IP literals, a dotted host with
/// no empty label, and none of `*.localhost`, `*.local`, `*.internal`.
/// `None` means the JS refuses the URL and moves on to the next one.
///
/// One trailing dot is stripped first, as the JS does. Any empty label
/// left (`localhost..`, `node.internal..`, `a..b.example`) is refused
/// (deviation `ccip-hosts`, #76): the JS strips only one dot, so a second
/// one passed its suffix and dot checks.
///
/// Main checks the rest, which needs the network: the `.onion` rule (it
/// depends on the session's proxy) and, at connect time, the resolved
/// address (design 0004, CCIP-Read).
pub fn gateway_request(
    template: &str,
    sender: &[u8; 20],
    call_data: &[u8],
) -> Option<GatewayRequest> {
    let sender = format!("0x{}", to_hex(sender));
    let data = format!("0x{}", to_hex(call_data));
    let url = template
        .replace("{sender}", &sender)
        .replace("{data}", &data);
    let parsed = Url::parse(&url).ok()?;
    if parsed.scheme() != "https" || !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let host = match parsed.host()? {
        // `isIP` on the normalized host: WHATWG already turned numeric and
        // hex IPv4 forms into dotted quads.
        Host::Ipv4(_) | Host::Ipv6(_) => return None,
        // One trailing dot, as `.replace(/\.$/, '')`.
        Host::Domain(domain) => domain.strip_suffix('.').unwrap_or(domain).to_lowercase(),
    };
    if !host.contains('.')
        || host.split('.').any(str::is_empty)
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return None;
    }
    let get = template.contains("{data}");
    Some(GatewayRequest {
        url,
        method: if get { Method::Get } else { Method::Post },
        body: (!get).then(|| format!(r#"{{"sender":"{sender}","data":"{data}"}}"#)),
    })
}

/// The answer's `data`: `JSON.parse(body).data`, which must be `0x`, even
/// length, hex. The body is decoded as UTF-8 the way Node does it, with
/// invalid sequences replaced, and parsed as V8 parses JSON, so nothing
/// elsewhere in the document changes the outcome.
pub fn parse_gateway_response(body: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(body);
    let json = crate::jsjson::parse(&text).ok()?;
    let data = json.get("data")?.as_str()?;
    let hex = data.strip_prefix("0x")?;
    if hex.len() % 2 != 0 {
        return None;
    }
    hex.as_bytes().chunks(2).map(crate::hex_byte).collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER: [u8; 20] = [0xee; 20];

    #[test]
    fn expands_get_and_post() {
        let get =
            gateway_request("https://gw.example/{sender}/{data}.json", &SENDER, &[1, 2]).unwrap();
        assert_eq!(get.method, Method::Get);
        assert_eq!(
            get.url,
            format!("https://gw.example/0x{}/0x0102.json", "ee".repeat(20))
        );
        assert_eq!(get.body, None);
        let post = gateway_request("https://gw.example/lookup", &SENDER, &[0xab]).unwrap();
        assert_eq!(post.method, Method::Post);
        assert_eq!(
            post.body.unwrap(),
            format!(r#"{{"sender":"0x{}","data":"0xab"}}"#, "ee".repeat(20))
        );
    }

    #[test]
    fn refuses_what_ccip_fetch_refuses() {
        for url in [
            "http://gw.example/{data}",
            "https://user:pass@gw.example/{data}",
            "https://user@gw.example/{data}",
            "https://127.0.0.1/{data}",
            "https://2130706433/{data}",
            "https://0x7f.1/{data}",
            "https://[::1]/{data}",
            "https://[::ffff:127.0.0.1]/{data}",
            "https://localhost/{data}",
            "https://node.localhost/{data}",
            "https://printer.local/{data}",
            "https://svc.internal/{data}",
            "https://gateway/{data}",
            "not a url",
        ] {
            assert_eq!(gateway_request(url, &SENDER, &[1]), None, "{url}");
        }
        // A trailing dot is ignored for the checks, as in the JS.
        assert!(gateway_request("https://node.localhost./{data}", &SENDER, &[1]).is_none());
        assert!(gateway_request("https://gw.example./{data}", &SENDER, &[1]).is_some());
    }

    #[test]
    fn parses_answers() {
        assert_eq!(
            parse_gateway_response(br#"{"data":"0x00ff"}"#),
            Some(vec![0, 255])
        );
        assert_eq!(parse_gateway_response(br#"{"data":"0x"}"#), Some(vec![]));
        // Invalid UTF-8 outside `data` doesn't matter, as in Node.
        assert_eq!(
            parse_gateway_response(b"{\"x\":\"\xff\",\"data\":\"0x01\"}"),
            Some(vec![1])
        );
        // As V8: a huge number and a lone surrogate elsewhere are fine, and a
        // repeated key takes its last value.
        assert_eq!(
            parse_gateway_response(br#"{"data":"0x01","ignored":1e400}"#),
            Some(vec![1])
        );
        assert_eq!(
            parse_gateway_response(br#"{"x":"\ud800","data":"0x01"}"#),
            Some(vec![1])
        );
        assert_eq!(
            parse_gateway_response(br#"{"data":"0x01","data":"0x02"}"#),
            Some(vec![2])
        );
        for body in [
            &br#"{"data":"0x0"}"#[..],
            br#"{"data":"00ff"}"#,
            br#"{"data":"0X00"}"#,
            br#"{"data":"0xzz"}"#,
            br#"{"data":1}"#,
            br#"[1]"#,
            b"\xef\xbb\xbf{\"data\":\"0x\"}",
            b"nope",
        ] {
            assert_eq!(
                parse_gateway_response(body),
                None,
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }
}
