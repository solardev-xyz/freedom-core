//! One discovery query (design 0007, "Network-specific NAT64 prefixes"):
//! AAAA for `ipv4only.arpa`, over plain DNS on UDP, to one resolver.
//!
//! The discovery-only path: this one name and type, and nothing else. The
//! resolver is a configured target for this query alone, asked from a
//! socket connected to it, so only its replies are read. Its answer is
//! parsed, never dialed: each AAAA record that embeds `192.0.0.170` or
//! `192.0.0.171` at one of RFC 6052's positions teaches a prefix
//! ([`Nat64Prefix::in_ipv4only_answer`]), and one that embeds neither
//! teaches nothing.
//!
//! - **An answer:** `NOERROR` with or without AAAA records, or `NXDOMAIN`
//!   (RFC 7050 §3: no prefix is advertised). A `NOERROR`'s TTL is the
//!   smallest of its AAAA records', or, without one, the negative TTL its
//!   SOA gives. An `NXDOMAIN` teaches nothing, whatever its answer section
//!   holds, and its TTL is its SOA's.
//! - **A failure:** no reply within the attempts, any other response code,
//!   a truncated reply, a reply outside the protocol (not a response to
//!   this query: another opcode or question), or a socket error, such as
//!   the resolver's port refusing.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use freedom_ipfs_addr::Nat64Prefix;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};

/// The name RFC 7050 has a DNS64 synthesize for.
pub const NAME: &str = "ipv4only.arpa.";

/// The UDP payload the query offers (EDNS0): the DNS flag day's 1232 bytes,
/// room for many more AAAA records than [`Nat64State::MAX_PREFIXES`].
///
/// [`Nat64State::MAX_PREFIXES`]: freedom_ipfs_addr::Nat64State::MAX_PREFIXES
const PAYLOAD: u16 = 1232;

/// The largest reply read. One that doesn't fit is refused, not read cut
/// short: the receive buffer is a byte longer, so a datagram that fills it
/// was larger.
pub const MAX_REPLY: usize = 4096;

/// What one resolver answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The prefixes its AAAA records teach, possibly none.
    pub prefixes: Vec<Nat64Prefix>,
    /// How long the answer may be kept: its AAAA records' smallest TTL, or
    /// without one its SOA's negative TTL, if it gave either.
    pub ttl: Option<Duration>,
}

/// Why a resolver gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The socket couldn't be opened, or sending or receiving failed (a
    /// refused port included).
    Socket,
    /// No reply within the attempts.
    Timeout,
    /// The reply was truncated, by the resolver (the TC bit), or by the
    /// receive because it was larger than [`MAX_REPLY`].
    Truncated,
    /// A response code other than `NOERROR` and `NXDOMAIN`, as a number.
    Rcode(u16),
    /// A reply that isn't a well-formed response to this query.
    Malformed,
    /// Its round was abandoned before it could send (discovery paused).
    Abandoned,
}

impl Failure {
    /// A fixed name for logs and stats.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Socket => "socket",
            Self::Timeout => "timeout",
            Self::Truncated => "truncated",
            Self::Rcode(_) => "rcode",
            Self::Malformed => "malformed",
            Self::Abandoned => "abandoned",
        }
    }
}

/// Whether a query may send: the check and the send as one step, so
/// nothing that ends the allowance can come between them.
pub trait Gate: Sync {
    /// Runs `send` if sends are allowed, the allowance held until it
    /// returns, and gives its result; `None` once they aren't allowed.
    fn run(&self, send: &dyn Fn() -> std::io::Result<usize>) -> Option<std::io::Result<usize>>;
}

/// Sends always allowed: tests.
#[cfg(test)]
pub struct Open;

#[cfg(test)]
impl Gate for Open {
    fn run(&self, send: &dyn Fn() -> std::io::Result<usize>) -> Option<std::io::Result<usize>> {
        Some(send())
    }
}

/// Asks `resolver` for `ipv4only.arpa`'s AAAA records, with query ID `id`:
/// up to `attempts` sends of the same query, each through `gate`, each
/// waiting `attempt` for its reply. A reply with another ID is skipped, as a
/// late one to another query would be.
///
/// A send doesn't block: a gate may hold a lock across it.
pub fn ask(
    resolver: SocketAddr,
    id: u16,
    attempt: Duration,
    attempts: u32,
    gate: &dyn Gate,
) -> Result<Answer, Failure> {
    let query = encode(id)?;
    let local: SocketAddr = if resolver.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local).map_err(|_| Failure::Socket)?;
    socket.connect(resolver).map_err(|_| Failure::Socket)?;
    let mut buffer = vec![0u8; MAX_REPLY + 1];
    for _ in 0..attempts.max(1) {
        socket.set_nonblocking(true).map_err(|_| Failure::Socket)?;
        let sent = gate.run(&|| socket.send(&query));
        socket.set_nonblocking(false).map_err(|_| Failure::Socket)?;
        match sent {
            None => return Err(Failure::Abandoned),
            // A full send buffer (`WouldBlock`) included.
            Some(Err(_)) => return Err(Failure::Socket),
            Some(Ok(_)) => {}
        }
        let deadline = Instant::now() + attempt;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            socket
                .set_read_timeout(Some(left))
                .map_err(|_| Failure::Socket)?;
            match socket.recv(&mut buffer) {
                // Too large: the kernel cut it short. Ours is refused as
                // truncated; another's is skipped, as any other is.
                Ok(read) if read > MAX_REPLY => {
                    if buffer.get(..2).is_some_and(|head| head == id.to_be_bytes()) {
                        return Err(Failure::Truncated);
                    }
                }
                Ok(read) => {
                    if let Some(reply) = buffer.get(..read).and_then(|reply| answer(reply, id)) {
                        return reply;
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    break;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                // Windows reports a datagram larger than the buffer as an
                // error, with the buffer filled; elsewhere it is cut short.
                Err(e) if oversize(&e) => {
                    if buffer.get(..2).is_some_and(|head| head == id.to_be_bytes()) {
                        return Err(Failure::Truncated);
                    }
                }
                Err(_) => return Err(Failure::Socket),
            }
        }
    }
    Err(Failure::Timeout)
}

/// Whether a receive failed because the datagram was larger than the
/// buffer: Windows' `WSAEMSGSIZE`.
fn oversize(error: &std::io::Error) -> bool {
    cfg!(windows) && error.raw_os_error() == Some(10040)
}

/// The query: ID `id`, recursion desired, one question (`ipv4only.arpa`,
/// AAAA, IN), and EDNS0 offering [`PAYLOAD`] bytes.
pub fn encode(id: u16) -> Result<Vec<u8>, Failure> {
    let name = Name::from_ascii(NAME).map_err(|_| Failure::Malformed)?;
    let mut message = Message::new();
    message
        .set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(name, RecordType::AAAA));
    let mut edns = Edns::new();
    edns.set_max_payload(PAYLOAD);
    message.set_edns(edns);
    message.to_vec().map_err(|_| Failure::Malformed)
}

/// What `reply` says, if it is a reply to query `id`: `None` for a
/// message with another ID, which is skipped.
pub fn answer(reply: &[u8], id: u16) -> Option<Result<Answer, Failure>> {
    let Ok(message) = Message::from_vec(reply) else {
        // Its ID, if it has one, decides whether it was ours.
        let ours = reply.get(..2).is_some_and(|head| head == id.to_be_bytes());
        return ours.then_some(Err(Failure::Malformed));
    };
    if message.id() != id {
        return None;
    }
    Some(read(&message))
}

/// A reply to our query, read.
fn read(message: &Message) -> Result<Answer, Failure> {
    let ours = Name::from_ascii(NAME).map_err(|_| Failure::Malformed)?;
    let question_matches = matches!(message.queries(), [query]
        if *query.name() == ours
            && query.query_type() == RecordType::AAAA
            && query.query_class() == DNSClass::IN);
    if message.message_type() != MessageType::Response
        || message.op_code() != OpCode::Query
        || !question_matches
    {
        return Err(Failure::Malformed);
    }
    if message.truncated() {
        return Err(Failure::Truncated);
    }
    let nxdomain = match message.response_code() {
        ResponseCode::NoError => false,
        ResponseCode::NXDomain => true,
        other => return Err(Failure::Rcode(u16::from(other))),
    };
    let mut prefixes = Vec::new();
    let mut ttl: Option<u32> = None;
    // NXDOMAIN: the name doesn't exist, so no prefix is advertised (RFC 7050
    // §3), whatever its answer section holds.
    let answers = if nxdomain { &[][..] } else { message.answers() };
    for record in answers {
        if let RData::AAAA(aaaa) = record.data() {
            prefixes.extend(Nat64Prefix::in_ipv4only_answer(aaaa.0));
            ttl = Some(ttl.map_or(record.ttl(), |ttl| ttl.min(record.ttl())));
        }
    }
    if ttl.is_none() {
        // No AAAA record: the negative answer's TTL (RFC 2308 §5).
        ttl = message
            .name_servers()
            .iter()
            .find_map(|record| match record.data() {
                RData::SOA(soa) => Some(record.ttl().min(soa.minimum())),
                _ => None,
            });
    }
    Ok(Answer {
        prefixes,
        ttl: ttl.map(|seconds| Duration::from_secs(u64::from(seconds))),
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{AAAA, SOA};
    use hickory_proto::rr::{Record, RecordData};
    use std::sync::mpsc;

    /// A reply to `query` (bytes the client sent): `rcode`, these AAAA
    /// records (address, TTL) and, if given, an SOA with this TTL and
    /// minimum. `edit` may change the message before it is encoded.
    pub fn reply_to(
        query: &[u8],
        rcode: ResponseCode,
        records: &[(Ipv6Addr, u32)],
        soa: Option<(u32, u32)>,
        edit: impl FnOnce(&mut Message),
    ) -> Vec<u8> {
        let query = Message::from_vec(query).unwrap();
        let mut message = Message::new();
        message
            .set_id(query.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .set_recursion_available(true)
            .set_response_code(rcode);
        for question in query.queries() {
            message.add_query(question.clone());
        }
        let name = Name::from_ascii(NAME).unwrap();
        for (addr, ttl) in records {
            message.add_answer(Record::from_rdata(
                name.clone(),
                *ttl,
                AAAA(*addr).into_rdata(),
            ));
        }
        if let Some((ttl, minimum)) = soa {
            let soa = SOA::new(
                Name::from_ascii("arpa.").unwrap(),
                Name::from_ascii("hostmaster.arpa.").unwrap(),
                1,
                3600,
                600,
                86400,
                minimum,
            );
            message.add_name_server(Record::from_rdata(
                Name::from_ascii("arpa.").unwrap(),
                ttl,
                soa.into_rdata(),
            ));
        }
        edit(&mut message);
        message.to_vec().unwrap()
    }

    /// A resolver on loopback that answers each query it gets with what
    /// `respond` returns for its bytes (a list of datagrams, possibly
    /// empty), and reports each query it got, before answering it. It keeps
    /// answering when nobody reads the reports.
    pub fn resolver(
        respond: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
    ) -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let (sent, got) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            while let Ok((read, from)) = socket.recv_from(&mut buffer) {
                let query = buffer[..read].to_vec();
                // Reported before it is answered: once its answer is read,
                // the query is in the report.
                let _ = sent.send(query.clone());
                for datagram in respond(&query) {
                    let _ = socket.send_to(&datagram, from);
                }
            }
        });
        (addr, got)
    }

    fn v6(text: &str) -> Ipv6Addr {
        text.parse().unwrap()
    }

    fn prefix(text: &str, len: u8) -> Nat64Prefix {
        Nat64Prefix::new(v6(text), len).unwrap()
    }

    const ATTEMPT: Duration = Duration::from_millis(300);

    #[test]
    fn the_query_is_one_aaaa_question_for_ipv4only_arpa_with_edns() {
        let query = Message::from_vec(&encode(0x1234).unwrap()).unwrap();
        assert_eq!(query.id(), 0x1234);
        assert_eq!(query.message_type(), MessageType::Query);
        assert_eq!(query.op_code(), OpCode::Query);
        assert!(query.recursion_desired());
        assert_eq!(query.queries().len(), 1);
        let question = &query.queries()[0];
        assert_eq!(question.name().to_ascii(), NAME);
        assert_eq!(question.query_type(), RecordType::AAAA);
        assert_eq!(question.query_class(), DNSClass::IN);
        assert_eq!(query.extensions().as_ref().unwrap().max_payload(), PAYLOAD);
        assert!(query.answers().is_empty());
    }

    #[test]
    fn an_answer_teaches_the_prefixes_its_records_embed() {
        let (addr, got) = resolver(|query| {
            vec![reply_to(
                query,
                ResponseCode::NoError,
                &[
                    // 192.0.0.170 under 64:ff9b::/96 and 192.0.0.171 under a /64.
                    (v6("64:ff9b::c000:aa"), 300),
                    (v6("2a00:1:2:3:c0:0:ab00:0"), 120),
                    // Neither well-known address: nothing.
                    (v6("2a00:1::808:808"), 30),
                ],
                None,
                |_| {},
            )]
        });
        let answer = ask(addr, 7, ATTEMPT, 1, &Open).unwrap();
        assert_eq!(
            answer.prefixes,
            vec![prefix("64:ff9b::", 96), prefix("2a00:1:2:3::", 64)]
        );
        // The smallest AAAA TTL, the record that teaches nothing included.
        assert_eq!(answer.ttl, Some(Duration::from_secs(30)));
        // One query, and only ours.
        let query = got.recv().unwrap();
        assert_eq!(query, encode(7).unwrap());
        assert!(got.try_recv().is_err());
    }

    #[test]
    fn nodata_and_nxdomain_teach_nothing_with_the_negative_ttl() {
        for rcode in [ResponseCode::NoError, ResponseCode::NXDomain] {
            let (addr, _) =
                resolver(move |query| vec![reply_to(query, rcode, &[], Some((900, 60)), |_| {})]);
            assert_eq!(
                ask(addr, 9, ATTEMPT, 1, &Open),
                Ok(Answer {
                    prefixes: vec![],
                    ttl: Some(Duration::from_secs(60)),
                }),
                "{rcode:?}"
            );
            let (addr, _) = resolver(move |query| vec![reply_to(query, rcode, &[], None, |_| {})]);
            assert_eq!(
                ask(addr, 9, ATTEMPT, 1, &Open),
                Ok(Answer {
                    prefixes: vec![],
                    ttl: None,
                }),
                "{rcode:?}"
            );
        }
    }

    #[test]
    fn nxdomain_teaches_nothing_even_with_answers() {
        for soa in [Some((900, 60)), None] {
            let (addr, _) = resolver(move |query| {
                vec![reply_to(
                    query,
                    ResponseCode::NXDomain,
                    &[(v6("64:ff9b::c000:aa"), 30)],
                    soa,
                    |_| {},
                )]
            });
            assert_eq!(
                ask(addr, 9, ATTEMPT, 1, &Open),
                Ok(Answer {
                    prefixes: vec![],
                    ttl: soa.map(|_| Duration::from_secs(60)),
                }),
                "{soa:?}"
            );
        }
    }

    #[test]
    fn a_reply_larger_than_the_buffer_is_refused_not_read_cut_short() {
        // The adversarial review's probe: past MAX_REPLY, the kernel cuts
        // the datagram short, and what is left would parse.
        let (addr, _) = resolver(|query| {
            let mut reply = reply_to(
                query,
                ResponseCode::NoError,
                &[(v6("64:ff9b::c000:aa"), 60)],
                None,
                |_| {},
            );
            reply.resize(MAX_REPLY + 100, 0);
            vec![reply]
        });
        assert_eq!(
            ask(addr, 0x4242, ATTEMPT, 1, &Open),
            Err(Failure::Truncated)
        );
        // One that fills the buffer exactly is read.
        let (addr, _) = resolver(|query| {
            let mut reply = reply_to(
                query,
                ResponseCode::NoError,
                &[(v6("64:ff9b::c000:aa"), 60)],
                None,
                |_| {},
            );
            reply.resize(MAX_REPLY, 0);
            vec![reply]
        });
        assert!(ask(addr, 0x4242, ATTEMPT, 1, &Open).is_ok());
    }

    #[test]
    fn an_abandoned_query_sends_nothing_more() {
        let (addr, got) = resolver(|_| vec![]);
        /// Allows the first send only.
        struct First(std::sync::atomic::AtomicUsize);
        impl Gate for First {
            fn run(
                &self,
                send: &dyn Fn() -> std::io::Result<usize>,
            ) -> Option<std::io::Result<usize>> {
                (self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0).then(send)
            }
        }
        let gate = First(std::sync::atomic::AtomicUsize::new(0));
        assert_eq!(
            ask(addr, 1, Duration::from_millis(100), 3, &gate),
            Err(Failure::Abandoned)
        );
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(got.try_iter().count(), 1);
    }

    #[test]
    fn other_response_codes_fail() {
        for (rcode, number) in [
            (ResponseCode::ServFail, 2),
            (ResponseCode::Refused, 5),
            (ResponseCode::FormErr, 1),
            (ResponseCode::NotImp, 4),
        ] {
            let (addr, _) = resolver(move |query| {
                vec![reply_to(
                    query,
                    rcode,
                    &[(v6("64:ff9b::c000:aa"), 60)],
                    None,
                    |_| {},
                )]
            });
            assert_eq!(ask(addr, 1, ATTEMPT, 1, &Open), Err(Failure::Rcode(number)));
        }
    }

    #[test]
    fn a_truncated_reply_fails() {
        let (addr, _) = resolver(|query| {
            vec![reply_to(
                query,
                ResponseCode::NoError,
                &[],
                None,
                |message| {
                    message.set_truncated(true);
                },
            )]
        });
        assert_eq!(ask(addr, 1, ATTEMPT, 1, &Open), Err(Failure::Truncated));
    }

    #[test]
    fn a_reply_to_another_question_or_not_a_response_is_malformed() {
        let edits: [fn(&mut Message); 4] = [
            |message| {
                message.set_message_type(MessageType::Query);
            },
            |message| {
                message.set_op_code(OpCode::Status);
            },
            |message| {
                let mut other = message.clone();
                other.take_queries();
                other.add_query(Query::query(
                    Name::from_ascii("example.com.").unwrap(),
                    RecordType::AAAA,
                ));
                *message = other;
            },
            |message| {
                let mut other = message.clone();
                other.take_queries();
                other.add_query(Query::query(Name::from_ascii(NAME).unwrap(), RecordType::A));
                *message = other;
            },
        ];
        for edit in edits {
            let (addr, _) = resolver(move |query| {
                vec![reply_to(
                    query,
                    ResponseCode::NoError,
                    &[(v6("64:ff9b::c000:aa"), 60)],
                    None,
                    edit,
                )]
            });
            assert_eq!(ask(addr, 1, ATTEMPT, 1, &Open), Err(Failure::Malformed));
        }
        // Bytes that don't parse, under our ID.
        let (addr, _) = resolver(|query| vec![[&query[..2], &[0xff; 5][..]].concat()]);
        assert_eq!(ask(addr, 1, ATTEMPT, 1, &Open), Err(Failure::Malformed));
    }

    #[test]
    fn another_id_is_skipped_and_ours_still_read() {
        let (addr, _) = resolver(|query| {
            let ours = reply_to(
                query,
                ResponseCode::NoError,
                &[(v6("64:ff9b::c000:aa"), 60)],
                None,
                |_| {},
            );
            // Another ID's reply, which would fail the query if read.
            let mut stray = reply_to(query, ResponseCode::ServFail, &[], None, |_| {});
            stray[0] ^= 0xff;
            // Garbage under another ID, then a reply under another ID, then ours.
            vec![vec![0x00, 0x01, 0xff], stray, ours]
        });
        let answer = ask(addr, 0x0203, ATTEMPT, 1, &Open).unwrap();
        assert_eq!(answer.prefixes, vec![prefix("64:ff9b::", 96)]);
    }

    #[test]
    fn a_reply_from_another_address_is_never_read() {
        // A forger on another port answers first, under our ID, with a
        // prefix; the resolver itself then answers NXDOMAIN.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let forger = UdpSocket::bind("127.0.0.1:0").unwrap();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            let (read, from) = socket.recv_from(&mut buffer).unwrap();
            let query = &buffer[..read];
            let forged = reply_to(
                query,
                ResponseCode::NoError,
                &[(v6("64:ff9b::c000:aa"), 60)],
                None,
                |_| {},
            );
            forger.send_to(&forged, from).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            let genuine = reply_to(query, ResponseCode::NXDomain, &[], None, |_| {});
            socket.send_to(&genuine, from).unwrap();
        });
        assert_eq!(
            ask(addr, 0x4242, ATTEMPT, 1, &Open),
            Ok(Answer {
                prefixes: vec![],
                ttl: None,
            })
        );
    }

    #[test]
    fn no_reply_times_out_after_every_attempt() {
        let (addr, got) = resolver(|_| vec![]);
        let started = Instant::now();
        assert_eq!(
            ask(addr, 1, Duration::from_millis(100), 3, &Open),
            Err(Failure::Timeout)
        );
        assert!(started.elapsed() >= Duration::from_millis(300));
        // The same query, three times.
        let sent: Vec<Vec<u8>> = got.try_iter().collect();
        assert_eq!(sent, vec![encode(1).unwrap(); 3]);
    }

    #[test]
    fn a_second_attempt_can_answer() {
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = count.clone();
        let (addr, _) = resolver(move |query| {
            if seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                vec![]
            } else {
                vec![reply_to(query, ResponseCode::NoError, &[], None, |_| {})]
            }
        });
        assert!(ask(addr, 1, Duration::from_millis(150), 2, &Open).is_ok());
    }

    #[test]
    fn a_closed_port_fails_without_waiting_out_the_attempts() {
        // A port nothing listens on: the ICMP error refuses the connected
        // socket's receive (on Linux and macOS; Windows reports it too).
        let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let result = ask(addr, 1, Duration::from_millis(200), 2, &Open);
        assert!(
            matches!(result, Err(Failure::Socket | Failure::Timeout)),
            "{result:?}"
        );
    }
}
