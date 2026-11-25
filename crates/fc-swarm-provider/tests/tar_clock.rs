//! A tar's header times as the reference writes them: bee-js 13.2.0's
//! `TarStream.beginFile` (`swarm.publish`'s collections) and page-upload.js's
//! `tarPieces` (a page's `publishFiles`) each read `Date.now()` for a header
//! as they write it, once the entry before it has gone out. So an entry that
//! takes seconds to stream gives the next header a later time, and the tar's
//! bytes (and the upload's reference) follow. The vectors' clock is fixed,
//! so this plays both machines with the world's clock moving while the
//! first part streams.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, VecDeque};

use common::*;
use fc_json::JsString;
use fc_swarm_provider::machine::node::{BodyOut, MAX_FRAME, WINDOW};
use fc_swarm_provider::machine::shell::{Shell, ShellCall, ShellMethod, ShellOutcome};
use fc_swarm_provider::machine::{
    AskId, Call, Effect, Event, Form, Live, Need, Outcome, ReadyCheck, Reply, Request, StoreWrite,
};
use fc_swarm_provider::value::{Bytes, BytesKind, Source, Value};

/// A second's start, and 3.5 s on: the first header's time and the
/// second's differ.
const T0: u64 = 1_767_225_600_000;
const LATER: u64 = T0 + 3_500;

const STAMPS: &str = r#"{"stamps":[{"batchID":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","utilization":0,"usable":true,"label":"freedom","depth":22,"amount":"100000000000","bucketDepth":16,"blockNumber":1000,"immutableFlag":true,"exists":true,"batchTTL":864000}]}"#;

trait Machine {
    fn answer(&mut self, world: &mut TestWorld, id: AskId, event: Event);
    fn take_effects(&mut self) -> Vec<Effect>;
    fn done(&self) -> bool;
}

impl Machine for Request {
    fn answer(&mut self, world: &mut TestWorld, id: AskId, event: Event) {
        Request::answer(self, world, id, event);
    }
    fn take_effects(&mut self) -> Vec<Effect> {
        Request::take_effects(self)
    }
    fn done(&self) -> bool {
        self.outcome().is_some()
    }
}

impl Machine for Shell {
    fn answer(&mut self, world: &mut TestWorld, id: AskId, event: Event) {
        Shell::answer(self, world, id, event);
    }
    fn take_effects(&mut self) -> Vec<Effect> {
        Shell::take_effects(self)
    }
    fn done(&self) -> bool {
        self.outcome().is_some()
    }
}

struct Feed {
    id: AskId,
    part: u32,
    data: Vec<u8>,
    sent: usize,
    window: usize,
}

/// Plays an upload to its end: main answers every ask honestly, streams
/// each part within the core's credit, and moves the clock to `LATER`
/// just before part 0's last frame and end. Returns the tar body.
fn play(
    machine: &mut impl Machine,
    world: &mut TestWorld,
    parts: &BTreeMap<u32, Vec<u8>>,
) -> Vec<u8> {
    let mut queue: VecDeque<Effect> = machine.take_effects().into();
    let mut feeds: Vec<Feed> = Vec::new();
    let mut credits: VecDeque<(AskId, usize)> = VecDeque::new();
    let mut body = Vec::new();
    loop {
        if machine.done() {
            return body;
        }
        if let Some(effect) = queue.pop_front() {
            match effect {
                Effect::Ask(ask) => {
                    let event = match ask.need {
                        Need::Ready(ReadyCheck::Publish) => Some(Event::Ready(Ok(()))),
                        Need::Write(StoreWrite::HistoryInsert(_)) => Some(Event::Inserted(Ok(1))),
                        Need::Write(_) => Some(Event::Written(Ok(()))),
                        Need::Upload => Some(Event::Turn),
                        Need::Live => Some(Event::Live(Live {
                            name: true,
                            live: true,
                            agent: false,
                        })),
                        Need::Node(call) if call.form == Form::Stamps => {
                            Some(Event::Reply(Reply {
                                status: 200,
                                status_text: "OK".to_owned(),
                                headers: Vec::new(),
                                body: STAMPS.as_bytes().to_vec(),
                            }))
                        }
                        Need::Node(call) if call.form == Form::BzzTar => Some(Event::BodyOpen),
                        Need::Part(k) => {
                            let data = parts[&k].clone();
                            let len = data.len() as u64;
                            feeds.push(Feed {
                                id: ask.id,
                                part: k,
                                data,
                                sent: 0,
                                window: WINDOW as usize,
                            });
                            Some(Event::PartHead(len))
                        }
                        other => panic!("{other:?}"),
                    };
                    if let Some(event) = event {
                        machine.answer(world, ask.id, event);
                    }
                }
                Effect::Credit { id, bytes } => {
                    feeds.iter_mut().find(|f| f.id == id).unwrap().window += bytes;
                }
                Effect::Body { id, out } => match out {
                    BodyOut::Head { .. } => {}
                    BodyOut::Data(frame) => {
                        body.extend_from_slice(&frame);
                        credits.push_back((id, frame.len()));
                    }
                    BodyOut::End => {
                        credits.retain(|(c, _)| *c != id);
                        let reply = Reply {
                            status: 201,
                            status_text: "Created".to_owned(),
                            headers: vec![("swarm-tag".to_owned(), "5".to_owned())],
                            body: format!(r#"{{"reference":"{}"}}"#, sha(&body)).into_bytes(),
                        };
                        machine.answer(world, id, Event::Reply(reply));
                    }
                    BodyOut::Abort(why) => panic!("the body aborted: {why:?}"),
                },
                Effect::Cancel(_) => {}
            }
            queue.extend(machine.take_effects());
            continue;
        }
        if let Some((id, bytes)) = credits.pop_front() {
            machine.answer(world, id, Event::BodyCredit(bytes));
            queue.extend(machine.take_effects());
            continue;
        }
        if let Some(at) = feeds
            .iter()
            .position(|f| f.window > 0 || f.sent == f.data.len())
        {
            let feed = &mut feeds[at];
            let n = feed.window.min(MAX_FRAME).min(feed.data.len() - feed.sent);
            let id = feed.id;
            if feed.part == 0 && feed.sent + n == feed.data.len() {
                // The first entry's last bytes come seconds after its first.
                world.now = LATER;
            }
            if n > 0 {
                let frame = feed.data[feed.sent..feed.sent + n].to_vec();
                feed.sent += n;
                feed.window -= n;
                machine.answer(world, id, Event::Data(frame));
            } else {
                feeds.remove(at);
                machine.answer(world, id, Event::End);
            }
            queue.extend(machine.take_effects());
            continue;
        }
        panic!("the upload waits with nothing asked");
    }
}

/// Each entry's header time (ustar's `mtime`, 11 octal digits), in order.
fn header_times(tar: &[u8]) -> Vec<u64> {
    let mut times = Vec::new();
    let mut at = 0;
    while at + 512 <= tar.len() && tar[at..at + 512].iter().any(|b| *b != 0) {
        let header = &tar[at..at + 512];
        let octal = |field: &[u8]| {
            u64::from_str_radix(std::str::from_utf8(&field[..11]).unwrap(), 8).unwrap()
        };
        times.push(octal(&header[136..148]));
        let size = octal(&header[124..136]) as usize;
        at += 512 + size.div_ceil(512) * 512;
    }
    times
}

/// Two parts: the first long enough to take several frames.
fn two_parts() -> BTreeMap<u32, Vec<u8>> {
    BTreeMap::from([(0, vec![0x61; 200_000]), (1, b"index".to_vec())])
}

#[test]
fn a_collections_headers_take_the_clock_as_each_is_written() {
    let parts = two_parts();
    let params = r#"{"kind":"collection","parts":[{"path":"big.bin","bytes":200000,"part":0},{"path":"index.html","bytes":5,"part":1}],"pin":true,"deferred":true}"#;
    let call = ShellCall::parse(ShellMethod::Publish, &fc_json::parse(params).unwrap()).unwrap();
    let mut world = TestWorld::new(T0);
    let mut shell = Shell::start(call, &mut world);
    let body = play(&mut shell, &mut world, &parts);
    assert!(matches!(shell.outcome(), Some(ShellOutcome::Result(_))));
    // bee-js's `beginFile` for the second entry runs after the first's
    // bytes went: 3.5 s later, the next second.
    assert_eq!(header_times(&body), [T0 / 1000, LATER / 1000]);
    // And so the bytes are those bee-js writes at those two times.
    let mut want = fc_swarm::tar::TarWriter::new(T0 / 1000).unwrap();
    let mut tar = want.begin("big.bin", 200_000).unwrap();
    want.data(200_000).unwrap();
    tar.extend_from_slice(&parts[&0]);
    tar.extend_from_slice(want.end().unwrap());
    let mut second = fc_swarm::tar::TarWriter::new(LATER / 1000).unwrap();
    tar.extend_from_slice(&second.begin("index.html", 5).unwrap());
    second.data(5).unwrap();
    tar.extend_from_slice(&parts[&1]);
    tar.extend_from_slice(second.end().unwrap());
    tar.extend_from_slice(second.finish().unwrap());
    assert_eq!(body, tar);
}

#[test]
fn a_pages_files_headers_take_the_clock_as_each_is_written() {
    let parts = two_parts();
    let file = |path: &str, part: u32, len: u64| {
        Value::object([
            ("path", Value::str(path)),
            (
                "bytes",
                Value::Bytes(Bytes {
                    len,
                    kind: BytesKind::Uint8Array,
                    source: Source::Part(part),
                    data: true,
                }),
            ),
        ])
    };
    let key = JsString::from("https://site.example");
    let call = Call {
        method: Value::str("swarm_publishFiles"),
        params: Value::object([(
            "files",
            Value::array([file("big.bin", 0, 200_000), file("index.html", 1, 5)]),
        )]),
        key: key.clone(),
        approval: None,
    };
    let mut world = TestWorld::new(T0);
    world.grants.insert(key);
    let mut request = Request::start(&call, &mut world).unwrap();
    let body = play(&mut request, &mut world, &parts);
    assert!(
        matches!(request.outcome(), Some(Outcome::Result(_))),
        "{:?}",
        request.outcome()
    );
    // page-upload.js's `tarPieces` makes the second header when the loop
    // asks for it, after the first entry's pieces were written.
    assert_eq!(header_times(&body), [T0 / 1000, LATER / 1000]);
}
