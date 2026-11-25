//! A streamed upload body (design 0015, "Streams" and "Bounds"):
//! `swarm.body`'s answer to main, written once main asks for it and only
//! within main's window, from the core's own bytes (a tar's headers and
//! padding, the bytes of a file the params carry inline) and the
//! request's parts (`shell.swarm_part`), one part at a time, each in its
//! turn. A part is credited only for bytes that went out on the body
//! ("credit goes in only when it can go out"), so a node that stops
//! reading holds one window in each direction.

use std::collections::VecDeque;

use fc_swarm::chunker::{Chunker, Root};
use fc_swarm::tar::TarWriter;

use crate::machine::node::{BodyAbort, BodyOut, MAX_FRAME, WINDOW};
use crate::machine::{AskId, Cx, Event, World};

/// Where some of a body's bytes come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Piece {
    /// Bytes the core holds (inline in the params).
    Own(Vec<u8>),
    /// A part of the request's params, of `len` bytes.
    Part { part: u32, len: u64 },
}

impl Piece {
    pub(crate) fn len(&self) -> u64 {
        match self {
            Piece::Own(bytes) => bytes.len() as u64,
            Piece::Part { len, .. } => *len,
        }
    }
}

/// What the body writes next.
#[derive(Debug)]
enum Next {
    Piece(Piece),
    /// A tar entry's header.
    Header {
        path: String,
        len: u64,
    },
    /// The end of a tar entry of `len` bytes: its padding.
    EndEntry {
        len: u64,
    },
    /// The tar's two zero blocks.
    Finish,
}

/// The part being copied.
#[derive(Debug)]
struct Copy {
    id: AskId,
    len: u64,
    received: u64,
    ended: bool,
}

/// Why the body stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// A part that isn't its declared length: main broke the protocol.
    PartLength,
    /// A part main couldn't stream (aborted, failed, refused).
    Part,
    /// The tar writer refused (a size past its field), or the bytes
    /// written aren't the length announced: a core bug.
    Internal,
}

/// One streamed body.
#[derive(Debug)]
pub(crate) struct BodyWriter {
    call: AskId,
    total: u64,
    sent: u64,
    window: u64,
    opened: bool,
    ended: bool,
    tar: Option<TarWriter>,
    queue: VecDeque<Next>,
    /// Bytes ready to go, each with the part they came from.
    pending: VecDeque<(Vec<u8>, Option<AskId>)>,
    copy: Option<Copy>,
    /// The chunk tree of what went out, for a body whose root the core
    /// checks (a feed entry over one chunk: deviations `feed-wrap-root`,
    /// `reference-check`), and its root once the body ended.
    hash: Option<Chunker>,
    root: Option<Root>,
}

impl BodyWriter {
    /// One file's bytes, from `piece`.
    pub(crate) fn file(piece: Piece) -> BodyWriter {
        BodyWriter::new(piece.len(), None, VecDeque::from([Next::Piece(piece)]))
    }

    /// One file's bytes, from `piece`, hashed as they go out: its chunk
    /// tree's root once the body ended ([`BodyWriter::root`]).
    pub(crate) fn hashed(piece: Piece) -> BodyWriter {
        let mut writer = BodyWriter::file(piece);
        writer.hash = Some(Chunker::new());
        writer
    }

    /// The root of what went out, for a [`BodyWriter::hashed`] body that
    /// ended.
    pub(crate) fn root(&self) -> Option<&Root> {
        self.root.as_ref()
    }

    /// A tar of `entries` (path, bytes) as page-upload.js writes it, each
    /// header stamped `mtime` (seconds), or `None` where the tar writer
    /// refuses an entry.
    pub(crate) fn tar(entries: Vec<(String, Piece)>, mtime: u64) -> Option<BodyWriter> {
        let mut measure = TarWriter::new(mtime).ok()?;
        let mut total: u64 = 0;
        let mut queue = VecDeque::new();
        for (path, piece) in entries {
            let len = piece.len();
            // Each header's length, as the writer will make it.
            let header = measure.begin(&path, len).ok()?;
            measure.data(usize::try_from(len).ok()?).ok()?;
            let padding = measure.end().ok()?;
            total = total
                .checked_add(header.len() as u64)?
                .checked_add(len)?
                .checked_add(padding.len() as u64)?;
            queue.push_back(Next::Header { path, len });
            queue.push_back(Next::Piece(piece));
            queue.push_back(Next::EndEntry { len });
        }
        total = total.checked_add(measure.finish().ok()?.len() as u64)?;
        queue.push_back(Next::Finish);
        let tar = TarWriter::new(mtime).ok()?;
        Some(BodyWriter::new(total, Some(tar), queue))
    }

    fn new(total: u64, tar: Option<TarWriter>, queue: VecDeque<Next>) -> BodyWriter {
        BodyWriter {
            call: AskId(0),
            total,
            sent: 0,
            window: 0,
            opened: false,
            ended: false,
            tar,
            queue,
            pending: VecDeque::new(),
            copy: None,
            hash: None,
            root: None,
        }
    }

    /// The body's length, which the call announces.
    pub(crate) fn total(&self) -> u64 {
        self.total
    }

    /// The call whose body this is.
    pub(crate) fn bind(&mut self, call: AskId) {
        self.call = call;
    }

    /// Whether the whole body went out.
    pub(crate) fn ended(&self) -> bool {
        self.ended
    }

    /// Main asked for the body: its head, then what the window allows.
    pub(crate) fn open<W: World>(&mut self, cx: &mut Cx<'_, W>) -> Result<(), Fault> {
        self.opened = true;
        self.window = WINDOW;
        cx.body(self.call, BodyOut::Head { bytes: self.total });
        self.pump(cx)
    }

    /// Main's credit on the body.
    pub(crate) fn credit<W: World>(
        &mut self,
        cx: &mut Cx<'_, W>,
        bytes: usize,
    ) -> Result<(), Fault> {
        self.window = self.window.saturating_add(bytes as u64);
        self.pump(cx)
    }

    /// Whether `id` is the part this body copies.
    pub(crate) fn copies(&self, id: AskId) -> bool {
        self.copy.as_ref().is_some_and(|c| c.id == id)
    }

    /// The next answer for the part being copied.
    pub(crate) fn part<W: World>(&mut self, cx: &mut Cx<'_, W>, event: Event) -> Result<(), Fault> {
        let Some(copy) = self.copy.as_mut() else {
            return Err(Fault::Internal);
        };
        match event {
            Event::PartHead(len) if len == copy.len => {}
            Event::PartHead(_) => return Err(Fault::PartLength),
            Event::Data(bytes) => {
                copy.received = copy.received.saturating_add(bytes.len() as u64);
                if copy.received > copy.len {
                    return Err(Fault::PartLength);
                }
                self.pending.push_back((bytes, Some(copy.id)));
            }
            Event::End if copy.received == copy.len => copy.ended = true,
            Event::End => return Err(Fault::PartLength),
            _ => return Err(Fault::Part),
        }
        self.pump(cx)
    }

    /// Ends the body short, if it is open and not yet ended, and stops the
    /// part it was copying.
    pub(crate) fn abort<W: World>(&mut self, cx: &mut Cx<'_, W>, why: BodyAbort) {
        if let Some(copy) = self.copy.take() {
            cx.cancel(copy.id);
        }
        self.pending.clear();
        self.queue.clear();
        if self.opened && !self.ended {
            self.ended = true;
            cx.body(self.call, BodyOut::Abort(why));
        }
    }

    /// The terminal of a body that is open and not yet ended, now ended:
    /// what the request sends when it ends without the machine. The part
    /// it was copying is cancelled with the request's other asks.
    pub(crate) fn terminal(&mut self, why: BodyAbort) -> Option<(AskId, BodyOut)> {
        self.copy = None;
        self.pending.clear();
        self.queue.clear();
        if !self.opened || self.ended {
            return None;
        }
        self.ended = true;
        Some((self.call, BodyOut::Abort(why)))
    }

    /// Sends what the window allows, and takes the next piece once the
    /// last has gone.
    fn pump<W: World>(&mut self, cx: &mut Cx<'_, W>) -> Result<(), Fault> {
        if !self.opened || self.ended {
            return Ok(());
        }
        loop {
            while self.window > 0 {
                let Some((bytes, from)) = self.pending.front_mut() else {
                    break;
                };
                let n = bytes
                    .len()
                    .min(MAX_FRAME)
                    .min(usize::try_from(self.window).unwrap_or(usize::MAX));
                let rest = bytes.split_off(n);
                let frame = std::mem::replace(bytes, rest);
                let from = *from;
                if self.pending.front().is_some_and(|(b, _)| b.is_empty()) {
                    self.pending.pop_front();
                }
                if frame.is_empty() {
                    continue;
                }
                self.window -= n as u64;
                self.sent += n as u64;
                if let Some(chunker) = self.hash.as_mut() {
                    chunker
                        .write(&frame, &mut |_| {})
                        .map_err(|_| Fault::Internal)?;
                }
                cx.body(self.call, BodyOut::Data(frame));
                if let Some(part) = from {
                    // What went out comes in.
                    cx.credit(part, n);
                }
            }
            if !self.pending.is_empty() {
                // The window is shut: main's credit reopens it.
                return Ok(());
            }
            if let Some(copy) = &self.copy {
                if !copy.ended {
                    return Ok(());
                }
                self.copy = None;
            }
            match self.queue.pop_front() {
                None => {
                    if self.sent != self.total {
                        return Err(Fault::Internal);
                    }
                    self.ended = true;
                    self.root = self.hash.take().map(|chunker| chunker.finish(&mut |_| {}));
                    cx.body(self.call, BodyOut::End);
                    return Ok(());
                }
                Some(Next::Piece(Piece::Own(bytes))) => {
                    if !bytes.is_empty() {
                        self.pending.push_back((bytes, None));
                    }
                }
                Some(Next::Piece(Piece::Part { part, len })) => {
                    let id = cx.part(part);
                    self.copy = Some(Copy {
                        id,
                        len,
                        received: 0,
                        ended: false,
                    });
                }
                Some(Next::Header { path, len }) => {
                    let tar = self.tar.as_mut().ok_or(Fault::Internal)?;
                    let header = tar.begin(&path, len).map_err(|_| Fault::Internal)?;
                    self.pending.push_back((header, None));
                }
                Some(Next::EndEntry { len }) => {
                    let tar = self.tar.as_mut().ok_or(Fault::Internal)?;
                    tar.data(usize::try_from(len).map_err(|_| Fault::Internal)?)
                        .map_err(|_| Fault::Internal)?;
                    let padding = tar.end().map_err(|_| Fault::Internal)?;
                    if !padding.is_empty() {
                        self.pending.push_back((padding.to_vec(), None));
                    }
                }
                Some(Next::Finish) => {
                    let tar = self.tar.take().ok_or(Fault::Internal)?;
                    let end = tar.finish().map_err(|_| Fault::Internal)?;
                    self.pending.push_back((end.to_vec(), None));
                }
            }
        }
    }
}
