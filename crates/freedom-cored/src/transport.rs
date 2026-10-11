//! Stdio transport: a reader thread turning stdin into frames, and one
//! serialized writer thread for stdout (design 0001, "Transport").

use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, Sender};

use fc_protocol::frame::Decoder;
use zeroize::Zeroizing;

use crate::serve::Event;

const READ_CHUNK: usize = 64 * 1024;

/// Reads stdin until EOF or a framing error, sending frames to `events`.
pub fn spawn_reader(events: Sender<Event>) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("stdin".into())
        .spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buffer = Zeroizing::new(vec![0u8; READ_CHUNK]);
            let mut decoder = Decoder::new();
            loop {
                let read = match stdin.read(&mut buffer[..]) {
                    Ok(0) => {
                        let _ = events.send(Event::Eof {
                            at_boundary: decoder.is_at_boundary(),
                        });
                        return;
                    }
                    Ok(read) => read,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        let _ = events.send(Event::Eof { at_boundary: false });
                        return;
                    }
                };
                if let Err(e) = decoder.push(&buffer[..read]) {
                    let _ = events.send(Event::ProtocolError(e.to_string()));
                    return;
                }
                while let Some(frame) = decoder.pop() {
                    if events.send(Event::Frame(frame)).is_err() {
                        return;
                    }
                }
            }
        })
}

/// Writes already-framed messages to stdout, in order, until the channel
/// closes.
pub fn spawn_writer(
    frames: Receiver<Zeroizing<Vec<u8>>>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("stdout".into())
        .spawn(move || {
            let mut stdout = std::io::stdout().lock();
            for frame in frames {
                if stdout
                    .write_all(&frame)
                    .and_then(|()| stdout.flush())
                    .is_err()
                {
                    return;
                }
            }
        })
}

/// Frames one JSON message.
pub fn frame(payload: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(payload.len() + 5));
    fc_protocol::frame::encode_json(payload, &mut out).ok()?;
    Some(out)
}
