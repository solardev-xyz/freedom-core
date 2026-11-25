//! The method machines, by group (design 0015, "The methods"): Access
//! (`requestAccess`, `getCapabilities`), the Reads (`readChunk`,
//! `readData`, `readSingleOwnerChunk`, `readFeedEntry`, `listFeeds`), the
//! feed index lookup the feed writes use, the Publish group
//! (`publishData`, `publishFiles`, `publishChunk`, `getUploadStatus`), the
//! feed and SOC writes (`createFeed`, `updateFeed`, `writeFeedEntry`,
//! `writeSingleOwnerChunk`, `getSigningIdentity`) and Messaging
//! (`getMessagingIdentity`, `sendPss`, `sendGsoc`, `subscribe`).

use fc_json::JsString;

use crate::errors::{self, ChunkRead};
use crate::machine::node::{Failed, transport_text};
use crate::machine::{Cx, Failure, Outcome, World};
use crate::value::Value;

pub mod access;
mod body;
pub mod chunk_reads;
pub mod create_feed;
pub mod feed_index;
pub mod feed_read;
pub mod feed_write;
pub mod messaging;
pub mod publish;
pub mod read_data;
pub mod signing;
pub mod soc_write;
pub mod upload_status;
pub(crate) mod writes;

/// `getPermission(origin)`, which every method but Access and the Reads
/// needs first: `notConnected()`.
pub(crate) fn permitted<W: World>(cx: &Cx<'_, W>) -> Result<(), Outcome> {
    if cx.connected() {
        Ok(())
    } else {
        Err(Failure::not_connected().into())
    }
}

/// page-swarm.js's `NO_ADDRESS`: the document no longer holds its key.
pub(crate) fn no_address() -> Failure {
    Failure {
        code: crate::machine::page::UNAUTHORIZED,
        message: JsString::from("This page has no address to connect from yet"),
        data: Some(Value::object([("reason", Value::str("no_address"))])),
    }
}

/// `LIMITS` (swarm-provider-ipc.js), as `getCapabilities` reports them.
pub mod limits {
    pub const MAX_DATA_BYTES: u64 = 10 * 1024 * 1024;
    pub const MAX_FILES_BYTES: u64 = 50 * 1024 * 1024;
    pub const MAX_FILE_COUNT: u64 = 100;
    pub const MAX_PATH_BYTES: u64 = 100;
    pub const MAX_CHUNK_PAYLOAD_BYTES: u64 = 4096;
    /// messaging-service.js's `MAX_MESSAGE_BYTES`.
    pub const MAX_MESSAGE_BYTES: u64 = 4000;
    /// messaging-service.js's `MAX_TARGET_DEPTH`.
    pub const MAX_TARGET_DEPTH: u64 = 3;
    pub const MAX_SUBSCRIPTIONS: u64 = 32;
}

impl From<Failure> for Outcome {
    fn from(failure: Failure) -> Self {
        Outcome::Error(failure)
    }
}

/// The page's error for a read's chunk download that failed before any
/// reply, through `mapChunkReadError`: a transport failure is -32603 with
/// its class's text; main's pool full is `busy`. A chunk reply past its
/// 4,201 bytes can't be the chunk asked for, so it reads as bytes that
/// don't validate, as the reference reads an oversized download
/// (`unmarshal*` refuses a payload past 4,096 bytes).
pub(crate) fn chunk_failed(failed: Failed, read: ChunkRead) -> Failure {
    match failed {
        Failed::Busy => Failure::busy(),
        Failed::TooLarge => mismatch(read),
        class => Failure::internal(transport_text(class)),
    }
}

/// `chunk_type_mismatch` through `mapChunkReadError`.
pub(crate) fn mismatch(read: ChunkRead) -> Failure {
    errors::map_chunk_read_error(&errors::chunk_type_mismatch(read)).into()
}

/// A node's error answer to a read's chunk download, through
/// `isChunkNotFoundError` and `mapChunkReadError`.
pub(crate) fn chunk_error(
    read: ChunkRead,
    reference: &str,
    reply: &crate::machine::Reply,
) -> Failure {
    match reply.error(errors::Site::BeeJs) {
        Ok(err) => {
            errors::map_chunk_read_error(&errors::chunk_read_error(read, reference, &err)).into()
        }
        Err(class) => chunk_failed(class, read),
    }
}
