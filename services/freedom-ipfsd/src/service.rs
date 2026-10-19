//! The `ipfs.*` methods on fc-service's connection (design 0007, "Methods").
//!
//! - `ipfs.hello` answers the service's version, the freedom-ipfs build it
//!   links, and which process this is. The connection checks the protocol
//!   and frame kinds first, and adds `protocol`.
//! - `ipfs.start` and `ipfs.stop`: [`Instances`].
//! - `ipfs.shutdown` ends the connection (fc-service); [`Service::end`]
//!   then tears down every instance, and the process exits 0.
//! - `ipfs.request` and `ipfs.stats` come next (PR 3). Until then, as any
//!   other method, they are `unknown_method`.

use std::sync::Arc;

use fc_protocol::error::{ErrorBody, ErrorCode};
use fc_service::conn::{Connection, End, Hello, Request, Service};
use serde_json::{Map, Value, json};

use crate::build_info;
use crate::instances::Instances;

pub struct IpfsService {
    instances: Arc<Instances>,
}

impl IpfsService {
    pub fn new(instances: Arc<Instances>) -> IpfsService {
        IpfsService { instances }
    }
}

impl Service for IpfsService {
    fn hello(&self, _hello: &Hello) -> Result<Map<String, Value>, ErrorBody> {
        let mut members = Map::new();
        members.insert("service_version".into(), env!("CARGO_PKG_VERSION").into());
        members.insert(
            "freedom_ipfs".into(),
            json!({
                "version": build_info::FREEDOM_IPFS_VERSION,
                "git_commit": build_info::FREEDOM_IPFS_COMMIT,
            }),
        );
        members.insert("kind".into(), self.instances.kind().name().into());
        Ok(members)
    }

    fn request(&self, conn: &Connection, request: Request<'_>) {
        match request.method {
            "ipfs.start" => self.instances.start(conn, request.id, request.params),
            "ipfs.stop" => self.instances.stop(conn, request.id, request.params),
            _ => {
                let _ = conn.reply_error(
                    request.id,
                    &ErrorBody::new(ErrorCode::UnknownMethod, "unknown method"),
                );
            }
        }
    }

    fn cancel(&self, conn: &Connection, id: u64) {
        self.instances.cancel(conn, id);
    }

    fn end(&self, conn: &Connection, _end: End) {
        self.instances.end(conn);
    }
}
