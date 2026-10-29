//! The IPFS walk (design 0009, The IPFS walk): being built.

use super::jobs::{Verdict, Work};
use super::{Failure, PieceFailure, PieceId};
use crate::plan::Root;
use crate::validate::Refusal as PlanRefusal;

/// What a piece or a job is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tag {
    Block(u64),
}

type Core = super::Core<Tag>;

/// What the request asks beside its path.
#[derive(Debug, Clone)]
pub(crate) struct Asked {
    pub range: Option<String>,
    pub if_none_match: Option<String>,
    pub now: i64,
    pub car: bool,
}

#[derive(Debug)]
pub(crate) struct Walk;

impl Walk {
    pub(crate) fn start(
        core: &mut Core,
        _root: &Root,
        _path: &str,
        _asked: Asked,
    ) -> Result<Self, PlanRefusal> {
        core.fail(Failure::Unverifiable);
        Ok(Self)
    }
}

impl super::Events<Tag> for Walk {
    fn whole(&mut self, core: &mut Core, _: Tag, _: u16, _: &[(String, String)], body: Vec<u8>) {
        core.unhold(body.len());
    }
    fn stream_head(&mut self, _: &mut Core, _: Tag, _: PieceId, _: u16, _: &[(String, String)]) {}
    fn stream_data(&mut self, core: &mut Core, _: Tag, _: PieceId, bytes: Vec<u8>) {
        core.unhold(bytes.len());
    }
    fn stream_end(&mut self, _: &mut Core, _: Tag, _: PieceId) {}
    fn failed(&mut self, _: &mut Core, _: Tag, _: PieceFailure) {}
    fn hashed(&mut self, core: &mut Core, _: Tag, _: Verdict, work: Work) {
        core.unhold(work.size());
    }
}
