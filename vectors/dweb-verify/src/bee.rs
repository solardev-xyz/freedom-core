//! Bee's plain (level-0) splitter, for the trees Ant's writes differently.
//!
//! Bee's hashtrie writer (bee `pkg/file/pipeline/hashtrie/hashtrie.go`,
//! `Sum`, at a93fb7a7) carries a level's lone leftover reference up to the
//! next level unwrapped ("case 1"); Ant v0.5.71's `StreamingSplitter::finish`
//! wraps it in an intermediate chunk of one reference. Everywhere else the
//! two agree, which [`split`]'s callers check.

type Addr = [u8; 32];

/// A chunk: its address and wire bytes.
pub type Chunk = (Addr, Vec<u8>);

const BRANCHES: usize = 128;

fn wrap(level: &mut Vec<(Addr, u64)>, out: &mut Vec<Chunk>) -> Option<(Addr, u64)> {
    let mut payload = Vec::with_capacity(level.len() * 32);
    let mut span = 0u64;
    for (a, s) in level.iter() {
        payload.extend_from_slice(a);
        span += s;
    }
    level.clear();
    let addr = ant_crypto::bmt_hash_with_span(&span.to_le_bytes(), &payload)?;
    let mut wire = span.to_le_bytes().to_vec();
    wire.extend_from_slice(&payload);
    out.push((addr, wire));
    Some((addr, span))
}

/// Splits `data` as Bee does with no erasure coding. Returns the root and
/// every chunk, leaves included.
pub fn split(data: &[u8]) -> Option<(Addr, Vec<Chunk>)> {
    let mut out = Vec::new();
    if data.len() <= 4096 {
        let (addr, wire) = ant_crypto::cac_new(data)?;
        out.push((addr, wire));
        return Some((addr, out));
    }
    // levels[i]: the pending references of tree level i + 1.
    let mut levels: Vec<Vec<(Addr, u64)>> = vec![Vec::new()];
    for leaf in data.chunks(4096) {
        let (addr, wire) = ant_crypto::cac_new(leaf)?;
        out.push((addr, wire));
        levels[0].push((addr, leaf.len() as u64));
        let mut i = 0;
        while levels[i].len() == BRANCHES {
            let wrapped = wrap(&mut levels[i], &mut out)?;
            if levels.len() == i + 1 {
                levels.push(Vec::new());
            }
            levels[i + 1].push(wrapped);
            i += 1;
        }
    }
    // `Sum`: from the bottom, a lone reference moves up as it is, more
    // than one is wrapped, until one reference is left at the top.
    let mut i = 0;
    loop {
        if levels.len() == i + 1 {
            levels.push(Vec::new());
        }
        let higher = levels[i + 1..].iter().any(|l| !l.is_empty());
        match levels[i].len() {
            0 => {}
            1 if !higher => return Some((levels[i][0].0, out)),
            1 => {
                let lone = levels[i].remove(0);
                levels[i + 1].push(lone);
            }
            _ => {
                let wrapped = wrap(&mut levels[i], &mut out)?;
                levels[i + 1].push(wrapped);
            }
        }
        i += 1;
    }
}
