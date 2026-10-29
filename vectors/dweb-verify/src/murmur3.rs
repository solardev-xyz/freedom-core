//! MurmurHash3 x64 128 (Austin Appleby's reference, `MurmurHash3_x64_128`),
//! as boxo's HAMT hashes names with it (`github.com/spaolacci/murmur3`,
//! `Sum128`), seed 0. The generator checks it against Kubo's own HAMT
//! layout: every name of the recorded HAMT must sit where this hash puts it.

const C1: u64 = 0x87c3_7b91_1142_53d5;
const C2: u64 = 0x4cf5_ad43_2745_937f;

fn fmix(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    k ^= k >> 33;
    k
}

/// The two 64-bit halves `(h1, h2)`, which `Sum128` returns in that order.
pub fn x64_128(data: &[u8], seed: u64) -> (u64, u64) {
    let mut h1 = seed;
    let mut h2 = seed;
    let blocks = data.len() / 16;
    for i in 0..blocks {
        let b = &data[i * 16..i * 16 + 16];
        let mut k1 = u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
        let mut k2 = u64::from_le_bytes(b[8..].try_into().unwrap_or([0; 8]));
        k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1
            .rotate_left(27)
            .wrapping_add(h2)
            .wrapping_mul(5)
            .wrapping_add(0x52dc_e729);
        k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
        h2 ^= k2;
        h2 = h2
            .rotate_left(31)
            .wrapping_add(h1)
            .wrapping_mul(5)
            .wrapping_add(0x3849_5ab5);
    }
    let tail = &data[blocks * 16..];
    let mut k1 = 0u64;
    let mut k2 = 0u64;
    for (i, &byte) in tail.iter().enumerate().rev() {
        if i >= 8 {
            k2 ^= u64::from(byte) << ((i - 8) * 8);
        } else {
            k1 ^= u64::from(byte) << (i * 8);
        }
    }
    if tail.len() > 8 {
        k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
        h2 ^= k2;
    }
    if !tail.is_empty() {
        k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
        h1 ^= k1;
    }
    let len = data.len() as u64;
    h1 ^= len;
    h2 ^= len;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix(h1);
    h2 = fmix(h2);
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    (h1, h2)
}

/// The 64 bits boxo's HAMT consumes, a byte per level: `Sum128`'s first
/// half, big-endian (boxo `hamt/util.go`, `hashBits`).
pub fn hamt_bits(name: &str) -> [u8; 8] {
    x64_128(name.as_bytes(), 0).0.to_be_bytes()
}

/// Known answers: SMHasher's verification value for x64_128 is checked by
/// the caller over the HAMT; these pin the empty input and a short one.
pub fn self_check() -> Result<(), String> {
    // MurmurHash3_x64_128("", 0) is all zeros.
    if x64_128(b"", 0) != (0, 0) {
        return Err("murmur3 of the empty input isn't zero".into());
    }
    // SMHasher's verification: hash keys {}, {0}, {0,1}, … {0..254} with
    // seed 256 - i, hash the concatenated 16-byte results with seed 0; the
    // first 4 bytes, little-endian, are 0x6384BA69.
    let mut all = Vec::with_capacity(256 * 16);
    let mut key = Vec::with_capacity(256);
    for i in 0..256u64 {
        let (a, b) = x64_128(&key, 256 - i);
        all.extend_from_slice(&a.to_le_bytes());
        all.extend_from_slice(&b.to_le_bytes());
        key.push(i as u8);
    }
    let (v, _) = x64_128(&all, 0);
    if (v as u32) != 0x6384_ba69 {
        return Err(format!(
            "murmur3 fails SMHasher's verification value: {:08x}",
            v as u32
        ));
    }
    Ok(())
}
