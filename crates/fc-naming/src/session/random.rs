//! The machine's random source. Shuffles and ethers' 429 back-off draw
//! from one stream, in the reference's order (design 0004, Pool and
//! quarantine), so a replay seeded like the reference stays in step.

/// Uniform values in `[0, 1)`, like `Math.random`.
pub trait Random {
    fn next_f64(&mut self) -> f64;
}

/// mulberry32, as the replay harness seeds `Math.random`.
#[derive(Debug, Clone)]
pub struct Mulberry32 {
    state: u32,
}

impl Mulberry32 {
    pub fn new(seed: u32) -> Self {
        Self { state: seed }
    }
}

impl Random for Mulberry32 {
    fn next_f64(&mut self) -> f64 {
        // JavaScript's `| 0`, `Math.imul` and `>>>` are all mod 2^32.
        self.state = self.state.wrapping_add(0x6d2b_79f5);
        let s = self.state;
        let mut t = (s ^ (s >> 15)).wrapping_mul(1 | s);
        t = t.wrapping_add((t ^ (t >> 7)).wrapping_mul(61 | t)) ^ t;
        f64::from(t ^ (t >> 14)) / 4_294_967_296.0
    }
}

/// `floor(r × n)` for `r` in `[0, 1)`: an index below `n`.
pub(crate) fn index_below(random: &mut dyn Random, n: usize) -> usize {
    let r = random.next_f64();
    // `n` is small (at most the endpoint count) and `r < 1`, so the product
    // is exact and below `n`.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let index = (r * n as f64).floor() as usize;
    index.min(n.saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_harness_javascript() {
        // node -e 'mulberry32(7)' over the harness's seeded() function.
        let mut random = Mulberry32::new(7);
        let first: Vec<f64> = (0..3).map(|_| random.next_f64()).collect();
        assert_eq!(
            first,
            vec![
                0.011_704_753_153_026_104,
                0.061_958_257_574_588_06,
                0.976_907_632_779_33
            ]
        );
    }
}
