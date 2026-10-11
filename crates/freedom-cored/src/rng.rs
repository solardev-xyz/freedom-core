//! The OS random number generator, for the logic crates' injected RNGs.

/// `getrandom`, as a fallible crypto RNG.
pub struct OsRng;

#[derive(Debug)]
pub struct RngError;

impl std::fmt::Display for RngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the OS random number generator failed")
    }
}

impl std::error::Error for RngError {}

impl rand_core::TryRng for OsRng {
    type Error = RngError;

    fn try_next_u32(&mut self) -> Result<u32, RngError> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, RngError> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RngError> {
        getrandom::fill(dst).map_err(|_| RngError)
    }
}

impl rand_core::TryCryptoRng for OsRng {}
