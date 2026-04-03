// Based on rand_core::TryRng
pub trait TryRng {
    type Error: core::error::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error>;
    fn try_next_u64(&mut self) -> Result<u64, Self::Error>;
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error>;
}

pub fn test_tryrng<R: TryRng>(rng: &mut R) {
    // Zero-length fill must not panic
    rng.try_fill_bytes(&mut []).unwrap();

    // Single-byte fill exercises the take=1 path
    let mut one = [0u8; 1];
    rng.try_fill_bytes(&mut one).unwrap();

    // Basic fill: output should not be all zeros
    let mut buf = [0u8; 32];
    rng.try_fill_bytes(&mut buf).unwrap();
    assert!(buf.iter().any(|&b| b != 0));

    // Two consecutive fills should differ
    let mut buf2 = [0u8; 32];
    rng.try_fill_bytes(&mut buf2).unwrap();
    assert_ne!(buf, buf2);

    // Non-multiple-of-4 length exercises the partial last word path
    let mut buf3 = [0u8; 15];
    rng.try_fill_bytes(&mut buf3).unwrap();
    assert!(buf3.iter().any(|&b| b != 0));

    // Fill larger than a typical FIFO depth (>64 bytes) exercises multi-iteration draining
    let mut large = [0u8; 128];
    rng.try_fill_bytes(&mut large).unwrap();
    assert!(large.iter().any(|&b| b != 0));

    let _ = rng.try_next_u32().unwrap();
    let _ = rng.try_next_u64().unwrap();
}
