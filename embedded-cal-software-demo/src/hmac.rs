use embedded_cal::{HashProvider, HmacProvider, plumbing::hash::SHA2SHORT_BLOCK_SIZE};

use crate::hash::{HashAlgorithm, HashResult};

use super::{Extender, ExtenderConfig};

/// HMAC algorithm identifier for software HMAC over [`Extender`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HmacAlgorithm {
    HmacSha256,
}

impl embedded_cal::HmacAlgorithm for HmacAlgorithm {
    const MAX_LEN: usize = 32;

    fn len(&self) -> usize {
        match self {
            HmacAlgorithm::HmacSha256 => 32,
        }
    }

    #[inline]
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        match number.into() {
            5 => Some(HmacAlgorithm::HmacSha256),
            _ => None,
        }
    }
}

pub enum HmacKey<EC: ExtenderConfig> {
    // This is exactly as HmacState to the point where the HmacKey associated type could also be
    // HmacState -- but that would incur a Clone requirement (and a Clone guarantee on HmacState)
    // that we can't keep up when we forward to the underlying implementation.
    HmacSha256 {
        inner: <Extender<EC> as HashProvider>::HashState,
        outer_key: [u8; SHA2SHORT_BLOCK_SIZE],
    },
}

impl<EC: ExtenderConfig> Clone for HmacKey<EC> {
    // This is the default implemnentation, but we can't derive it because EC is not clone. (We
    // don't expect it to, but we'd need "minimal derives" in Rust to make it derivable).
    fn clone(&self) -> Self {
        match self {
            Self::HmacSha256 { inner, outer_key } => Self::HmacSha256 {
                inner: inner.clone(),
                outer_key: *outer_key,
            },
        }
    }
}

pub enum HmacState<EC: ExtenderConfig> {
    HmacSha256 {
        /// Inner hash state accumulating `H((K XOR ipad) || message)`.
        inner: <Extender<EC> as HashProvider>::HashState,
        /// Key material XORed with opad, ready for the outer hash in `finalize`.
        outer_key: [u8; SHA2SHORT_BLOCK_SIZE],
    },
}

pub enum HmacResult {
    HmacSha256([u8; 32]),
}

impl AsRef<[u8]> for HmacResult {
    fn as_ref(&self) -> &[u8] {
        match self {
            HmacResult::HmacSha256(data) => data.as_slice(),
        }
    }
}

impl<EC: ExtenderConfig> HmacProvider for Extender<EC> {
    type Algorithm = HmacAlgorithm;
    type Key = HmacKey<EC>;
    type HmacState = HmacState<EC>;
    type HmacResult = HmacResult;

    fn load_from_keydata(&mut self, algorithm: Self::Algorithm, key: &[u8]) -> Self::Key {
        match algorithm {
            HmacAlgorithm::HmacSha256 => {
                // Normalise key to exactly SHA2SHORT_BLOCK_SIZE bytes.
                // If key is longer than the block size, hash it first (RFC 2104).
                let mut key_block = [0u8; SHA2SHORT_BLOCK_SIZE];
                if key.len() > SHA2SHORT_BLOCK_SIZE {
                    let hashed = HashProvider::hash(self, HashAlgorithm::Sha256, key);
                    let h = hashed.as_ref();
                    debug_assert_eq!(h.len(), 32, "SHA-256 must produce 32 bytes");
                    key_block[..h.len()].copy_from_slice(h);
                } else {
                    key_block[..key.len()].copy_from_slice(key);
                }

                // outer_key = key_block XOR opad (0x5c)
                let mut outer_key = [0u8; SHA2SHORT_BLOCK_SIZE];
                for (o, &k) in outer_key.iter_mut().zip(key_block.iter()) {
                    *o = k ^ 0x5c;
                }

                // ipad_block = key_block XOR ipad (0x36)
                let mut ipad_block = [0u8; SHA2SHORT_BLOCK_SIZE];
                for (i, &k) in ipad_block.iter_mut().zip(key_block.iter()) {
                    *i = k ^ 0x36;
                }

                // Start inner hash: H((key XOR ipad) || ...)
                let mut inner = HashProvider::init(self, HashAlgorithm::Sha256);
                HashProvider::update(self, &mut inner, &ipad_block);

                HmacKey::HmacSha256 { inner, outer_key }
            }
        }
    }

    fn init(&mut self, key: Self::Key) -> Self::HmacState {
        match key {
            HmacKey::HmacSha256 { inner, outer_key } => HmacState::HmacSha256 { inner, outer_key },
        }
    }

    fn update(&mut self, state: &mut Self::HmacState, data: &[u8]) {
        match state {
            HmacState::HmacSha256 { inner, .. } => {
                HashProvider::update(self, inner, data);
            }
        }
    }

    fn finalize(&mut self, state: Self::HmacState) -> Self::HmacResult {
        match state {
            HmacState::HmacSha256 { inner, outer_key } => {
                // Finish inner hash, then compute outer: H(outer_key || inner_result)
                let inner_result = HashProvider::finalize(self, inner);
                let mut outer = HashProvider::init(self, HashAlgorithm::Sha256);
                HashProvider::update(self, &mut outer, &outer_key);
                HashProvider::update(self, &mut outer, inner_result.as_ref());
                match HashProvider::finalize(self, outer) {
                    HashResult::Sha256(buf) => HmacResult::HmacSha256(buf),
                    _ => unreachable!("Sha256 init produces Sha256 result"),
                }
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tests::dummy_sha256;

    struct ImplementSha256Short;

    impl ExtenderConfig for ImplementSha256Short {
        const IMPLEMENT_SHA2SHORT: bool = true;
        type Base = dummy_sha256::DummySha256;
    }

    #[test]
    fn test_hmac_sha256_on_dummy() {
        let mut cal = Extender::<ImplementSha256Short>(dummy_sha256::DummySha256);

        testvectors::test_hmac_sha256(&mut cal);
    }
}
