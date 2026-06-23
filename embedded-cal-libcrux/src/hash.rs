// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::HashProvider;
use libcrux_iot_sha3::{
    SHA3_224_DIGEST_SIZE, SHA3_256_DIGEST_SIZE, SHA3_384_DIGEST_SIZE, SHA3_512_DIGEST_SIZE,
};
use libcrux_secrets::{ClassifyRef, Declassify};

use super::*;

#[derive(Clone)]
pub struct Sha256State(libcrux_sha2::Sha256);

#[derive(Clone)]
pub struct Sha3_224State(libcrux_iot_sha3::Sha3_224);
#[derive(Clone)]
pub struct Sha3_256State(libcrux_iot_sha3::Sha3_256);
#[derive(Clone)]
pub struct Sha3_384State(libcrux_iot_sha3::Sha3_384);
#[derive(Clone)]
pub struct Sha3_512State(libcrux_iot_sha3::Sha3_512);

pub enum HashState<EC: ExtenderConfig> {
    Direct(HashStateOf<EC::Base>),
    Sha256(Sha256State),
    Sha3_224(Sha3_224State),
    Sha3_256(Sha3_256State),
    Sha3_384(Sha3_384State),
    Sha3_512(Sha3_512State),
}

impl<EC: ExtenderConfig> Clone for HashState<EC> {
    // This is the default implementation, but we can't derive it because EC is not clone. (We
    // don't expect it to, but we'd need "minimal derives" in Rust to make it derivable).
    fn clone(&self) -> Self {
        match self {
            Self::Direct(d) => Self::Direct(d.clone()),
            Self::Sha256(s) => Self::Sha256(s.clone()),
            Self::Sha3_224(s) => Self::Sha3_224(s.clone()),
            Self::Sha3_256(s) => Self::Sha3_256(s.clone()),
            Self::Sha3_384(s) => Self::Sha3_384(s.clone()),
            Self::Sha3_512(s) => Self::Sha3_512(s.clone()),
        }
    }
}

impl<EC: ExtenderConfig> HashProvider for Extender<EC> {
    type Algorithm = HashAlgorithm<EC>;
    type State = HashState<EC>;
    type Output = HashResult<EC>;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::State {
        match algorithm {
            HashAlgorithm::Direct(alg) => HashState::Direct(self.0.hash().init(alg)),
            HashAlgorithm::Sha256 => HashState::Sha256(Sha256State(libcrux_sha2::Sha256::new())),
            HashAlgorithm::Sha3_224 => {
                HashState::Sha3_224(Sha3_224State(libcrux_iot_sha3::Sha3_224::new()))
            }
            HashAlgorithm::Sha3_256 => {
                HashState::Sha3_256(Sha3_256State(libcrux_iot_sha3::Sha3_256::new()))
            }
            HashAlgorithm::Sha3_384 => {
                HashState::Sha3_384(Sha3_384State(libcrux_iot_sha3::Sha3_384::new()))
            }
            HashAlgorithm::Sha3_512 => {
                HashState::Sha3_512(Sha3_512State(libcrux_iot_sha3::Sha3_512::new()))
            }
        }
    }

    fn update(&mut self, instance: &mut Self::State, data: &[u8]) {
        match instance {
            HashState::Direct(i) => self.0.hash().update(i, data),
            HashState::Sha256(s) => s.0.update(data),
            HashState::Sha3_224(s) => s.0.update(data.classify_ref()),
            HashState::Sha3_256(s) => s.0.update(data.classify_ref()),
            HashState::Sha3_384(s) => s.0.update(data.classify_ref()),
            HashState::Sha3_512(s) => s.0.update(data.classify_ref()),
        }
    }

    fn finalize(&mut self, instance: Self::State) -> Self::Output {
        match instance {
            HashState::Direct(underlying) => HashResult::Direct(self.0.hash().finalize(underlying)),
            HashState::Sha256(s) => {
                let mut output = [0u8; 32];
                s.0.finish(&mut output);
                HashResult::Sha256(output)
            }
            HashState::Sha3_224(s) => HashResult::Sha3_224(s.0.finish().declassify()),
            HashState::Sha3_256(s) => HashResult::Sha3_256(s.0.finish().declassify()),
            HashState::Sha3_384(s) => HashResult::Sha3_384(s.0.finish().declassify()),
            HashState::Sha3_512(s) => HashResult::Sha3_512(s.0.finish().declassify()),
        }
    }
}

pub enum HashAlgorithm<EC: ExtenderConfig> {
    Direct(HashAlgorithmOf<EC::Base>),
    Sha256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

// Seems the Derive wouldn't take because it only looks at whether all arguments are Clone, not at
// whether the parts of the arguments that are used are. Could be replaced by some
// derive-stuff-more-smartly crate.
impl<EC: ExtenderConfig> Clone for HashAlgorithm<EC> {
    fn clone(&self) -> Self {
        match self {
            HashAlgorithm::Direct(a) => HashAlgorithm::Direct(a.clone()),
            HashAlgorithm::Sha256 => HashAlgorithm::Sha256,
            HashAlgorithm::Sha3_224 => HashAlgorithm::Sha3_224,
            HashAlgorithm::Sha3_256 => HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_384 => HashAlgorithm::Sha3_384,
            HashAlgorithm::Sha3_512 => HashAlgorithm::Sha3_512,
        }
    }
}

// As for Clone
impl<EC: ExtenderConfig> core::fmt::Debug for HashAlgorithm<EC> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HashAlgorithm::Direct(arg0) => f.debug_tuple("Direct").field(arg0).finish(),
            HashAlgorithm::Sha256 => write!(f, "Sha256"),
            HashAlgorithm::Sha3_224 => write!(f, "Sha3_224"),
            HashAlgorithm::Sha3_256 => write!(f, "Sha3_256"),
            HashAlgorithm::Sha3_384 => write!(f, "Sha3_384"),
            HashAlgorithm::Sha3_512 => write!(f, "Sha3_512"),
        }
    }
}

// As for Clone
impl<EC: ExtenderConfig> PartialEq for HashAlgorithm<EC> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (HashAlgorithm::Direct(l0), HashAlgorithm::Direct(r0)) => l0 == r0,
            (HashAlgorithm::Sha256, HashAlgorithm::Sha256) => true,
            (HashAlgorithm::Sha3_224, HashAlgorithm::Sha3_224) => true,
            (HashAlgorithm::Sha3_256, HashAlgorithm::Sha3_256) => true,
            (HashAlgorithm::Sha3_384, HashAlgorithm::Sha3_384) => true,
            (HashAlgorithm::Sha3_512, HashAlgorithm::Sha3_512) => true,
            _ => false,
        }
    }
}

// As for Clone
impl<EC: ExtenderConfig> Eq for HashAlgorithm<EC> {}

impl<EC: ExtenderConfig> embedded_cal::HashAlgorithm for HashAlgorithm<EC> {
    fn len(&self) -> usize {
        match self {
            HashAlgorithm::Direct(a) => a.len(),
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha3_224 => SHA3_224_DIGEST_SIZE,
            HashAlgorithm::Sha3_256 => SHA3_256_DIGEST_SIZE,
            HashAlgorithm::Sha3_384 => SHA3_384_DIGEST_SIZE,
            HashAlgorithm::Sha3_512 => SHA3_512_DIGEST_SIZE,
        }
    }

    #[inline]
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        let number: i128 = number.into();

        match number {
            -16 => Some(HashAlgorithm::Sha256),
            _ => HashAlgorithmOf::<EC::Base>::from_cose_number(number).map(HashAlgorithm::Direct),
        }
    }

    #[inline]
    fn from_ni_id(number: u8) -> Option<Self> {
        match number {
            1 => Self::from_cose_number(-16),
            9 => Some(HashAlgorithm::Sha3_224),
            10 => Some(HashAlgorithm::Sha3_256),
            11 => Some(HashAlgorithm::Sha3_384),
            12 => Some(HashAlgorithm::Sha3_512),
            _ => None,
        }
    }

    #[inline]
    fn from_ni_name(name: &str) -> Option<Self> {
        match name {
            "sha-256" => Self::from_cose_number(-16),
            "sha3-224" => Some(HashAlgorithm::Sha3_224),
            "sha3-256" => Some(HashAlgorithm::Sha3_256),
            "sha3-384" => Some(HashAlgorithm::Sha3_384),
            "sha3-512" => Some(HashAlgorithm::Sha3_512),
            _ => None,
        }
    }
}

pub enum HashResult<EC: ExtenderConfig> {
    Direct(HashOutputOf<EC::Base>),
    Sha256([u8; 32]),
    Sha3_224([u8; SHA3_224_DIGEST_SIZE]),
    Sha3_256([u8; SHA3_256_DIGEST_SIZE]),
    Sha3_384([u8; SHA3_384_DIGEST_SIZE]),
    Sha3_512([u8; SHA3_512_DIGEST_SIZE]),
}

impl<EC: ExtenderConfig> AsRef<[u8]> for HashResult<EC> {
    fn as_ref(&self) -> &[u8] {
        match self {
            HashResult::Direct(result) => result.as_ref(),
            HashResult::Sha256(data) => data.as_slice(),
            HashResult::Sha3_224(data) => data.as_slice(),
            HashResult::Sha3_256(data) => data.as_slice(),
            HashResult::Sha3_384(data) => data.as_slice(),
            HashResult::Sha3_512(data) => data.as_slice(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestConfig;

    impl ExtenderConfig for TestConfig {
        type Base = embedded_cal::empty::EmptyCal<true>;
    }

    #[test]
    fn test_hash_algorithm_sha256() {
        let mut cal = Extender::<TestConfig>::new(embedded_cal::empty::EmptyCal);

        testvectors::test_hash_algorithm_sha256(&mut cal);
    }
}
