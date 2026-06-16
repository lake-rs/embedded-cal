// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::{Cal, HashProvider};

use super::*;

#[derive(Clone)]
pub struct Sha256State(libcrux_sha2::Sha256);

pub enum HashState<EC: ExtenderConfig> {
    Direct(<<EC::Base as Cal>::HashProvider as HashProvider>::State),
    Sha256(Sha256State),
}

impl<EC: ExtenderConfig> Clone for HashState<EC> {
    // This is the default implemnentation, but we can't derive it because EC is not clone. (We
    // don't expect it to, but we'd need "minimal derives" in Rust to make it derivable).
    fn clone(&self) -> Self {
        match self {
            Self::Direct(d) => Self::Direct(d.clone()),
            Self::Sha256(s) => Self::Sha256(s.clone()),
        }
    }
}

impl<EC: ExtenderConfig> HashProvider for Extender<EC> {
    type Algorithm = HashAlgorithm<EC>;
    type State = HashState<EC>;
    type Output = HashResult<EC>;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::State {
        match algorithm {
            HashAlgorithm::Sha256 => HashState::Sha256(Sha256State(libcrux_sha2::Sha256::new())),
            HashAlgorithm::Direct(alg) => HashState::Direct(self.0.hash().init(alg)),
        }
    }

    fn update(&mut self, instance: &mut Self::State, data: &[u8]) {
        match instance {
            HashState::Direct(i) => self.0.hash().update(i, data),
            HashState::Sha256(s) => s.0.update(data),
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
        }
    }
}

pub enum HashAlgorithm<EC: ExtenderConfig> {
    Sha256,
    Direct(<<EC::Base as Cal>::HashProvider as HashProvider>::Algorithm),
}

// Seems the Derive wouldn't take because it only looks at whether all arguments are Clone, not at
// whether the parts of the arguments that are used are. Could be replaced by some
// derive-stuff-more-smartly crate.
impl<EC: ExtenderConfig> Clone for HashAlgorithm<EC> {
    fn clone(&self) -> Self {
        match self {
            HashAlgorithm::Sha256 => HashAlgorithm::Sha256,
            HashAlgorithm::Direct(a) => HashAlgorithm::Direct(a.clone()),
        }
    }
}

// As for Clone
impl<EC: ExtenderConfig> core::fmt::Debug for HashAlgorithm<EC> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "Sha256"),
            HashAlgorithm::Direct(arg0) => f.debug_tuple("Direct").field(arg0).finish(),
        }
    }
}

// As for Clone
impl<EC: ExtenderConfig> PartialEq for HashAlgorithm<EC> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (HashAlgorithm::Direct(l0), HashAlgorithm::Direct(r0)) => l0 == r0,
            (HashAlgorithm::Sha256, HashAlgorithm::Sha256) => true,
            _ => false,
        }
    }
}

// As for Clone
impl<EC: ExtenderConfig> Eq for HashAlgorithm<EC> {}

impl<EC: ExtenderConfig> embedded_cal::HashAlgorithm for HashAlgorithm<EC> {
    fn len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Direct(a) => a.len(),
        }
    }

    #[inline]
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        let number: i128 = number.into();

        match number {
            -16 => Some(HashAlgorithm::Sha256),
            _ => <<EC::Base as Cal>::HashProvider as HashProvider>::Algorithm::from_cose_number(
                number,
            )
            .map(HashAlgorithm::Direct),
        }
    }

    #[inline]
    fn from_ni_id(number: u8) -> Option<Self> {
        match number {
            1 => Self::from_cose_number(-16),
            _ => None,
        }
    }

    #[inline]
    fn from_ni_name(name: &str) -> Option<Self> {
        match name {
            "sha-256" => Self::from_cose_number(-16),
            _ => None,
        }
    }
}

pub enum HashResult<EC: ExtenderConfig> {
    Sha256([u8; 32]),
    Direct(<<EC::Base as Cal>::HashProvider as HashProvider>::Output),
}

impl<EC: ExtenderConfig> AsRef<[u8]> for HashResult<EC> {
    fn as_ref(&self) -> &[u8] {
        match self {
            HashResult::Sha256(data) => data.as_slice(),
            HashResult::Direct(result) => result.as_ref(),
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
