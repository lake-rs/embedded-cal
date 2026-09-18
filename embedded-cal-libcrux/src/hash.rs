// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use embedded_cal::HashProvider;
use libcrux_iot_sha3::{
    SHA3_224_DIGEST_SIZE, SHA3_256_DIGEST_SIZE, SHA3_384_DIGEST_SIZE, SHA3_512_DIGEST_SIZE,
};
use libcrux_secrets::{ClassifyRef, DeclassifyRef, U8};

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

pub struct HashState<EC: ExtenderConfig>(HashStateInner<EC>);

enum HashStateInner<EC: ExtenderConfig> {
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
        let inner = match &self.0 {
            HashStateInner::Direct(d) => HashStateInner::Direct(d.clone()),
            HashStateInner::Sha256(s) => HashStateInner::Sha256(s.clone()),
            HashStateInner::Sha3_224(s) => HashStateInner::Sha3_224(s.clone()),
            HashStateInner::Sha3_256(s) => HashStateInner::Sha3_256(s.clone()),
            HashStateInner::Sha3_384(s) => HashStateInner::Sha3_384(s.clone()),
            HashStateInner::Sha3_512(s) => HashStateInner::Sha3_512(s.clone()),
        };
        Self(inner)
    }
}

impl<EC: ExtenderConfig> HashProvider for Extender<EC> {
    type Algorithm = HashAlgorithm<EC>;
    type State = HashState<EC>;
    type Output = HashResult<EC>;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::State {
        let inner = match algorithm {
            HashAlgorithm::Direct(alg) => HashStateInner::Direct(self.0.hash().init(alg)),
            HashAlgorithm::Sha256 => {
                HashStateInner::Sha256(Sha256State(libcrux_sha2::Sha256::new()))
            }
            HashAlgorithm::Sha3_224 => {
                HashStateInner::Sha3_224(Sha3_224State(libcrux_iot_sha3::Sha3_224::new()))
            }
            HashAlgorithm::Sha3_256 => {
                HashStateInner::Sha3_256(Sha3_256State(libcrux_iot_sha3::Sha3_256::new()))
            }
            HashAlgorithm::Sha3_384 => {
                HashStateInner::Sha3_384(Sha3_384State(libcrux_iot_sha3::Sha3_384::new()))
            }
            HashAlgorithm::Sha3_512 => {
                HashStateInner::Sha3_512(Sha3_512State(libcrux_iot_sha3::Sha3_512::new()))
            }
        };
        HashState(inner)
    }

    fn update(&mut self, instance: &mut Self::State, data: &[u8]) {
        // classify the data for compatibility with libcrux_iot_sha3 when the check-secret-independence
        // feature is activated. No-op if the feature is disabled.
        self.update_with_classified(instance, data.classify_ref());
    }

    fn finalize(&mut self, instance: Self::State) -> Self::Output {
        let inner = match instance.0 {
            HashStateInner::Direct(underlying) => {
                HashResultInner::Direct(self.0.hash().finalize(underlying))
            }
            HashStateInner::Sha256(s) => {
                let mut output = [0u8; 32];
                s.0.finish(&mut output);
                HashResultInner::Sha256(output)
            }
            HashStateInner::Sha3_224(s) => HashResultInner::Sha3_224(s.0.finish()),
            HashStateInner::Sha3_256(s) => HashResultInner::Sha3_256(s.0.finish()),
            HashStateInner::Sha3_384(s) => HashResultInner::Sha3_384(s.0.finish()),
            HashStateInner::Sha3_512(s) => HashResultInner::Sha3_512(s.0.finish()),
        };
        HashResult(inner)
    }
}

impl<EC: ExtenderConfig> Extender<EC> {
    /// Update the hash state with [`tyalias@U8`] data.
    ///
    /// This is intended for compatibility with libcrux APIs that work on the
    /// [libcrux-secrets][ls] types. If a SHA-3 algorithm was selected,
    /// the classified data is passed directly to the libcrux-iot SHA-3 implementation.  
    /// For the other backends, the data is first [declassified][dc], which is a noop
    /// if the `check-secret-independence` feature is not enabled.
    ///
    /// <div class="warning">
    ///
    /// If this method is used with the `check-secret-independence` feature and a
    /// hash algorithm other than SHA-3, a successful compilation **does not** constitute
    /// a proof that the hash algorithm implementation is secret independent.
    ///
    /// </div>
    ///
    /// [ls]: https://docs.rs/libcrux-secrets/latest/libcrux_secrets/
    /// [dc]: https://docs.rs/libcrux-secrets/latest/libcrux_secrets/trait.Declassify.html
    /// [ha]: `embedded_cal::HashAlgorithm`
    pub fn update_with_classified(
        &mut self,
        instance: &mut <Self as HashProvider>::State,
        data: &[U8],
    ) {
        match &mut instance.0 {
            // declassify the data for compatibility with the direct and sha2 algorithms
            // when the check-secret-independence feature is activated. No-op if the feature
            // is disabled.
            HashStateInner::Direct(i) => self.0.hash().update(i, data.declassify_ref()),
            HashStateInner::Sha256(s) => s.0.update(data.declassify_ref()),
            HashStateInner::Sha3_224(s) => s.0.update(data),
            HashStateInner::Sha3_256(s) => s.0.update(data),
            HashStateInner::Sha3_384(s) => s.0.update(data),
            HashStateInner::Sha3_512(s) => s.0.update(data),
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

        // Try base first, and fall back to libcrux
        if let Some(base_algo) = HashAlgorithmOf::<EC::Base>::from_cose_number(number) {
            return Some(HashAlgorithm::Direct(base_algo));
        }

        match number {
            -16 => Some(HashAlgorithm::Sha256),
            // There are no COSE numbers for SHA-3
            _ => None,
        }
    }

    #[inline]
    fn from_ni_id(number: u8) -> Option<Self> {
        if let Some(base_algo) = HashAlgorithmOf::<EC::Base>::from_ni_id(number) {
            return Some(HashAlgorithm::Direct(base_algo));
        }

        match number {
            1 => Some(HashAlgorithm::Sha256),
            9 => Some(HashAlgorithm::Sha3_224),
            10 => Some(HashAlgorithm::Sha3_256),
            11 => Some(HashAlgorithm::Sha3_384),
            12 => Some(HashAlgorithm::Sha3_512),
            _ => None,
        }
    }

    #[inline]
    fn from_ni_name(name: &str) -> Option<Self> {
        if let Some(base_algo) = HashAlgorithmOf::<EC::Base>::from_ni_name(name) {
            return Some(HashAlgorithm::Direct(base_algo));
        }

        match name {
            "sha-256" => Some(HashAlgorithm::Sha256),
            "sha3-224" => Some(HashAlgorithm::Sha3_224),
            "sha3-256" => Some(HashAlgorithm::Sha3_256),
            "sha3-384" => Some(HashAlgorithm::Sha3_384),
            "sha3-512" => Some(HashAlgorithm::Sha3_512),
            _ => None,
        }
    }
}

/// The digest of the [`Extender`] as [`HashProvider`].
pub struct HashResult<EC: ExtenderConfig>(HashResultInner<EC>);

enum HashResultInner<EC: ExtenderConfig> {
    Direct(HashOutputOf<EC::Base>),
    Sha256([u8; 32]),
    Sha3_224([U8; SHA3_224_DIGEST_SIZE]),
    Sha3_256([U8; SHA3_256_DIGEST_SIZE]),
    Sha3_384([U8; SHA3_384_DIGEST_SIZE]),
    Sha3_512([U8; SHA3_512_DIGEST_SIZE]),
}

impl<EC: ExtenderConfig> HashResult<EC> {
    /// Return hash bytes as [`tyalias@U8`].
    ///
    /// This provides convenient access to the hash digest bytes as a [libcrux-secrets][li]
    /// [`tyalias@U8`] type for integration with other libcrux APIs.
    ///
    /// # Secret Independence Checking
    ///
    /// The embedded-cal-libcrux  [`HashProvider`] uses a SHA-3 implementation
    /// provided by [libcrux-iot][li] that integrates with the [libcrux-secrets][ls] crate
    /// for lightweight secret-independence checking. This method directly exposes the
    /// classified result of the SHA-3 implementation, while classifying the result
    /// when the base or SHA-2 algorithms are used. If the `check-secret-independence`
    /// feature is not enabled, these classify operations are noops.
    ///
    /// [li]: https://github.com/celabshq/libcrux-iot
    /// [ls]: https://docs.rs/libcrux-secrets/latest/libcrux_secrets/
    pub fn as_classified(&self) -> &[U8] {
        match &self.0 {
            HashResultInner::Direct(result) => result.as_ref().classify_ref(),
            HashResultInner::Sha256(data) => data.as_slice().classify_ref(),
            // The HashResult must impl AsRef<u8>, so we need to declassify the secret output of
            // Sha3 to type-check under the `check-secret-independence feature`
            HashResultInner::Sha3_224(data) => data.as_slice(),
            HashResultInner::Sha3_256(data) => data.as_slice(),
            HashResultInner::Sha3_384(data) => data.as_slice(),
            HashResultInner::Sha3_512(data) => data.as_slice(),
        }
    }
}

impl<EC: ExtenderConfig> AsRef<[u8]> for HashResult<EC> {
    fn as_ref(&self) -> &[u8] {
        // The HashResult must impl AsRef<u8>, so we need to declassify the secret output of
        // Sha3 to type-check under the `check-secret-independence feature`.
        // Re-uses `as_classified` to reduce code duplication. Without `check-secret-independence`,
        // enabled, all classify/declassify are noops.
        self.as_classified().declassify_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestConfig;

    impl ExtenderConfig for TestConfig {
        type Base = embedded_cal::empty::EmptyCal;
    }

    #[test]
    fn test_hash_algorithm_sha256() {
        let mut cal = Extender::<TestConfig>::new(embedded_cal::empty::EmptyCal);
        testvectors::test_hash_algorithm_sha256(&mut cal);
    }

    #[test]
    fn test_hash_algorithm_sha3_224() {
        let mut cal = Extender::<TestConfig>::new(embedded_cal::empty::EmptyCal);
        testvectors::sha3::test_hash_algorithm_sha3_224(&mut cal);
    }

    #[test]
    fn test_hash_algorithm_sha3_256() {
        let mut cal = Extender::<TestConfig>::new(embedded_cal::empty::EmptyCal);
        testvectors::sha3::test_hash_algorithm_sha3_256(&mut cal);
    }

    #[test]
    fn test_hash_algorithm_sha3_384() {
        let mut cal = Extender::<TestConfig>::new(embedded_cal::empty::EmptyCal);
        testvectors::sha3::test_hash_algorithm_sha3_384(&mut cal);
    }

    #[test]
    fn test_hash_algorithm_sha3_512() {
        let mut cal = Extender::<TestConfig>::new(embedded_cal::empty::EmptyCal);
        testvectors::sha3::test_hash_algorithm_sha3_512(&mut cal);
    }

    /// Test that the `update_with_classified` API type-checks.
    #[test]
    fn test_update_with_classified_sha3_256() {
        let mut cal = Extender::<TestConfig>::new(embedded_cal::empty::EmptyCal);
        let mut state = cal.init(HashAlgorithm::Sha3_256);
        cal.update_with_classified(&mut state, [0; 200].classify_ref());
        let _result = cal.finalize(state);
    }
}
