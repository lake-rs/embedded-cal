#![no_std]

pub trait HashProvider {
    type Algorithm: HashAlgorithm;
    /// State in which is carried between rounds of feeding data.
    ///
    /// As construction is not fallible, this can not be a handle into a limited pool.
    ///
    /// FIXME: Do we anticpate hardware that can *not* store its state in RAM, and thus needs to
    /// run from init through update into finalize without being preempted by another operation?
    type HashState: Sized;
    type HashResult: AsRef<[u8]>;

    // Spitballing here to convey the idea and check whether ownership and lifetimes can work this
    // way. FIXME: Pick terminology from existing crates.

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState;
    fn update(&mut self, instance: &mut Self::HashState, data: &[u8]);
    // FIXME: (How) do we best carry around that the results's AsRef is exactly the .len() of the
    // algorithm?
    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult;

    // Some convenience functions probably make sense

    fn full_pass(&mut self, algorithm: Self::Algorithm, data: &[u8]) -> Self::HashResult {
        let mut state = self.init(algorithm);
        self.update(&mut state, data);
        self.finalize(state)
    }

    // Should we have convenience functions also that pack HashState with a &mut self? (And can we
    // do that without default associated types? Probably, by providing a type in this crate.)
}

/// A hash algorithm identifier.
///
/// While const traits are not stable yet, implementers should prepare for the constructors and
/// other methods to be `const` functions.
// FIXME: Are all of those requirements good?
pub trait HashAlgorithm: Sized + PartialEq + Eq + core::fmt::Debug + Clone {
    /// Output length of .
    fn len(&self) -> usize;

    /// Selects a hash algorithm from its COSE number.
    ///
    /// FIXME: Do they really have matching COSE algorithm numbers? OSCORE and EDHOC use -10 for
    /// SHA-256, but that may be a stretch. Maybe this should also be
    /// `from_algorithm_underlying_cose_directhkdf_number()`?
    ///
    /// This works from `Into<i128>` because the numeric range of CBOR integers is effectively that
    /// of a i65 (the sign is in the data type); inlining will take care of systems not *actually*
    /// materializing any i128 comparisons, let alone arithmetic.
    #[inline]
    #[allow(unused_variables, reason = "Argument names are part of the documentation")]
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        None
    }

    /// Selects a hash algorithm from a Suite ID out of the IANA Named Information Hash Algorith
    /// Registry
    ///
    /// <https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg>
    ///
    /// Note that while the number is expressed as a [`u8`], the actual usable value space is
    /// 0..=63 excluding the reserved 32; implementations must return None for values outside this
    /// range.
    #[inline]
    #[allow(unused_variables, reason = "Argument names are part of the documentation")]
    fn from_ni_id(number: u8) -> Option<Self> {
        None
    }

    /// Selects a hash algorithm from a Hash Name String out of the IANA Named Information Hash
    /// Algorith Registry
    ///
    /// <https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg>
    #[inline]
    #[allow(unused_variables, reason = "Argument names are part of the documentation")]
    fn from_ni_name(name: &str) -> Option<Self> {
        None
    }
}

// FIXME: Should we introduce a feature to no build those all the time?
pub fn test_hash_algorithm_sha256<HA: HashAlgorithm>() {
    // FIXME see from_cose_number comment
    let cose_neg10 = HA::from_cose_number(-10);
    let ni_1 = HA::from_ni_id(1);
    let ni_named = HA::from_ni_name("sha-256");

    // Those are not *strictly* required, because there's no rule that any backend needs to
    // recognize all identifiers, but those should be widespread enough.
    assert_eq!(cose_neg10, ni_1);
    assert_eq!(cose_neg10, ni_named);

    // When we actually want to test for test vectors here, we'll need to take a &mut Hashing
    // rather than just the algorithm.
}
