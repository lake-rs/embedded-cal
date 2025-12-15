#![no_std]

pub trait Cal: HashProvider {}

pub trait HashProvider {
    type Algorithm: HashAlgorithm;
    /// State in which is carried between rounds of feeding data.
    ///
    /// As construction is not fallible, this can not be a handle into a limited pool.
    ///
    /// If hardware exists that an only hash efficiently in an internal state, this needs to be an
    /// encapsulation of that state, as construction is not fallible. As this is likely a costly
    /// process, such implementations are encourated to implement [`Self::hash`] in an optimized
    /// way. (Also, if such a hardware actually exists, please open an issue about it).
    type HashState: Sized;
    type HashResult: AsRef<[u8]>;

    // Spitballing here to convey the idea and check whether ownership and lifetimes can work this
    // way. FIXME: Pick terminology from existing crates.

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState;
    fn update(&mut self, instance: &mut Self::HashState, data: &[u8]);
    // FIXME: (How) do we best carry around that the results's AsRef is exactly the .len() of the
    // algorithm?
    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult;

    /// Hash contiguous in-memory data in a single pass.
    ///
    /// This method is provided, but implementations are encouraged to provide optimized versions
    /// if an actual speed-up can be gained; conversely, users are encouraged to use this if data
    /// is already present in this form.
    ///
    /// Optimized versions are expected to be rare, though, so don't go out of your way using it:
    /// Only buffer the full data, or create special cases for when there actually is just one item
    /// in an iterator, without testing and possibly consulting with the back-end authors first.
    fn hash(&mut self, algorithm: Self::Algorithm, data: &[u8]) -> Self::HashResult {
        let mut state = self.init(algorithm);
        self.update(&mut state, data);
        self.finalize(state)
    }
}

/// A hash algorithm identifier.
///
/// While const traits are not stable yet, implementers should prepare for the constructors and
/// other methods to be `const` functions.
#[allow(
    clippy::len_without_is_empty,
    reason = "Lint only makes sense when length can reasonably be zero, which is not the case here."
)]
// FIXME: Are all of those requirements good?
pub trait HashAlgorithm: Sized + PartialEq + Eq + core::fmt::Debug + Clone {
    /// Output length of .
    fn len(&self) -> usize;

    /// Selects a hash algorithm from its COSE number.
    ///
    /// The algorithm number comes from the ["COSE Algorithms"
    /// registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms) maintained by IANA.
    ///
    /// This works from `Into<i128>` because the numeric range of CBOR integers is effectively that
    /// of a i65 (the sign is in the data type); inlining will take care of systems not *actually*
    /// materializing any i128 comparisons, let alone arithmetic.
    #[inline]
    #[allow(
        unused_variables,
        reason = "Argument names are part of the documentation"
    )]
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
    #[allow(
        unused_variables,
        reason = "Argument names are part of the documentation"
    )]
    fn from_ni_id(number: u8) -> Option<Self> {
        None
    }

    /// Selects a hash algorithm from a Hash Name String out of the IANA Named Information Hash
    /// Algorith Registry
    ///
    /// <https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg>
    #[inline]
    #[allow(
        unused_variables,
        reason = "Argument names are part of the documentation"
    )]
    fn from_ni_name(name: &str) -> Option<Self> {
        None
    }
}

// FIXME: Should we introduce a feature to no build those all the time?
pub fn test_hash_algorithm_sha256<HA: HashAlgorithm>() {
    // FIXME see from_cose_number comment
    let cose_neg10 = HA::from_cose_number(-16);
    let ni_1 = HA::from_ni_id(1);
    let ni_named = HA::from_ni_name("sha-256");

    // Those are not *strictly* required, because there's no rule that any backend needs to
    // recognize all identifiers, but those should be widespread enough.
    assert_eq!(cose_neg10, ni_1);
    assert_eq!(cose_neg10, ni_named);

    // When we actually want to test for test vectors here, we'll need to take a &mut Hashing
    // rather than just the algorithm.
}
