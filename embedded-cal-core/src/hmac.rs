pub trait HmacProvider {
    type Algorithm: HmacAlgorithm;
    /// State carried between rounds of feeding data into the HMAC.
    type HmacState: Sized;
    /// Output of an HMAC operation.
    type HmacResult: AsRef<[u8]>;

    fn init(&mut self, algorithm: Self::Algorithm, key: &[u8]) -> Self::HmacState;
    fn update(&mut self, state: &mut Self::HmacState, data: &[u8]);
    fn finalize(&mut self, state: Self::HmacState) -> Self::HmacResult;

    /// Compute HMAC over contiguous in-memory data in a single pass.
    fn hmac(&mut self, algorithm: Self::Algorithm, key: &[u8], data: &[u8]) -> Self::HmacResult {
        let mut state = self.init(algorithm, key);
        self.update(&mut state, data);
        self.finalize(state)
    }
}

/// An HMAC algorithm identifier.
#[allow(
    clippy::len_without_is_empty,
    reason = "Lint only makes sense when length can reasonably be zero, which is not the case here."
)]
pub trait HmacAlgorithm: Sized + PartialEq + Eq + core::fmt::Debug + Clone {
    /// Output length in bytes.
    fn len(&self) -> usize;

    /// Selects an HMAC algorithm from its COSE number.
    ///
    /// The algorithm number comes from the ["COSE Algorithms"
    /// registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms) maintained by IANA.
    #[inline]
    #[allow(
        unused_variables,
        reason = "Argument names are part of the documentation"
    )]
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        None
    }
}

/// Type which an implementation of [`Cal`][crate::Cal] can use when it implements no HMAC
/// algorithm for [`HmacProvider`].
///
/// This type is uninhabited and can stand in for all of the [`Algorithm`][HmacProvider::Algorithm],
/// [`HmacState`][HmacProvider::HmacState] and [`HmacResult`][HmacProvider::HmacResult] associated
/// types.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NoHmacAlgorithms {}

impl HmacAlgorithm for NoHmacAlgorithms {
    fn len(&self) -> usize {
        match *self {}
    }
}

impl AsRef<[u8]> for NoHmacAlgorithms {
    fn as_ref(&self) -> &[u8] {
        match *self {}
    }
}

pub fn test_hmac_algorithm_hmacsha256<HA: HmacAlgorithm>() {
    let cose_5 = HA::from_cose_number(5i8);
    assert!(
        cose_5.is_some(),
        "HMAC 256/256 must be recognised by COSE number 5"
    );
    assert_eq!(cose_5.as_ref().map(|a| a.len()), Some(32));
}
