pub trait HmacProvider {
    type Algorithm: HmacAlgorithm;
    /// A nascent state that .
    type Key: Clone + Sized;
    /// State carried between rounds of feeding data into the HMAC.
    type HmacState: Sized;
    /// Output of an HMAC operation.
    type HmacResult: AsRef<[u8]>;

    /// Starts an HMAC operation based on a key that is entered as raw bytes.
    ///
    /// This is a convenience wrapper for `Self::init(Self::load_from_keydatra(algorithm, key))`.
    fn init_with_keydata(&mut self, algorithm: Self::Algorithm, key: &[u8]) -> Self::HmacState {
        let key = self.load_from_keydata(algorithm, key);
        self.init(key)
    }
    /// Initializes a key from raw bytes.
    fn load_from_keydata(&mut self, algorithm: Self::Algorithm, key: &[u8]) -> Self::Key;
    /// Starts an HMAC operation.
    fn init(&mut self, key: Self::Key) -> Self::HmacState;
    fn update(&mut self, state: &mut Self::HmacState, data: &[u8]);
    fn finalize(&mut self, state: Self::HmacState) -> Self::HmacResult;

    /// Compute HMAC over contiguous in-memory data in a single pass, based on a key directly
    /// entered as bytes.
    ///
    /// This is a shortcut for [`self.init_with_keydata(…)`][Self::init_with_keydata()] /
    /// [`self.update(…)`][Self::update()] / [`self.finalize(…)`][Self::finalize()].
    fn hmac_with_keydata(
        &mut self,
        algorithm: Self::Algorithm,
        key: &[u8],
        data: &[u8],
    ) -> Self::HmacResult {
        let mut state = self.init_with_keydata(algorithm, key);
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
    /// The maximum output of [`Self::len()`].
    ///
    /// This can be used by consumers of this trait (e.g. the HMAC trait) to build internal
    /// buffers.
    const MAX_LEN: usize;

    /// A `[u8; MAX_LEN]` type.
    ///
    /// This is needed as a workaround while limitation inconst generics mean that users (in
    /// particular, HKDF implementations) can not create a local variable of type `[u8;
    /// Self::HmacAlgorithm::MAX_LEN]`.
    ///
    /// The only sensible implementation is `[u8; MAX_LEN]`. Users of the trait may panic if it is
    /// not, but must assume that it is anything for safety and security.
    type MaxLenBuf: AsMut<[u8]> + Sized + Default;

    /// Output length in bytes.
    ///
    /// ## Constraints
    ///
    /// The returned value must not be greater than [`Self::MAX_LEN`]; otherwise, consumers of the
    /// trait may panic.
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

pub fn test_hmac_algorithm_hmacsha256<HA: HmacAlgorithm>() {
    let cose_5 = HA::from_cose_number(5i8);
    assert!(
        cose_5.is_some(),
        "HMAC 256/256 must be recognised by COSE number 5"
    );
    assert_eq!(cose_5.as_ref().map(|a| a.len()), Some(32));
}
