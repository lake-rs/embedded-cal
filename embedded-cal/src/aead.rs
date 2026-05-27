// FIXME: Document that we don't do variable length tags (or more precisely, overhead of encryption
// like in plain AES), and that we expect the tag to be separate (although we could consider
// changing interfaces if it turns out that everyone appends the tag to the ciphertext anyway, to
// the point where it's easier to just take a longe buffer, especially if future algorithms start
// *expecing* that).

/// Symmetric encryption with authentication and additional data.
///
/// This trait is modelled after the
/// [`aead::AeadInPlace`](https://docs.rs/aead/latest/aead/trait.AeadInPlace.html) trait,
/// but does not use it directly because
/// - `embedded-cal` passes around an exclusive reference to its engine, and
/// - its operation is cryptographically agile rather than monomorphized over algorithms.
pub trait AeadProvider {
    type Algorithm: AeadAlgorithm;
    type Key: Sized;
    type Tag: Sized + AsRef<[u8]>;

    /// Loads a key from the key's bytes.
    ///
    /// # Panics
    ///
    /// … if key's length is not `alg.key_length()`.
    fn load_from_keydata(&mut self, alg: Self::Algorithm, key: &[u8]) -> Self::Key;

    /// Encrypts data in place.
    ///
    /// The AEAD tag is returned separately; depending on the higher-layer protocol it is appended
    /// to the message or gets sent separately.
    ///
    /// # Panics
    ///
    /// … if nonce's length is not `alg.nonce_length()` of the algorithm that generated the key.
    // Potential for enhancement: Create a key-and-nonce type that moves the nonce length check
    // from encryption time to preparation time?
    fn encrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        aad: impl AadGenerator,
    ) -> Self::Tag;

    /// Decrypts data in place.
    ///
    /// The AEAD tag is returned separately; depending on the higher-layer protocol it is appended
    /// to the message or gets sent separately.
    ///
    /// # Panics
    ///
    /// … if nonce's length is not `alg.nonce_length()` of the algorithm that generated the key, or
    /// the tag's length is not `alg.tag_length()`.
    ///
    /// # Implementation guidance
    ///
    /// As the message is passed in in a buffer that is available even in case of error, it is best
    /// practice to zero the message when verification fails, to make sure that even when the error
    /// is handled badly, an attacker can not hope to place crafted content in a place that might
    /// be mistaken for verified data.
    #[must_use = "message must not be accessed after a failed decryption"]
    fn decrypt_in_place(
        &mut self,
        key: &Self::Key,
        nonce: &[u8],
        message: &mut [u8],
        tag: &[u8],
        aad: impl AadGenerator,
    ) -> Result<(), DecryptionFailed>;
}

/// Error indicating that an AEAD decryption failed.
///
/// AEAD algorithms generally do not report structured errors; this always indicates some form of
/// "the calculated AEAD tag mismatched".
#[derive(Debug)]
pub struct DecryptionFailed;

impl core::fmt::Display for DecryptionFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("decryption failed")
    }
}

impl core::error::Error for DecryptionFailed {}

pub trait AeadAlgorithm: Sized + PartialEq + Eq + core::fmt::Debug + Clone {
    /// Length of a key in bytes.
    fn key_length(&self) -> usize;

    /// Length of the cryptographic tag in bytes.
    fn tag_length(&self) -> usize;

    /// Length of the nonce (called IV in some algorithms) in bytes.
    fn nonce_length(&self) -> usize;

    /// Selects an AEAD algorithm from its COSE number.
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

/// Type which an implementation of [`Cal`][crate::Cal] can use when it implements no AEAD
/// algorithm for [`AeadProvider`].
///
/// This type is uninhabited and can stand in for all of the [`Algorithm`][AeadProvider::Algorithm]
/// and [`Tag`][AeadProvider::Tag] associated types.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NoAeadAlgorithms {}

/// Tool for providing the AAD (Additional Authenticated Data) in a scatter-gather fashion.
pub trait AadGenerator {
    // FIXME: What precise guarantees do we want to ask/give?
    fn items(&self) -> impl Iterator<Item = &[u8]>;
}

impl AadGenerator for &[u8] {
    fn items(&self) -> impl Iterator<Item = &[u8]> {
        [*self].into_iter()
    }
}

impl AadGenerator for &[&[u8]] {
    fn items(&self) -> impl Iterator<Item = &[u8]> {
        self.iter().copied()
    }
}

pub fn test_aead_algorithm_aesccm_16_64_128<AP: AeadProvider>() {
    let cose_10 = AP::Algorithm::from_cose_number(10i8).expect(
        "test for type claiming AES-CCM-16-64-128 compatibility did not recognize COSE number 10",
    );
    assert_eq!(cose_10.tag_length(), 8)
}
