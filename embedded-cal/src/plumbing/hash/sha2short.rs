#[derive(PartialEq, Eq)]
pub enum Sha2ShortVariant {
    Sha244,
    Sha256,
}

/// Trait indicating that there is hardware support for SHA2.
///
/// The assumptions on the hardware so far are:
/// * It takes *most* data in chunks that are the block size.
/// * The first chunk size may be different. (Yes that is odd; nonetheless, that is how the
///   STM32WB55 works).
/// * It may or may not add the padding. If it does add the padding, an incomplete block may be
///   sent at finalization.
/// * All those decisions are known at build time, and expressed in constants.
pub trait Sha2Short {
    /// Whether this trait is actually supported. See [`Plumbing`][super::super::Plumbing] docs for
    /// rationale..
    const SUPPORTED: bool;

    /// If true, the user needs to send all the padding data into the implementation through the
    /// [`Self::update()`] function.
    const SEND_PADDING: bool;

    /// Size of the first chunk to be sent to [`Self::update()`], if it differs from the block size.
    ///
    /// Implementations that do not need this special handling should set this to 0.
    const FIRST_CHUNK_SIZE: usize;
    /// If true, the [`Self::update()`] function can be passed data from consecutive blocks.
    const UPDATE_MULTICHUNK: bool;

    /// State containing an ongoing operation.
    ///
    /// Analogous to [`crate::HashProvider::HashState`].
    type State: Sized;

    /// Initiates a [`Self::State`] according to the selected algorithm.
    fn init(&mut self, variant: Sha2ShortVariant) -> Self::State;
    /// Iteratively sends data to be hashed into the instance.
    ///
    /// If [`Self::SEND_PADDING`] is true, data needs to (eventually) include the SHA-2 padding;
    /// otherwise, no padding must be added by the caller.
    ///
    /// Data must be sent in chunks as described by `*CHUNK*` associated constants: The first chunk
    /// must be of size [`Self::FIRST_CHUNK_SIZE`] (unless that is 0, then that empty slice is not
    /// sent), subsequent chunks of the block size. If [`Self::UPDATE_MULTICHUNK`] is given,
    /// multiple chunks (first and/or subsequent) can be passed in together for efficiency.
    ///
    /// Note that for the `SEND_PADDING = false` case, some data may be left after sending whole
    /// chunks; that data is passed in at finalization.
    ///
    /// # Panics
    ///
    /// … if data lengths do not adhere to the `CHUNKS` configuration.
    ///
    /// (There is no need for the implementation to panic: It may also just produce a wrong result).
    fn update(&mut self, instance: &mut Self::State, data: &[u8]);
    /// Extracts the hash into a target slice.
    ///
    /// Implementations must accept overly long slices, and may write the full 32 byte rather than
    /// the 28 byte of a SHA-244 if the output is long enough.
    ///
    /// # Panics
    ///
    /// * if the target array is insufficient for the type of hash, or
    /// * if the last chunk data is too large and should really have been sent through the update
    ///   function. (In particular, for `SEND_PADDING = true` implementations, if the last_chunk is
    ///   not empty).
    ///
    /// (There is no need for the implementation to panic: It may also just produce a wrong result).
    // FIXME the constraints on who must and may do what are a current guess, we should re-evaluate
    // them. Maybe passing a 32-byte target array works better.
    //
    // Same goes for the last chunk -- can we accept more? Probably not, leave it up to the higher
    // layer to do this just as it should be done.
    fn finalize(&mut self, instance: Self::State, last_chunk: &[u8], target: &mut [u8]);

    // FIXME: For platforms with costly suspension, should we provide an init-update-finish
    // all-in-one method?
}
