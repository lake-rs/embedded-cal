//! Minimal stand-in for the libcrux based implementation and polyfills.
//!
//! Currently, this demonstrates how that layer would work on top of a hardware implementation that
//! only does the hard work of the SHA hashes and not the clerical buffering / padding.
#![no_std]

use embedded_cal::{
    Cal, HashProvider, HmacProvider,
    plumbing::Plumbing,
    plumbing::hash::{SHA2SHORT_BLOCK_SIZE, Sha2Short, Sha2ShortVariant},
};

pub trait ExtenderConfig {
    const IMPLEMENT_SHA2SHORT: bool;

    type Base: Cal + Plumbing;
}

impl<EC: ExtenderConfig> Extender<EC> {
    pub fn new(base: EC::Base) -> Self {
        Self(base)
    }
}

pub struct Extender<EC: ExtenderConfig>(EC::Base);

const HASH_WRAPPER_MAX_BLOCKSIZE: usize = 68;

impl<EC: ExtenderConfig> embedded_cal::Cal for Extender<EC> {}

impl<EC: ExtenderConfig> HashProvider for Extender<EC> {
    type Algorithm = HashAlgorithm<EC>;

    type HashState = HashState<EC>;

    type HashResult = HashResult<EC>;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        match algorithm {
            HashAlgorithm::Sha256 => HashState::Sha256 {
                written: 0,
                buffer: [0; _],
                instance: Sha2Short::init(&mut self.0, Sha2ShortVariant::Sha256),
            },
            HashAlgorithm::Direct(alg) => HashState::Direct(HashProvider::init(&mut self.0, alg)),
        }
    }

    fn update(&mut self, instance: &mut Self::HashState, mut data: &[u8]) {
        match instance {
            HashState::Direct(i) => HashProvider::update(&mut self.0, i, data),
            HashState::Sha256 {
                written,
                buffer,
                instance,
            } => {
                // In the common case of this also being 64, the compiler has all it needs to fold
                // this in with the line after it.
                let mut written_in_buffer = if *written < <EC::Base as Sha2Short>::FIRST_CHUNK_SIZE
                {
                    // First chunk not yet sent to hardware; all bytes are still buffered.
                    *written
                } else {
                    // First chunk already sent; remaining bytes cycle through SHA2SHORT_BLOCK_SIZE blocks.
                    (*written - <EC::Base as Sha2Short>::FIRST_CHUNK_SIZE) % SHA2SHORT_BLOCK_SIZE
                };

                // Not trying to be efficient here: This is a demo implementation.
                // In particular, this does *not* test sending more than a single buffer multiple in;
                // that'll be tested soon enough (and easy to fix).
                loop {
                    let buffer_max = if *written < <EC::Base as Sha2Short>::FIRST_CHUNK_SIZE {
                        <EC::Base as Sha2Short>::FIRST_CHUNK_SIZE
                    } else {
                        SHA2SHORT_BLOCK_SIZE
                    };

                    let buffer_to_fill = &mut buffer[written_in_buffer..buffer_max];
                    let fill_bytes = if data.len() > buffer_to_fill.len() {
                        buffer_to_fill.len()
                    } else {
                        data.len()
                    };
                    buffer_to_fill[..fill_bytes].copy_from_slice(&data[..fill_bytes]);
                    data = &data[fill_bytes..];
                    *written += fill_bytes;
                    written_in_buffer += fill_bytes;
                    if written_in_buffer < buffer_max {
                        return;
                    }
                    Sha2Short::update(&mut self.0, instance, &buffer[..buffer_max]);
                    written_in_buffer = 0;
                }
            }
        }
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        match instance {
            HashState::Direct(underlying) => {
                HashResult::Direct(HashProvider::finalize(&mut self.0, underlying))
            }
            HashState::Sha256 {
                written,
                buffer,
                instance,
            } => {
                // FIXME: deduplicate with update
                let mut written_in_buffer = if written < <EC::Base as Sha2Short>::FIRST_CHUNK_SIZE {
                    // First chunk not yet sent to hardware; all bytes are still buffered.
                    written
                } else {
                    // First chunk already sent; remaining bytes cycle through SHA2SHORT_BLOCK_SIZE blocks.
                    (written - <EC::Base as Sha2Short>::FIRST_CHUNK_SIZE) % SHA2SHORT_BLOCK_SIZE
                };
                // END FIXME

                let (instance, buffer) = if <EC::Base as Sha2Short>::SEND_PADDING {
                    let mut padding = [0; _];
                    let padding_size = sha256_padding(written, &mut padding);
                    let mut rewrapped = HashState::Sha256 {
                        written,
                        buffer,
                        instance,
                    };
                    HashProvider::update(self, &mut rewrapped, &padding[..padding_size]);
                    let HashState::Sha256 {
                        instance, buffer, ..
                    } = rewrapped
                    else {
                        unreachable!("Updating doesn't change the hash state type");
                    };
                    written_in_buffer = 0;
                    // Actually buffer will be unused, but we still need to have something
                    (instance, buffer)
                } else {
                    (instance, buffer)
                };

                let mut output = [0; 32];
                Sha2Short::finalize(
                    &mut self.0,
                    instance,
                    &buffer[..written_in_buffer],
                    &mut output,
                );
                HashResult::Sha256(output)
            }
        }
    }
}

pub enum HashAlgorithm<EC: ExtenderConfig> {
    // FIXME: Ideally we'd employ some witness type of <EC::Base as Sha2Short>::SUPPORTED
    // to render this uninhabited when unused.
    Sha256,
    Direct(<EC::Base as HashProvider>::Algorithm),
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
            _ => <EC::Base as HashProvider>::Algorithm::from_cose_number(number)
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

pub enum HashState<EC: ExtenderConfig> {
    Direct(<EC::Base as HashProvider>::HashState),
    Sha256 {
        written: usize,
        // FIXME: would rely on const generic arguments, have to pick configurable maximum instead and
        // const assert on that fitting.
        //
        // [u8; embedded_cal::plumbing::hash::hash_buffer_requirements::<EC::Base>()]
        //
        // (Also as we're an enum, we don't even have to go through hash_buffer_requirements, but
        // the problem is the same)
        buffer: [u8; HASH_WRAPPER_MAX_BLOCKSIZE],
        instance: <EC::Base as Sha2Short>::State,
    },
}

pub enum HashResult<EC: ExtenderConfig> {
    Sha256([u8; 32]),
    Direct(<EC::Base as HashProvider>::HashResult),
}

impl<EC: ExtenderConfig> AsRef<[u8]> for HashResult<EC> {
    fn as_ref(&self) -> &[u8] {
        match self {
            HashResult::Sha256(data) => data.as_slice(),
            HashResult::Direct(result) => result.as_ref(),
        }
    }
}

/// HMAC algorithm identifier for software HMAC over [`Extender`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HmacAlgorithm {
    HmacSha256,
}

impl embedded_cal::HmacAlgorithm for HmacAlgorithm {
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

pub enum HmacState<EC: ExtenderConfig> {
    HmacSha256 {
        /// Inner hash state accumulating `H((K XOR ipad) || message)`.
        inner: HashState<EC>,
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
    type HmacState = HmacState<EC>;
    type HmacResult = HmacResult;

    fn init(&mut self, algorithm: Self::Algorithm, key: &[u8]) -> Self::HmacState {
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

                HmacState::HmacSha256 { inner, outer_key }
            }
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

// Remaining code is copied from https://github.com/lake-rs/embedded-cal/pull/9

fn sha256_padding(msg_len: usize, out: &mut [u8; 256]) -> usize {
    sha2_padding(msg_len, 64, 56, 8, out)
}

fn sha2_padding(
    msg_len: usize,
    block_size: usize,
    length_offset: usize,
    length_bytes: usize,
    out: &mut [u8; 256],
) -> usize {
    out[0] = 0x80;

    let rem = (msg_len + 1) % block_size;

    let zero_pad = if rem <= length_offset {
        length_offset - rem
    } else {
        length_offset + (block_size - rem)
    };

    for b in &mut out[1..=zero_pad] {
        *b = 0;
    }

    let bit_len = (msg_len as u128) * 8;
    let len_bytes_be = bit_len.to_be_bytes();

    let start = 1 + zero_pad;
    out[start..start + length_bytes].copy_from_slice(&len_bytes_be[(16 - length_bytes)..]);

    1 + zero_pad + length_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    mod dummy_sha256;

    struct ImplementSha256Short;

    impl ExtenderConfig for ImplementSha256Short {
        const IMPLEMENT_SHA2SHORT: bool = true;
        type Base = dummy_sha256::DummySha256;
    }

    #[test]
    fn test_hash_algorithm_sha256_on_dummy() {
        let mut cal = Extender::<ImplementSha256Short>(dummy_sha256::DummySha256);

        testvectors::test_hash_algorithm_sha256(&mut cal);
    }

    #[test]
    fn test_hmac_sha256_on_dummy() {
        let mut cal = Extender::<ImplementSha256Short>(dummy_sha256::DummySha256);

        testvectors::test_hmac_sha256(&mut cal);
    }
}
