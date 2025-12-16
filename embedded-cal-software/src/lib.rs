//! Minimal stand-in for the libcrux based implementation and polyfills.
//!
//! Currently, this demonstrates how that layer would work on top of a hardware implementation that
//! only does the hard work of the SHA hashes and not the clerical buffering / padding.
#![no_std]

pub struct Extender<B: embedded_cal::Cal>(B);

const HASH_WRAPPER_MAX_BLOCKSIZE: usize = 64;

impl<B: embedded_cal::Cal> embedded_cal::Cal for Extender<B> {}

impl<B: embedded_cal::Cal> embedded_cal::HashProvider for Extender<B> {
    type Algorithm = HashAlgorithm<B::Algorithm>;

    type HashState = HashState<B::HashState>;

    type HashResult = B::HashResult;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        HashState {
            block_length: match &algorithm {
                HashAlgorithm::BlockWrap(_, block_length) => Some(*block_length),
                HashAlgorithm::Direct(_) => None,
            },
            underlying: self.0.init(match algorithm {
                HashAlgorithm::BlockWrap(alg, _) | HashAlgorithm::Direct(alg) => alg,
            }),
            cursor: 0,
            buffer: [0; _],
            blocks_written: 0,
        }
    }

    fn update(&mut self, instance: &mut Self::HashState, mut data: &[u8]) {
        let Some(block_length) = instance.block_length else {
            self.0.update(&mut instance.underlying, data);
            return;
        };
        let block_length: usize = block_length.into();
        // Not trying to be efficient here: This is a demo implementation.
        // In particular, this does *not* test sending more than a single buffer multiple in;
        // that'll be tested soon enough (and easy to fix).
        loop {
            let buffer_to_fill = &mut instance.buffer[instance.cursor..block_length];
            let fill_bytes = if data.len() > buffer_to_fill.len() {
                buffer_to_fill.len()
            } else {
                data.len()
            };
            buffer_to_fill[..fill_bytes].copy_from_slice(&data[..fill_bytes]);
            data = &data[fill_bytes..];
            instance.cursor += fill_bytes;
            if instance.cursor < block_length {
                return;
            }
            self.0
                .update(&mut instance.underlying, &instance.buffer[..block_length]);
            instance.cursor = 0;
            instance.blocks_written += 1;
        }
    }

    fn finalize(&mut self, mut instance: Self::HashState) -> Self::HashResult {
        if let Some(block_length) = instance.block_length {
            let block_length: usize = block_length.into();

            let mut padding = [0; _];
            let padding_size = sha256_padding(
                instance.blocks_written * block_length + instance.cursor,
                &mut padding,
            );
            self.update(&mut instance, &padding[..padding_size]);
            assert!(instance.cursor == 0, "Padding didn't pad out the message");
        };

        self.0.finalize(instance.underlying)
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum HashAlgorithm<A: embedded_cal::HashAlgorithm> {
    BlockWrap(A, core::num::NonZeroUsize),
    Direct(A),
}

impl<A: embedded_cal::HashAlgorithm> embedded_cal::HashAlgorithm for HashAlgorithm<A> {
    fn len(&self) -> usize {
        match self {
            HashAlgorithm::BlockWrap(a, _) => a.len(),
            HashAlgorithm::Direct(a) => a.len(),
        }
    }

    #[inline]
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        let number: i128 = number.into();

        if let Some(a) = A::from_cose_number(number) {
            return Some(HashAlgorithm::Direct(a));
        }

        // This is just demo code, so we just pick any: SHA256
        if number == -16 {
            return Some(HashAlgorithm::BlockWrap(
                A::fullblock_nonfinishing_from_cose_number(-16)?,
                64.try_into().unwrap(),
            ));
        }

        None
    }

    #[inline]
    fn from_ni_id(number: u8) -> Option<Self> {
        match number {
            1 => Self::from_cose_number(-16),
            _ => None,
        }
    }
}

pub struct HashState<S> {
    underlying: S,
    // If this is None, we pass on; otherwise, we spool and apply SHA-2 finalization. (Support for
    // more algorithms would require an extra disambiguator).
    block_length: Option<core::num::NonZeroUsize>,
    // I'd really love to use heapless -- can we hax that up?
    cursor: usize,
    buffer: [u8; HASH_WRAPPER_MAX_BLOCKSIZE],
    // … or combine cursor with blocks_written and modulo it out? Doesn't matter for a demo.
    blocks_written: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    mod dummy_sha256;

    #[test]
    fn test_hash_algorithm_sha256_on_dummy() {
        let mut cal = Extender(dummy_sha256::DummySha256);

        testvectors::test_hash_algorithm_sha256(&mut cal);
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
