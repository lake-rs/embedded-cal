// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
//! Tools helpful in implementing `embedded-cal`

pub mod aesccm;
pub mod montgomery;
pub mod p256;
pub mod p384;

/// Whether the big-endian `scalar` is in `1..n`, for a big-endian curve order `n` of the same
/// length; this is what private keys, nonces and signature components must satisfy.
///
/// This is not constant time: both comparisons stop at the first byte that differs, so the timing
/// reveals how many leading bytes of `scalar` match `0` or `n`. It is nevertheless used on secret
/// scalars (sampling keys and nonces, validating private keys): a uniformly random scalar starts
/// with such a matching byte only about 1 time in 128, and even then only that prefix leaks.
pub fn in_scalar_range<const N: usize>(scalar: &[u8; N], n: &[u8; N]) -> bool {
    // Big-endian bytes compare like digits: `<` is decided by the first byte that differs.
    *scalar != [0; N] && scalar < n
}

/// Draws a scalar uniformly from `1..n` by rejection sampling, for a big-endian curve order `n`.
///
/// Rejected candidates are wiped; the caller owns (and must wipe) the result.
pub fn random_scalar<const N: usize>(rng: &mut impl rand_core::CryptoRng, n: &[u8; N]) -> [u8; N] {
    let mut scalar = zeroize::Zeroizing::new([0u8; N]);
    loop {
        rng.fill_bytes(&mut *scalar);
        if in_scalar_range(&scalar, n) {
            return *scalar;
        }
    }
}

/// A 2-variant generic enum, useful for writing implementations that provide some own variants on
/// those passed on directly to a base.
///
/// It implements various traits depending on the own and base trait; currently, just as `AsRef`.
///
/// # Caveats
///
/// **Do not use this to** extend own enums, as those will become types with their fixed layout that
/// might easily use the very same discriminator field as the underlying type, and thus defeat
/// possible optimizations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Either<Own, Base> {
    Own(Own),
    Direct(Base),
}

impl<T: ?Sized, Own: AsRef<T>, Base: AsRef<T>> AsRef<T> for Either<Own, Base> {
    fn as_ref(&self) -> &T {
        match self {
            Either::Own(o) => o.as_ref(),
            Either::Direct(d) => d.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks the edges of `1..n` for one curve order `n`.
    fn check_scalar_range<const N: usize>(n: &[u8; N]) {
        assert!(!in_scalar_range(&[0; N], n));
        assert!(!in_scalar_range(n, n));
        assert!(!in_scalar_range(&[0xff; N], n));
        let mut one = [0; N];
        one[N - 1] = 1;
        assert!(in_scalar_range(&one, n));
        let mut n_minus_one = *n;
        n_minus_one[N - 1] -= 1;
        assert!(in_scalar_range(&n_minus_one, n));
    }

    #[test]
    fn scalar_range() {
        check_scalar_range(&p256::P256_ORDER_BYTES);
        check_scalar_range(&p384::P384_ORDER_BYTES);
    }
}
