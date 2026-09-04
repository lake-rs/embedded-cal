// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use super::*;
use ::hmac::Mac;
use embedded_cal::{Cal, HmacProvider};

type HmacSha256 = ::hmac::Hmac<sha2::Sha256>;

// std only macro-generates `Default` for arrays up to 32 elements
type MaxLenBuf = digest::generic_array::GenericArray<u8, digest::consts::U64>;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum HmacAlgorithm<BA> {
    HmacSha256,
    Direct(BA),
}

impl<BA: embedded_cal::HmacAlgorithm> embedded_cal::HmacAlgorithm for HmacAlgorithm<BA> {
    // FIXME: computing a max(32, BA::MAX_LEN) here would need a generic const expression
    // which is not available on stable Rust.
    const MAX_LEN: usize = 64;

    type MaxLenBuf = MaxLenBuf;

    fn len(&self) -> usize {
        match self {
            HmacAlgorithm::HmacSha256 => 32,
            HmacAlgorithm::Direct(a) => a.len(),
        }
    }

    #[inline]
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        let number: i128 = number.into();
        if let Some(a) = BA::from_cose_number(number) {
            return Some(HmacAlgorithm::Direct(a));
        }
        match number {
            5 => Some(HmacAlgorithm::HmacSha256),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub enum HmacKey<BK> {
    HmacSha256(HmacSha256),
    Direct(BK),
}

pub enum HmacState<BS> {
    HmacSha256(HmacSha256),
    Direct(BS),
}

pub enum HmacResult<BR> {
    HmacSha256([u8; 32]),
    Direct(BR),
}

impl<BR: AsRef<[u8]>> AsRef<[u8]> for HmacResult<BR> {
    fn as_ref(&self) -> &[u8] {
        match self {
            HmacResult::HmacSha256(r) => &r[..],
            HmacResult::Direct(r) => r.as_ref(),
        }
    }
}

impl<Base: Cal> HmacProvider for RustcryptoCalExtender<Base> {
    type Algorithm = HmacAlgorithm<HmacAlgorithmOf<Base>>;
    type Key = HmacKey<HmacKeyOf<Base>>;
    type State = HmacState<HmacStateOf<Base>>;
    type Output = HmacResult<HmacOutputOf<Base>>;

    fn load_from_keydata(&mut self, algorithm: Self::Algorithm, key: &[u8]) -> Self::Key {
        match algorithm {
            HmacAlgorithm::HmacSha256 => HmacKey::HmacSha256(
                HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length"),
            ),
            HmacAlgorithm::Direct(a) => HmacKey::Direct(self.base.hmac().load_from_keydata(a, key)),
        }
    }

    fn init(&mut self, key: Self::Key) -> Self::State {
        match key {
            HmacKey::HmacSha256(h) => HmacState::HmacSha256(h),
            HmacKey::Direct(k) => HmacState::Direct(self.base.hmac().init(k)),
        }
    }

    fn update(&mut self, state: &mut Self::State, data: &[u8]) {
        match state {
            HmacState::HmacSha256(h) => h.update(data),
            HmacState::Direct(s) => self.base.hmac().update(s, data),
        }
    }

    fn finalize(&mut self, state: Self::State) -> Self::Output {
        match state {
            HmacState::HmacSha256(h) => HmacResult::HmacSha256(h.finalize().into_bytes().into()),
            HmacState::Direct(s) => HmacResult::Direct(self.base.hmac().finalize(s)),
        }
    }
}
