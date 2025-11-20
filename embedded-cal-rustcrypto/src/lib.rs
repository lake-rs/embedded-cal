use digest::Digest;

pub struct RustcryptoCal;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum HashAlgorithm {
    Sha256,
}

impl embedded_cal::HashAlgorithm for HashAlgorithm {
    fn len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
        }
    }

    // FIXME: See from_cose_number definition
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        match number.into() {
            -10 => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }

    fn from_ni_id(number: u8) -> Option<Self> {
        match number {
            1 => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }

    fn from_ni_name(name: &str) -> Option<Self> {
        match name {
            "sha-256" => Some(HashAlgorithm::Sha256),
            _ => None,
        }
    }
}

pub enum HashState {
    Sha256(sha2::Sha256),
}

pub enum HashResult {
    Sha256([u8; 32]),
}

impl AsRef<[u8]> for HashResult {
    fn as_ref(&self) -> &[u8] {
        match self {
            HashResult::Sha256(r) => &r[..],
        }
    }
}

impl embedded_cal::HashProvider for RustcryptoCal {
    type Algorithm = HashAlgorithm;
    type HashState = HashState;
    type HashResult = HashResult;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        match algorithm {
            // Same for any, really
            HashAlgorithm::Sha256 => HashState::Sha256(Default::default()),
        }
    }

    fn update(&mut self, instance: &mut Self::HashState, data: &[u8]) {
        match instance {
            // Same for any, really
            HashState::Sha256(s) => s.update(data),
        }
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        match instance {
            // Same for any, really
            HashState::Sha256(s) => HashResult::Sha256(s.finalize().into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_sha256() {
        let mut cal = RustcryptoCal;

        embedded_cal::test_hash_algorithm_sha256::<
            <RustcryptoCal as embedded_cal::HashProvider>::Algorithm,
        >();
        testvectors::test_hash_algorithm_sha256(&mut cal);
    }
}
