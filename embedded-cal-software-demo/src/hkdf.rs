// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

// HkdfProvider is implemented for Extender<EC> via the blanket impl in embedded-cal.

#[cfg(test)]
mod tests {
    use crate::tests::dummy_sha256;
    use crate::{Extender, ExtenderConfig};

    struct ImplementSha256Short;

    impl ExtenderConfig for ImplementSha256Short {
        const IMPLEMENT_SHA2SHORT: bool = true;
        type Base = dummy_sha256::DummySha256;
    }

    #[test]
    fn test_hkdf_sha256_on_dummy() {
        let mut cal = Extender::<ImplementSha256Short>(dummy_sha256::DummySha256::new());
        testvectors::test_hkdf_sha256(&mut cal);
    }
}
