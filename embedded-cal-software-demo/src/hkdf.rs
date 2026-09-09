// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

// HkdfProvider is implemented for Extender<EC> via the blanket impl in embedded-cal.

#[cfg(test)]
mod tests {
    use crate::{Extender, ExtenderConfig};

    struct ImplementSha256Short;

    impl ExtenderConfig for ImplementSha256Short {
        const IMPLEMENT_SHA2SHORT: bool = true;
        const IMPLEMENT_SHA2SHORT_PLUMBING: bool = true;
        type Base = embedded_cal::empty::EmptyCal;
    }

    #[test]
    fn test_hkdf_sha256() {
        let mut cal = Extender::<ImplementSha256Short>(embedded_cal::empty::EmptyCal);
        testvectors::test_hkdf_sha256(&mut cal);
    }
}
