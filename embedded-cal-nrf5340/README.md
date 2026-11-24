<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
-->

# `embedded-cal-nrf5340`: Implementation of embedded-cal for nRF5340 hardware

This crate drives the Arm TrustZone CryptoCell-312 found in the nRF5340 application core
directly through its registers (via [`nrf-pac`](https://crates.io/crates/nrf-pac)), without
Arm's or Nordic's precompiled runtime libraries.

See [the embedded-cal documentation](https://docs.rs/embedded-cal/) for a high-level overview,
including usage and setup instructions.

The tests in `tests/` run on an nRF5340 DK through `probe-rs`; from this directory, run
`cargo test`.

## ⚠️ Security note

This crate provides cryptographic primitives based on hardware features.
It has not undergone any external audit.

## Contributing, license and other metadata

See the [main project README](https://github.com/lake-rs/embedded-cal/blob/main/README.md)
for metadata topics such as supported Rust versions (MSRV), citing embedded-cal, licenses, and how to contribute.
