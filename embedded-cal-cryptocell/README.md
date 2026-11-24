<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
-->

# `embedded-cal-cryptocell`: Implementation of embedded-cal for Arm TrustZone CryptoCell hardware

This crate drives the Arm TrustZone CryptoCell directly through its registers (via
[`nrf-pac`](https://crates.io/crates/nrf-pac)), without Arm's or Nordic's precompiled runtime
libraries. The chip is selected with a cargo feature:

| Feature   | Chip    | CryptoCell |
|-----------|---------|------------|
| `nrf5340` | nRF5340 | CC312      |
| `nrf52840` | nRF52840 | CC310 (no AES-256) |

No code path branches on secret data (see the crate documentation for details).

See [the embedded-cal documentation](https://docs.rs/embedded-cal/) for a high-level overview,
including usage and setup instructions.

The tests in `tests/` run on the chip's development kit through `probe-rs`; from this
directory, run `cargo test-nrf5340` or `cargo test-nrf52840`.

## ⚠️ Security note

This crate provides cryptographic primitives based on hardware features.
It has not undergone any external audit.

## Contributing, license and other metadata

See the [main project README](https://github.com/lake-rs/embedded-cal/blob/main/README.md)
for metadata topics such as supported Rust versions (MSRV), citing embedded-cal, licenses, and how to contribute.
