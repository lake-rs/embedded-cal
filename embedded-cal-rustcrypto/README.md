<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
-->

# `embedded-cal-rustcrypto`: Software implementation of embedded-cal based on RustCrypto libraries

This crate makes many operations from [RustCrypto](https://github.com/RustCrypto) available in the embedded-cal ecosystem.

See [the embedded-cal documentation](https://docs.rs/embedded-cal/) for a high-level overview,
[the algorithms list](https://github.com/lake-rs/embedded-cal/blob/main/ALGORITHMS.md)
for a detailed list of which module supports which operations,
or the [crate's documentation on initialization](https://docs.rs/embedded-cal-rustcrypto/latest/embedded_cal_rustcrypto/type.Standalone.html#method.standalone).

## Use on embedded systems

This crate is `no_std`.
The `standalone` feature (and thus `Standalone::standalone()`) takes its randomness from the operating system through `getrandom`,
so on bare metal targets it only builds with a [custom `getrandom` backend](https://docs.rs/getrandom/0.4/#custom-backend).

Without one, pass any infallible cryptographically secure RNG through [embedded-cal-rand](https://docs.rs/embedded-cal-rand/):
`RustcryptoCalExtender::new_extending(WithRng::new(EmptyCal, rng))`.
In place of `EmptyCal`, any other `Cal` (such as a hardware back-end) can be extended.

## ⚠️ Security note

This crate provides cryptographic primitives from crates of which only some have received external audits,
and none have received any formal verification in their default configuration.
<!-- At the time of writing, x25519-dalek has an optional fiat backend, no other README mentions formal methods. -->
See the dependencies' README files for the state per cryptographic operation.

## Contributing, license and other metadata

See the [main project README](https://github.com/lake-rs/embedded-cal/blob/main/README.md)
for metadata topics such as supported Rust versions (MSRV), citing embedded-cal, licenses, and how to contribute.
