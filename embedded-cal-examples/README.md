<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
-->

# `embedded-cal-examples`: Example library and application building on embedded-cal

This crate contains examples of how to use `embedded-cal`.

It can be used in different ways:

* [Looking at the library code](https://github.com/lake-rs/embedded-cal/blob/main/embedded-cal-examples/src/lib.rs):

  This is how a protocol implementation might do use the library.

* To just run that code:

  A standalone tool that is part of this crate can be run with different cryptographic back-ends,
  and then runs the library code seen above.

  The binary consists of [startup code](https://github.com/lake-rs/embedded-cal/blob/main/embedded-cal-examples/src/bin/demo.rs) that selects the back-end based on selected features,
  sets up logging,
  and leaves the rest to the library.

  Run it with libcrux like this:

  ```console
  $ cargo run --bin demo --features backend-libcrux,log-standalone
  [*] Running examples on a Cal of type &mut embedded_cal_libcrux::Extender<embedded_cal_libcrux::standalone::StandaloneConfig>
  [*] Computed SHA-256 hash of "hello world" (encoded in ASCII); hash is b9 4d 27 b9 93 4d 3e 08 a5 2e 52 d7 da 7d ab fa c4 84 ef e3 7a 53 80 ee 90 88 f7 ac e2 ef cd e9
  [*] Agreeing to use curve 1
  [*] Public part of our ephemeral key is 2c fc 54 [..., will differ on each run]
  [*] Shared secret with that peer is 4b a2 ee [..., will differ on each run]
  ```

  By comparison, running with rustcrypto back-ends selects a different curve (at the time of writing) from a set of public keys suggested by the network peer which the demo simulates:

  ```console
  $ cargo run --bin demo --features backend-rustcrypto,log-standalone
  [*] Running examples on a Cal of type &mut embedded_cal_rustcrypto::RustcryptoCalExtender<embedded_cal_rand::WithRng<embedded_cal::empty::EmptyCal, rand::rngs::std::StdRng>>
  [*] Computed SHA-256 hash of "hello world" (encoded in ASCII); hash is b9 4d 27 b9 93 4d 3e 08 a5 2e 52 d7 da 7d ab fa c4 84 ef e3 7a 53 80 ee 90 88 f7 ac e2 ef cd e9
  [*] Agreeing to use curve 4
  [...]
  ```

  Just for illustration, you can also select a null back-end (which, as is to be expected, provides no algorithms):

  ```console
  $ cargo run --bin demo --features backend-empty,log-standalone
  [*] Running examples on a Cal of type &mut embedded_cal::empty::EmptyCal
  [W] Skipping hash demo: Suite does not support SHA-256
  [W] No matching ECDH algorithm found.
  ```

  The same code is also run as part of the integration tests of the various hardware implementations shipped [along with embedded-cal](https://github.com/lake-rs/embedded-cal);
  there, output is sent through the `defmt` ecosystem rather than through `log`.

* Using the code as a library:

  When starting a project in which a platform's implementation of embedded-cal is used
  but the final application is not yet in place,
  calling `embedded_cal_examples::show_examples()` can be an easy way to demonstrate that the back-end is available and functional.

## Contributing, license and other metadata

See the [main project README](https://github.com/lake-rs/embedded-cal/blob/main/README.md)
for metadata topics such as supported Rust versions (MSRV), citing embedded-cal, licenses, and how to contribute.
