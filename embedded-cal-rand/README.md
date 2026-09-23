<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
-->

# `embedded-cal-rand`: Making a cryptographically secure random number generator accessible in embedded-cal

This crate provides two things:

* By default, a narrowly scoped extender for [`embedded-cal`](https://docs.rs/embedded-cal/latest/embedded_cal/)
  that forwards the [`TryCryptoRng`](https://docs.rs/rand_core/0.10.1/rand_core/trait.TryCryptoRng.html) trait
  into a given RNG,
  whereas other cryptographic operations are forwarded to the underlying component.

* With the feature `new_from_sys`,
  a constructor for such a wrapper that uses the [`rand` crate](https://docs.rs/rand/latest/rand/fn.make_rng.html) for easy setup.

## Using this crate

This crate is rarely used directly,
because implementations of embedded-cal on embedded systems generally also provide access to that platform's random number generator,
and software implementations used on standard systems provide their own constructors for standalone operation that includes a random number generator.
(The latter are the main motivation for this crate, as standalone functionality is implemented in terms of this crate).
