<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
-->

This crate is an example and a demo of how implementations of embedded-cal's plumbing layer can have their pieces connected into a functional Cal implementation for the algorithms supported by the plumbing.

It is **not** intended for production.
While the cryptographic algorithms it implements are passed through embedded-cal's test suite,
do not rely on their correctness, let alone other any cryptographically relevant properties.

It is useful for for experimentation and testing,
especially where the `embedded-cal-libcrux` implementation (that provides the same functionality properly)
does not yet have a particular mechanism implemented.
It may also (but currently does not) provide tools for debugging individual parts of a plumbing implementation
(e.g. for bypassing a hardware's provided HKDF mechanisms but using its hash acceleration),
which generally makes no sense in production software<!-- unless that discovers a bug in the hardware, but then the Rust implementation of that driver should disable the faulty component, at least conditionally -->.
