# Architectural considerations for embedded-cal

This document describes the architecture of embedded-cal.
As of now, this consists of design considerations, boundary conditions and requirements:
In the course of the implementation, those will be step in the background of a description of the full architecture.

## Design considerations and requirements

The main contributions in this project are

* an interface towards cryptographic primitives that is easy to use safely on constrained systems
* implementations of the interface ("backends") that can be combined:
  * a formally verified implementation of the supported algorithms, and
  * hardware accelerated implementations for some microcontrollers.

The provided implementations are not exhaustive:
A goal of the project is to encourage the development of implementations on a large variety of hardware backends.

### Requirements and optional features

Features being optional means that it is unsure whether embedded-cal can or should imlement them in a first iteration.
At any rate, a provider of cryptographic primitives can offer any subset of them.

* Usable with `no_std`
    * No arbitrary size limits: If any constraints are technically necessary, they need to be easy to tune.
* Provides access to cryptographic primitives:
    * AEAD with streaming AAD
    * ECDSA with streaming AAD
    * ECDH
    * Hashes
    * HKDF
    * HPKE (optional)
    * Other post-quantum mechanism (optional)
    * Symmetric encryption (optional; may be covered through AEAD if interfaces lean the COSE direction)
    * Random number generation
* Provides access to low-level cryptographic operations:
    * Individual AES operations
    * ECC coordinate operations (addition, multiplication etc.)
    * These operations may be of limited visibility compared to the remaining public API for stability reasons.
* Algorithm agility: Interfaces are algorithm generic at runtime.
    * Implementations provide associated types that express supported algorithms.
      These types avoid some misuse types (mixed use),
      fully parametrize the algorithms,
      and focus the error handling needed at runtime to well-understood spots.
    * Algorithm agility can be disabled in the type system by a back-end that provides just a single algorithm of a type and employs a ZST algorithm marker associated type. (optional)
    * Algorithms can be queried by COSE identifiers (required) or other established identifiers such as TLS (optional)
* Secret protection:
    * Keys are expressed using per-backend types that ensure that only matching operations are performed.
    * Backends can use references to keys and thus not create them in memory.
    * Secrets handled by the library are handled though zeroizing or similar interfaces.
* Instances are accessed through an exclusive reference.
    * A wrapper generic over a Mutex provides shared access (optional)
* It can provide the required cryptographic operations for
    * EDHOC (Lakers)
    * OSCORE (libOSCORE)
    * SUIT (as to be used in Ariel OS)
    * TLS (no concrete implementation planned)

Providing high-level COSE operations is an optional goal outside of the immediate scope of the trait.

## Implementation

The interface is implemented by a family of traits,
which reside in [`embedded_cal`](./embedded-cal/src/lib.rs).

Currently, a subset of the primitives is implemented there,
but adhering to all the generic principles.

## Usage

Practical use requires setting up an Cal instances;
the one currently provided is [`embedded_cal_rustcrypto::RustcryptoCal`](./embedded-cal-rustcrypto/src/lib.rs).
While that instance can be constructed at any point,
hardware based instances will come with their own non-trivial `::new()` function,
and will best be used augmented by (i.e., wrapped in) the formally verified implementation.

Once an exclusive reference to such an object exists,
its methods guide its use;
the test vectors have an [example of how to use hashing](./testvectors/src/lib.rs).
