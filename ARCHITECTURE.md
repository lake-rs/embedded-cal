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
    * A wrapper generic over a Mutex provides shared access ([#10](https://github.com/lake-rs/embedded-cal/issues/10), optional)
    * Incomplete operations should not block the system:
      Not all operations are expected to be complted before an operation of the same kind is started.

      Note that this is not about preemption or multi-core support (the exclusive reference ensures that operations are serialized),
      but about operatins receiving partial data (eg. hashing some part of a file) and continuing that operation after calculating a different item's hash.

      This is limited to where split operation is supported conceptually -- AEAD operations do require the plain-/ciphertext to be present throughout the operation.
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

## FAQ

* Q: Why are key, hash encryption states statically sized, rather than using generics to minimize stack usage?

  embedded-cal is designed for alogrithm agility.
  The concrete choice of algorithms is a run-time decision, allowing to switch off an unusable algorithm at any time.

  This apparently wastes resources (mostly in terms of stack size), but gives returns in reliability beyond the security gains of multiple algorithmns:
  If an operation can complete without a stack overflow on one algorithm, the stack is sufficiently sized for any algorithm.
  (And especially on microcontrollers, while stack space is limited, there is no harm in using more of it as long as the maximum is not exceeded).

  Moreover, this avoids the cost in program size (flash memory) of monomorphizing parts of a program to different algorithms.

  Applications that do need to minimize sizes in some part of the program are encourated to explore three possibilities in that order:

  * In storage, work with algorithm specific outputs.
    For example, if a particular part of the application only admits two concrete kinds of hashes that have the same size,
    it can use dynnamic sizes during computation, but store only the fixed-size bytes.
  * If the larger algorithms are completely unused, do not enable them globally.
    In general, embedded applications will need to opt into a selected subset of the supported algorithms anyway,
    and then, the selection focus can be on a diverse subset of the algorithms with smaller footprint.
  * There can be different instances of a `Cal` in a system.
    For cases when the run-time size is critical but the system needs to support larger algorithms in other parts,
    a differently parametrized `Cal` (that, for example, only supports the single algorithm) can be used.

* Q: The interfaces for starting operations are not parametrized.
  How does this, for example, support algorithms such as SHAKE that can have different output sizes?

  A: The interfaces for selecting an algorithm are currently based on COSE and TLS,
  both of which prefer to assign a single identifier to a fully parametrized algortihm (eg. SHAKE256).
  If constructors from other ecosystems are added where there are extra parameters, those constructors will need to account for them.

  Note that this is purely a constructor thing:
  If an implementation has a general algorithm for SHAKE,
  its `HashAlgorithm` item can be an enum with a `Shake(usize)` variant,
  even if only a limited subset of those can be crated with the portable constructors.
