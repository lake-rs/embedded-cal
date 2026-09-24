<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
-->

# `embedded-cal`: A Cryptographic Abstraction Layer (CAL) for embedded systems

*An embedded-systems-friendly verified crypto provider.*

embedded-cal is an abstraction for providers of cryptographic operations designed for the Rust language,
and comes with a verified implementation which is compatible with popular embedded platforms.
Using it, applications can be 1) fast on popular embedded platforms; 2) resistant to certain classes of side-channel attacks; 3) usable without the Rust standard library. Implementations for specific hardware make hardware acceleration support available for popular microcontroller units. The libcrux based software implementation fills in the gaps in hardware support, and includes formally verified for secret independence using the hax framework, a verification tool for high assurance code.

## Documentation and getting started

The main documentation resides with the code, and is [rendered on docs.rs](https://docs.rs/embedded-cal/) for all versions and crates.
An overview of all the crates is given below.

<!-- absolute URI is needed because this gets copied onto crates.io -->
Additionally, the [guided tour](https://github.com/lake-rs/embedded-cal/blob/main/GUIDED_TOUR.md) is available
to get an impression of how the library is used,
including running it in bare-metal setups.

## Components

Components of this project are the following crates:

* [`embedded-cal`](https://crates.io/crates/embedded-cal): 
  The main component, in which the abstraction interface is defined.
  Its [documentation](https://docs.rs/embedded-cal/) goes into the details of the interfaces,
  including the [main `Cal` trait](https://docs.rs/embedded-cal/latest/embedded_cal/trait.Cal.html).

* Hardware implementations for [nRF54L15](https://crates.io/crates/embedded-cal-nrf54l15)
  and [STM32WBA55](https://crates.io/crates/embedded-cal-stm32wba55).
  
  Due to the stackable architecture of embedded-cal,
  those do not need to implement all high-level operations
  (which is not just repetitive but also error-prone),
  but can rely on software implementations to complete them.

* The main software implementation is [embedded-cal-libcrux](https://crates.io/crates/embedded-cal-libcrux).
  It provides both full algorithms and implementations that build on building blocks that are closer to hardware.

* The [embedded-cal-software-demo](https://crates.io/crates/embedded-cal-software-demo) crate is used
  as a staging ground for exploration of the combination of hardware and software features.
  It is not designed for production use,
  but its exploratory implementations can be useful to understand features,
  or to compare hardware accelerations that are not yet available in the libcrux version.

* The [embedded-cal-rustcrypto](https://crates.io/crates/embedded-cal-rustcrypto) crate
  makes many operations from RustCrypto available.
  It does not compose high-level operations from possibly accelerated operations.
  Its main use is to easily make algorithms available that already have a Rust implementation,
  and to make it easy to start using embedded-cal.

While the software implementations can be instanciated standalone,
hardware accelerated implementations need platform specific initialization.
Those crates can be initialized in bare-metal setups as illustrated in their tests,
or provided as utility by an embedded operating systems like [Ariel OS](https://ariel-os.org).

Typical users of the traits
are network and security protocol implementations
such as
[Lakers](https://github.com/lake-rs/lakers/),
[libOSCORE](https://gitlab.com/oscore/liboscore)
or implementations of [SUIT](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/).

## MSRV

These crates currently have no MSRV; they target latest stable Rust at the time of writing.

Examples can use unstable features if it needed.

## Publications

`embedded-cal` was introduced in:

* embedded-cal: A Formally Verified Cryptographic Provider for Embedded Platforms. Elsa Lopez Perez, William Takeshi Pereira, Thomas Watteyne, Christian Amsüss, Franziskus Kiefer and Jonas Schneider-Bensch, Karthikeyan Bhargavan, Mališa Vučinić. International Workshop on Security, Privacy and Trust in the Internet of Things (SPT-IoT), part of IEEE International Conference on Pervasive Computing and Communications (PerCom), Pisa, Italy, 16-20 March 2026. **(Best Paper Award).** [PDF is available!](https://hal.science/hal-05524081v1/document)

## License

All files developed as part of this project is distributed under the terms of both the [Apache License, version 2.0](LICENSES/Apache-2.0.txt) and the [MIT License](LICENSES/MIT.txt).

Individual hardware accelerators can require additional binary data ("blobs") for their operation.
Those are shipped with this project for lack of an established place in the device's ROM,
and are only included in build outputs when that particular hardware acceleration is enabled.
At the time of writing, this affects the `embedded-cal-nrf54l15` crate.
See the individual crates' and/or files' license annotations for details.

## Contributors

The project is driven
by [Inria-AIO](https://aio.inria.fr/),
[Cryspen](https://cryspen.com/)
and [Christian Amsüss (@chrysn)](https://christian.amsuess.com/).

See [our contribution guidance](./policies/contributing.md) to contribute;
in short: we welcome additional contributors!

<!-- There is no requirement that we state this, but it is correct (because copied from the NGI page), and I wouldn't know which parts to leave out. -->
This project was funded through the [NGI0 Commons Fund](https://nlnet.nl/commonsfund), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) programme, under the aegis of [DG Communications Networks, Content and Technology](https://commission.europa.eu/about-european-commission/departments-and-executive-agencies/communications-networks-content-and-technology_en) under grant agreement No [101135429](https://cordis.europa.eu/project/id/101135429). Additional funding is made available by the [Swiss State Secretariat for Education, Research and Innovation](https://www.sbfi.admin.ch/sbfi/en/home.html) (SERI).
It is listed there as <https://nlnet.nl/project/embedded-cal/>.
