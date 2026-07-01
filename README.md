<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
-->

# `embedded-cal`: A Cryptographic Abstraction Layer (CAL) for embedded systems

*An embedded systems-friendly verified crypto provider.*

Embedded-cal develops a verified implementation of the cryptographic provider in Rust which is compatible with popular embedded platforms. This cryptographic provider will be 1) fast on popular embedded platforms; 2) resistant to certain classes of side-channel attacks; 3) usable without the Rust standard library. The module will lever the available hardware acceleration support of popular microcontroller units for embedded systems and fill in the gaps in hardware support through software implementations. The module will be formally verified for secret independence using the hax framework, a verification tool for high assurance code.

## Implementation roadmap

The coarse components of this project as planned are:

* Rust trait(s) that make a collection of cryptographic algorithms accessible.
* Implementations of that trait for different hardware accelations in embedded devices.
* Formally verified software implementations that are usable when no hardware acceleration is present.

Typical implementers of the traits
will be MCU- or -family specific back-ends that can be provided
by the device's HAL crate, or made available through an embedded operating system
such as [Ariel OS](https://ariel-os.org).

Typical users of the traits
will be network and security protocol implementations
such as
[Lakers](https://github.com/lake-rs/lakers/),
[libOSCORE](https://gitlab.com/oscore/liboscore)
or implementations of [SUIT](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/).

The project is currently being launched,
and expected to become usable before the end of 2025.

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

### Embedded-cal Libcrux
The `embedded-cal-libcrux` crate is currently licensed under the [GNU AFFERO GENERAL PUBLIC LICENSE Version 3](LICENSES/AGPL-3.0-only.txt), as its dependent [libcrux-iot](https://github.com/celabshq/libcrux-iot) is licensed under `AGPL-3.0-only`.

## Contributors

The project is driven
by [Inria-AIO](https://aio.inria.fr/),
[Cryspen](https://cryspen.com/)
and [Christian Amsüss (@chrysn)](https://christian.amsuess.com/).

We welcome additional contributors;
at the current stage, that can mainly happen in the interface designing, scope and requirements discover
happening [in the issue tracker](https://github.com/lake-rs/embedded-cal/issues).

<!-- There is no requirement that we state this, but it is correct (because copied from the NGI page), and I wouldn't know which parts to leave out. -->
This project was funded through the [NGI0 Commons Fund](https://nlnet.nl/commonsfund), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) programme, under the aegis of [DG Communications Networks, Content and Technology](https://commission.europa.eu/about-european-commission/departments-and-executive-agencies/communications-networks-content-and-technology_en) under grant agreement No [101135429](https://cordis.europa.eu/project/id/101135429). Additional funding is made available by the [Swiss State Secretariat for Education, Research and Innovation](https://www.sbfi.admin.ch/sbfi/en/home.html) (SERI).
It is listed there as <https://nlnet.nl/project/embedded-cal/>.
