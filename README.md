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
