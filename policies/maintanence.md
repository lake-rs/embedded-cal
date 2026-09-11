<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
-->
# Maintenance policy

This document describes how the maintainers operate.
It reflects current practice, and may change over time.

## Maintainer team

The maintainers of the project are those with write access to the repository.

A subset of the maintainers is listed as owners of our crates at [crates.io](https://crates.io/crates/embedded-cal).
The number of maintainers there is a trade-off between harm that can come from individual compromised developer systems
and being capable of acting even when individual maintainers are currently unavailable.

## Review and merging

Maintainers can merge changes that passed a maintainer's review.

In general, we require that any change be checked by two people, thereof one maintainer
(typically the author and a reviewer).
For trivial changes, we allow merging own pull requests.

## Project-wide decisions

Changes beyond regular development (e.g. around policies, architectural changes or changes the maintainer team)
are taken by rough consensus of the maintainer team.

## Releasing

Releases are made by opening a pull request that increments the version:
Rather than merging directly after review,
the PR's latest state before merging is uploaded by the author using [cargo-release](https://crates.io/crates/cargo-release),
which also creates a signed tag.
The PR is merged after that.

We adhere to semantic versioning.
Where practical, we introduce changes through addition of a new and deprecation of an old feature
(which can happen as a non-breaking change).
This way, users who upgrade to the latest version *before* a breaking change
and address all warnings
can update to the next breaking version with minimal effort.
