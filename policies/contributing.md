<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
-->
# Contributing to embedded-cal

embedded-cal is an Free Software project developed publicly by several people and organizations.
We welcome contributions from outside the existing team, both technical and non-technical in nature;
we aim to provide a friendly and inclusive atmosphere in which the project can grow.

This document describes the project' preferences for how anyone (including maintainers) can contribute to the project.
It is not set in stone, and reflects current practice; feel free to suggest improvements here as with any other place in the repository.

## Ways to contribute

* Live discussion of how and where embedded-cal is used,
  and how it could be enhanced,
  is valuable input to the project
  -- and also useful to coordinate other contributions.
  Our main channel of communications is our [public matrix room](https://matrix.to/#/#embedded-cal:matrix.org).

* Problems, questions or suggestions for improvements
  can be tracked in [our issue tracker](https://github.com/lake-rs/embedded-cal/issues/).

* Making embedded-cal more useful in the ecosystem works not just by adding code, but by just using it: embedded-cal works better the more often it is integrated with other software.

  If you work with specific hardware, you can provide the embedded-cal traits for it;
  if you implement a user of cryptographic functions, you can require an implementation of embedded-cal traits.

  Neither necessarily needs to reside in this project,
  although we are open to additional hardware implementations to be added (see below).

  Please let us know of such applications in our [user survey](https://github.com/lake-rs/embedded-cal/issues/113).

* Contributions to the source code can range from enhancing readability of documentation, fixing bugs or adding proofs up to adding completely new features.

  Please submit code to the project through the [pull requests](https://github.com/lake-rs/embedded-cal/pulls).
  Pull requests can be opened early on, and marked as draft pull requests,
  even if they are far from checking any boxes (on prettiness, documentation or even working in the first place):
  Those help us avoid duplication of work.
  When you think that your PR is ready, mark it as "ready for review".

  When contributing changes, please be aware of

  - our [policy on LLM usage](./llm-usage.md), and

  - the Free Software [licenses](../README.md#license) that apply to the project.

    We use the [reuse](https://reuse.software/) tool to check whether copyright and licensing statements are present.
    The set of licenses should be the project-wide license unless there is a good reason to diverge
    (e.g. for limited-hardware implementations where the implementation can only be derived from non-free manufacturer data),
    which will only be accepted on a case-by-case basis.

    Please put the name by which you want to be credited in the SPDX header of the file you add or edit,
    unless you consider your contribution trivial and prefer not to be regarded as a copyright holder.

  - We do not apply specific coding standards beyond the best practices set by the tools we use
    ([Rust](https://doc.rust-lang.org/beta/style-guide/index.html), [git](https://git-scm.com/docs/SubmittingPatches#separate-commits), hax and [reuse](https://reuse.software/));
    as a rule of thumb, if any formality is required, the build checks will alert you to it.

* Reviewing of pull requests (or commenting on issues) is not limited to maintainers.

  The focus of review are applicability ("Is this project the right place for this functionality?"), correctness ("Does the code provide the desired funcionality?"), is maintainability ("What trouble can this cause in the future?").

  Reviews can be anything from "This issue is important for me because of X" or "I tried this PR, it solves my issue Y",
  up to detailed code reviews --
  both help enhance the project (e.g. by pointing attention to important issues or changes, or by advancing the code into a better state when maintainers around to reviewing, respectively).

## Review process

Issues and pull requests will be picked up by maintainers for tagging, questions and review.
If you think it was missed, feel free to ask for updates, or tag individual maintainers who you think might be particularly knowledgeable about the area.

Further processing of pull requests is described in [the maintenance document](./maintenance.md) for the maintainers' reference, or for curious readers.
