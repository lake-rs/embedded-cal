<!--
SPDX-License-Identifier: MIT OR Apache-2.0
SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
-->

# LLM Usage Policy

This is a policy for how LLMs are used in `lake-rs/embedded-cal`.

## Overview

Using LLMs while working on `lake-rs/embedded-cal` is conditionally allowed, when done with care.
LLMs are not a substitute for thought,
and we do not allow them to be used in ways that risk losing our shared social and technical understanding of the project,
nor in ways that hurt our goals of creating a strong community.

We are aware that many clauses in this policy are unenforceable.
Our goal is _not_ to catch every violation.
Instead, our goal is to remove plausible deniability: to force a choice between following the policy and intentionally violating it.
See [Money laundering and AML compliance](https://www.bitsaboutmoney.com/archive/money-laundering-and-aml-compliance/) for more background about the motivation.

The policy's guidelines are roughly as follows:

> It's fine to use LLMs to answer questions, analyze, distill, refine, check, suggest, review. But not to **create**.

> LLMs work best when used as a tool to write _better_, not _faster_.

> We carve out a space for "experimentation" to inform future revisions to this policy.

## Rules

### Legend

- ✅ Allowed.
- ❌ Banned.
- ⚠️ Allowed with caveats. Must disclose that an LLM was used.
- ℹ️ Adds additional detail to the policy. These bullets are normative.

### Summary

- ✅ Allowed: Private use.
- ❌ Banned: LLM-created comments, docs. Replacing human judgement with LLM judgement. Requiring people to use an LLM to contribute.
- ⚠️ Conditionally allowed: Trivial changes, machine translation, LLM reviews and review bots, LLM-created code _under the experiment rules_.

### Non-exhaustive policy

This policy does not aim to be exhaustive.
If you have a use of LLMs in mind that isn't on this list, talk to people about it, and judge it in the spirit of this overview:

- Using an LLM for your own personal use is likely allowed ✅
- Showing LLM output to another human without solicitation is likely banned ❌
- Making a decision that affects others based on LLM output requires disclosure ⚠️

### ✅ Allowed

The following are allowed.

- Any use of an LLM where you are the only one who sees the output. For example:
  - Asking an LLM questions about an existing codebase.
  - Asking an LLM to summarize comments on an issue or PR.
    - ℹ️ This does not allow reposting the summary publicly. This only includes your own personal use.
  - Asking an LLM to privately review your code or prose.
    - ℹ️ This does not apply to public comments by the LLM. See "review bots" under ⚠️ below.
  - Writing dev-tools for your own personal use using an LLM.
  - Using an LLM to generate possible solutions to an issue, learning from them, and then writing something from scratch in your own style.
- Using an LLM in the creation of clearly experimental code changes that are not meant to be reviewed but must live as PRs on `lake-rs/embedded-cal`.
  - "Clearly experimental" includes markers such as `[PERF]` or `[EXPERIMENTAL]` titles.
  - We strongly recommend, but do not require, that experimental PRs disclose LLM usage.
    The goal here is to avoid other people picking up the draft work without knowing it's LLM-generated.
  - ℹ️ If a PR is no longer marked as clearly experimental, at that point disclosure is required.

### ❌ Banned

The following are banned.

- Comments that are originally created by an LLM posted from a personal user account.
  - ℹ️ This also applies to issue bodies and PR descriptions.
  - ℹ️ This also applies to voice/video content originally created or scripted by an LLM.
  - ℹ️ This does not apply if the LLM content is clearly quoted and marked; you can post that.
    However, the content of the comment must stand on its own even without the LLM content; it's not a substitute for your own words.
  - ℹ️ See also "machine-translation" in ⚠️ below.
- Documentation that is originally created by an LLM.
  - ℹ️ This includes non-trivial source comments, such as doc-comments, safety comments, or multiple paragraphs of non-doc-comments.
  - ℹ️ This does not include "trivial" changes (see ⚠️ below).
- Policies or processes that are written such that an LLM is required to execute them.
  - For example, you must not _only_ document where tests live with an `AGENTS.md`.
    Documentation must be authored for humans primarily, and LLM documentation may only summarize it, not add new detail.
- Treating an LLM review as a sufficient condition to merge or reject a change.
  LLM reviews, if enabled, **must** be advisory-only.
  - ℹ️ See "review bots" in ⚠️ below.
  - ℹ️ An LLM review does not substitute for self-review. Authors are expected to review their own code before posting and after each change.

### ⚠️ Allowed with caveats

These uses are allowed on a case-by-case basis, under the rules below.
If you are a new contributor, you should expect to be scrutinized more heavily than existing contributors,
since you haven't yet established trust with your reviewers.

All uses under "⚠️ Allowed with caveats" **must** disclose that an LLM was used.

- Using machine-translation (e.g. Google Translate) from your native language without posting your original message is allowed but discouraged.
  Doing so can introduce new miscommunications that weren't there originally, and prevents someone who speaks the language from providing a better translation.
  - ℹ️ Posting both your original message and the translated version is always ok, but you must still disclose that machine-translation was used.
- "Trivial" code or prose changes.
  - ℹ️ Changes are trivial if there is no other way to write them, or the other ways to write them are nearly identical. For example, the following are all trivial:
    - Typo fixes
    - Markdown links
    - Changing a word to a synonym
    - Type signatures for a trait implementation
  - ℹ️ Be cautious about PRs that consist solely of trivial changes.
- Using an LLM to discover bugs, as long as you personally verify the bug.
  - ℹ️ This also includes reviewers who use LLMs to discover flaws in unmerged code.
  - ℹ️ See also "Comments \[...\] posted from a personal user account" under ❌ above.
- Using an LLM as a "review bot" for PRs.
  - ℹ️ Review bots that post without being approved by a maintainer will be banned.
    This is a one-time approval; maintainers don't need to approve individual reviews.
  - ℹ️ Review bots **must** have a separate GitHub account that clearly marks them as an LLM.
    You **must not** post (or allow a tool to post) LLM reviews verbatim on your personal account unless clearly quoted with your own personal interpretation of the bot's analysis.
  - ℹ️ Review bot accounts must be blockable by individual users via the standard GitHub user-blocking mechanism. (Note that some GitHub "app" accounts post comments that look like users but cannot be blocked.)
  - ℹ️ LLM comments **must not** be blocking; reviewers must indicate which comments they want addressed.
    - In other words, reviewers must explicitly endorse an LLM comment before blocking a PR. They are responsible for their own analysis of the LLM's comment and cannot treat it as a CI failure.
  - ℹ️ This does not apply to private use of an LLM for reviews; see ✅ above.

## Experiment: LLM-created code changes intended for review

We leave space open to experiment with LLMs to inform future policies.
This experiment is meant to inform future non-experimental policy, not to serve as the perpetual LLM usage policy.

### Rules

Pre-arranged, non-critical, high-quality, well-tested, and well-reviewed code changes that are originally created by an LLM are allowed, **with disclosure**.

1. "Pre-arranged" means that a reviewer has communicated _ahead of time_ that they are willing to review an LLM-created PR.
   - ℹ️ New contributors cannot create a PR using an LLM unless they first talk with a reviewer.
     This must be the _same_ reviewer who will be assigned to the PR.
   - Authors are, of course, allowed to start work on a change before finding a reviewer.
     However, they must find a reviewer before opening a PR.
2. "Non-critical" means that it is extremely unlikely for the PR to cause a regression.
   - ℹ️ Examples:
     - Trivial changes to comments and tests are probably ok.
     - Changes that have a strong impact, like the traits, hardware implementation, or the plumbing system are probably not ok.
3. "High-quality" means that it is held to at least the same standard as other code changes.
   Everyone reads code, not just the author and reviewer;
   we are not interested in "vibe-coded" PRs that degrade the quality of the codebase.
4. "Well-tested" means that you have covered all edge-cases that either you or the reviewer can think of.
   - ℹ️ LLM-created PRs will be held to a higher standard than human-created PRs, because LLMs make it easier to write tests.
   - ℹ️ If there is no existing test suite for a section of code, you must either write a new test suite or close the PR.
     There are no exceptions for "writing the tests seems hard".
5. "Well-reviewed" means the author and reviewer both commit to fully understanding the code.
   - ℹ️ A review from a project member does not substitute for self-review.
     Authors are expected to review their own code before posting and after each change.

### Procedures

LLM-created PRs must be disclosured in the PR message.
