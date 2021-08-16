# Contribute to Stronghold

This document describes how to contribute to Stronghold.

We encourage everyone with knowledge of IOTA technology to contribute.

Thanks! :heart:

<details>
<summary>Do you have a question :question:</summary>
<br>

If you have a general or technical question, you can use one of the following resources instead of submitting an issue:

- [**Developer documentation:**](https://docs.iota.org/) For official information about developing with IOTA technology
- [**Discord:**](https://discord.iota.org/) For real-time chats with the developers and community members
- [**IOTA cafe:**](https://iota.cafe/) For technical discussions with the Research and Development Department at the IOTA Foundation
- [**StackExchange:**](https://iota.stackexchange.com/) For technical and troubleshooting questions
</details>

<br>

<details>
<summary>Ways to contribute :mag:</summary>
<br>

To contribute to Stronghold on GitHub, you can:

- Report a bug
- Suggest a new feature
- Build a new feature
- Join the Stronghold Initiative
</details>

<br>

<details>
<summary>Report a bug :bug:</summary>
<br>

This section guides you through reporting a bug. Following these guidelines helps maintainers and the community understand the bug, reproduce the behavior, and find related bugs.

### Before reporting a bug

Please check the following list:

- **Do not open a GitHub issue for [security vulnerabilities](.github/SECURITY.MD)**, instead, please contact us at [security@iota.org](mailto:security@iota.org).

- **Ensure the bug was not already reported** by searching on GitHub under [**Issues**](https://github.com/iotaledger/stronghold/issues). If the bug has already been reported **and the issue is still open**, add a comment to the existing issue instead of opening a new one.

**Note:** If you find a **Closed** issue that seems similar to what you're experiencing, open a new issue and include a link to the original issue in the body of your new one.

### Submitting A Bug Report

To report a bug, [open a new issue](https://github.com/iotaledger/stronghold/issues/new), and be sure to include as many details as possible, using the template.

**Note:** Minor changes such as fixing a typo can but do not need an open issue.

If you also want to fix the bug, submit a [pull request](#pull-requests) and reference the issue.
</details>

<br>

<details>
<summary>Suggest a new feature :bulb:</summary>
<br>

This section guides you through suggesting a new feature. Following these guidelines helps maintainers and the community collaborate to find the best possible way forward with your suggestion.

### Before suggesting a new feature

**Ensure the feature has not already been suggested** by searching on GitHub under [**Issues**](https://github.com/iotaledger/stronghold/issues).

### Suggesting a new feature

To suggest a new feature, talk to the IOTA community and IOTA Foundation members in the #stronghold-discussion channel on [Discord](https://discord.iota.org/).

Or, you can submit an official [Request for Comments (RFC)](https://github.com/iotaledger/stronghold-rfcs/).

</details>

<br>

<details>
<summary>Build a new feature :hammer:</summary>
<br>

This section guides you through building a new feature. Following these guidelines helps give your feature the best chance of being approved and merged.

### Before building a new feature

Make sure to discuss the feature in the #stronghold-discussion channel on [Discord](https://discord.iota.org/).

Otherwise, your feature may not be approved at all.

### Building a new feature

To build a new feature, check out a new branch based on the `master` branch, and be sure to document any public-facing APIs, using Rust code comments.
</details>

<br>

<details>
<summary>Join the Stronghold Initiative :deciduous_tree:</summary>
<br>

The [Stronghold Initiative](https://github.com/iota-community/stronghold) is a collaborative effort to improve the Stronghold developer experience by focussing on the following goals:

- Quality Assurance and Quality Control
- Documentation
- Benchmarks
- RFCs
- Node usability
- Improvements to modules and libraries

## How much time is involved

You can invest as much or as little time as you want into the initiative.

## What's in it for you

In return for your time, not only do you get to be a part of the future of IOTA technology, you will also be given a badge on Discord to show others that you're a valuable member of the IOTA community.

## How to join

If you're interested in joining, chat to us in the #experience channel on [Discord](https://discord.iota.org/).

</details>

<br>

<details>
<summary>Pull requests :mega:</summary>
<br>

This section guides you through submitting a pull request (PR). Following these guidelines helps give your PR the best chance of being approved and merged.

### Before submitting a pull request

Before submitting a pull request, please follow these steps to have your contribution considered by the maintainers:

- A pull request should have exactly one concern (for example one feature or one bug). If a PR addresses more than one concern, it should be split into two or more PRs.

- A pull request can be merged only if it references an open issue

    **Note:** You don't need to open an issue for minor changes such as typos, but you can if you want.

- All public interfaces should have descriptive documentation, including an
example that compiles and passes [documentation tests](https://doc.rust-lang.org/rustdoc/documentation-tests.html)

- All instances of `unsafe` should have a comment that explains why its use was unavoidable

- All code should be well tested, using unit tests and integration tests

- Code must compile and pass our [continuous integration tests](.github/workflows)

- To be compatible with the guidelines of the Eclipse foundation, all code must be licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0). This license must be referenced in every crate of the workspace (add [`./LICENSE`] to the crate's top level directory). For Rust crates, every `Cargo.toml` must contain the line `license = "Apache-2.0"`.

### Submitting a pull request

The following is a typical workflow for submitting a new pull request:

1. Fork this repository
2. Create a new branch based on your fork. For example, `git checkout -b fix/my-fix` or ` git checkout -b feat/my-feature`.
3. Run the `rustfmt` command to make sure your code is well formatted
4. Commit changes and push them to your fork
5. Target your pull request to be merged with `master`

If all [status checks](https://help.github.com/articles/about-status-checks/) pass, and the maintainer approves the PR, it will be merged.

**Note:** Reviewers may ask you to complete additional work, tests, or other changes before your pull request can be approved and merged.
</details>

<br>

<details>
<summary>Code of Conduct :clipboard:</summary>
<br>

This project and everyone participating in it is governed by the [IOTA Code of Conduct](.github/CODE_OF_CONDUCT.md).