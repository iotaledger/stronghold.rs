![banner](./documentation/static/img/Banner/banner_stronghold.png)

<!-- PROJECT SHIELDS -->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![Apache 2.0 license][license-shield]][license-url]
[![Discord][discord-shield]][discord-url]
[![StackExchange][stackexchange-shield]][stackexchange-url]
<!-- Add additional Badges. Some examples >
![Format Badge](https://github.com/iotaledger/stronghold.rs/workflows/Format/badge.svg "Format Badge")
![Audit Badge](https://github.com/iotaledger/stronghold.rs/workflows/Audit/badge.svg "Audit Badge")
![Clippy Badge](https://github.com/iotaledger/stronghold.rs/workflows/Clippy/badge.svg "Clippy Badge")
![BuildBadge](https://github.com/iotaledger/stronghold.rs/workflows/Build/badge.svg "Build Badge")
![Test Badge](https://github.com/iotaledger/stronghold.rs/workflows/Test/badge.svg "Test Badge")
![Coverage Badge](https://coveralls.io/repos/github/iotaledger/stronghold.rs/badge.svg "Coverage Badge")


<!-- PROJECT LOGO -->
<br />
<div align="center">
    <a href="https://github.com/iotaledger/stronghold.rs">
        <img src="https://raw.githubusercontent.com/iotaledger/stronghold.rs/dev/.meta/stronghold_beta.png" alt="Banner">
    </a>
    <h3 align="center">Stronghold</h3>
    <p align="center">
        A Rust library to build a secure software storage for sensitive data.
        <br />
        <a href="https://wiki.iota.org/stronghold.rs/welcome"><strong>Explore the docs »</strong></a>
        <br />
        <br />
        <a href="https://github.com/iotaledger/stronghold.rs/labels/bug">Report Bug</a>
        ·
        <a href="https://github.com/iotaledger/stronghold.rs/labels/request">Request Feature</a>
    </p>
</div>



<!-- TABLE OF CONTENTS -->
<!-- TODO 
Edit the ToC to your needs. If your project is part of the wiki, you should link directly to the Wiki where possible and remove unneeded sections to prevent duplicates 
-->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#building">Building</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

<span style="font-weight: 666;">IOTA Stronghold</span> is a secure software implementation with the sole purpose of isolating digital secrets from exposure to hackers and accidental leaks. It uses encrypted snapshots that can be easily backed up and securely shared between devices. It is written in stable rust and has strong guarantees of memory safety and process integrity. 


<p align="right">(<a href="#top">back to top</a>)</p>


<!-- TODO
This section should list any major frameworks/libraries used to bootstrap your project. Leave any add-ons/plugins for the acknowledgements section. Here are a few examples:
-->
### Built With

* [Rust](https://www.rust-lang.org/)

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- GETTING STARTED -->
## Getting Started

<!-- epic prose here -->

### Prerequisites

To build Stronghold, you need a recent version of [Rust](https://www.rust-lang.org) installed.

### Building

The library comes with [examples](client/examples) but has no executables on its own. You can use the following instructions to build the library:

1. Clone the repo:
   ```sh
   git clone https://github.com/iotaledger/stronghold.rs.git
   ```
2. Build the library
   ```sh
   cargo build --release
   ```

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->
## Usage

An easy way to get acquainted with Stronghold is by checking out the [examples section](clinet/examples).
Examples can be run from the command line interface. Stronghold comes with a simle CLI example, that
showcases all features in brief. To run the example change into the [client](client) directory, and run

```sh
cargo run --example cli
```

This should print the help of the example with all commands and options.


<p align="right">(<a href="#top">back to top</a>)</p>


<!-- ROADMAP -->
## Roadmap

#### Components
- [x] Engine
- [x] Client (with dual interfaces)
- [x] peer-to-peer communications
- [x] Secure runtime zone 
- [x] Integration with crypto.rs 
- [x] Integration with Firefly
- [x] Integration with Identity
 
### Documentation and Specification
- [x] User Handbooks
- [ ] Specification Documentation
- [ ] Tutorials

### Performance and Testing
- [x] Unit Tests
- [x] Lowlevel Library Fuzzing
- [x] Multiplatform benchmarks
- [x] Continuous Fuzzing
- [ ] Realworld tests

#### Applications
- [x] CLI binary
- [x] Dynamic high-performance store 
- [ ] C FFI bindings
- [ ] [Napi Bindings](https://napi.rs/)

### Hardware Integrations
- [ ] Hardware Abstraction Layer (HAL) API

See the [open issues](https://github.com/iotaledger/stronghold.rs/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#top">back to top</a>)</p>


## Security Audit(s)

Stronghold has been audited for security vulnerabilities. This process is intended to be regular as soon as new security relevant features will be shipped with a new version.

| Date       | Branch         | Commit #    | Document                                                                                                                 | By                                        |
|:-----------|:---------------|:------------|:-------------------------------------------------------------------------------------------------------------------------|:------------------------------------------|
| 04-05-2022 | `dev-refactor` | `#eb07c4a4` | [2022-05-04-IOTA-Stronghold-statement-of-work-performed-1](2022-05-04-IOTA-Stronghold-statement-of-work-performed-1.pdf) | [WITH Secure](https://www.withsecure.com) |


<!-- CONTRIBUTING -->
## Contributing

Contributions make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion to improve this, please create an RFC following the [Stronghold Enhancement Proposal(SEP)](SEP.md) process. Do not forget to give the project a star! Thanks again!

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- LICENSE -->
## License

Distributed under the Apache License. See [`LICENSE`](LICENSE) for more information.

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

Project Link: [https://github.com/iotaledger/stronghold.rs](https://github.com/iotaledger/stronghold.rs)

<p align="right">(<a href="#top">back to top</a>)</p>


<p align="right">(<a href="#top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/iotaledger/stronghold.rs.svg?style=for-the-badge
[contributors-url]: https://github.com/iotaledger/stronghold.rs/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/iotaledger/stronghold.rs.svg?style=for-the-badge
[forks-url]: https://github.com/iotaledger/stronghold.rs/network/members
[stars-shield]: https://img.shields.io/github/stars/iotaledger/stronghold.rs.svg?style=for-the-badge
[stars-url]: https://github.com/iotaledger/stronghold.rs/stargazers
[issues-shield]: https://img.shields.io/github/issues/iotaledger/stronghold.rs.svg?style=for-the-badge
[issues-url]: https://github.com/iotaledger/stronghold.rs/issues
[license-shield]: https://img.shields.io/github/license/iotaledger/stronghold.rs.svg?style=for-the-badge
[license-url]: https://github.com/iotaledger/stronghold.rs/blob/dev/LICENSE
[discord-shield]: https://img.shields.io/badge/Discord-9cf.svg?style=for-the-badge&logo=discord
[discord-url]: https://discord.iota.org
[stackexchange-shield]: https://img.shields.io/badge/StackExchange-9cf.svg?style=for-the-badge&logo=stackexchange
[stackexchange-url]: https://iota.stackexchange.com
