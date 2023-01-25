---
description: Get started with Stronghold. Prerequisites, how to build and use the library.   
image: /img/Banner/banner_stronghold.png
keywords:

- getting started
- open-source
- secure
- secrets
- Noise
- database
- Rust
- build
- run

---

# Getting Started

## Prerequisites

To build Stronghold, you need a recent version of [Rust](https://www.rust-lang.org) installed.

## Build the Library

The library comes with [examples](how_tos/cli/running_examples.mdx), but has no executables on its own. You can use the
following instructions to build the library:

1. Clone the repo:

```sh
git clone https://github.com/iotaledger/stronghold.rs.git
```

2. Build the library

```sh
cargo build --release
```

## Use The Library

You can get acquainted with Stronghold by checking out the [How Tos section](how_tos/cli/running_examples.mdx).

You can run the examples from the command line interface. Stronghold comes with a simple CLI example that briefly
showcases all its features. To run the example, change into the `client` directory, and run the following
command that will print the help of the example with all commands and options:

```sh
cargo run --example cli
```
