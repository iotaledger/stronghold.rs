---
description: Getting started with your project.
image: /img/logo/iota_logo.svg
keywords:
  - install
  - prerequisites
  - getting started
  - hello world
---

# Example Getting Started File

## Required Prior Knowledge

You should list any knowledge the user requires to properly understand your project, and it's source code and examples.
For example:

- [Java](https://www.java.com/).
- [JavaScript](https://www.w3schools.com/js/).
- [Node.js](https://nodejs.org/en/docs/guides/).
- [Python](https://www.python.org/about/gettingstarted/).
- [Rust](https://www.rust-lang.org/learn/get-started).
- [Wasm](https://webassembly.org/).

## Prerequisites

You should list any software and hardware requisites to run the project in this subsection, ideally with a link to the
official installation instructions. For example:

- [Npm](https://npmjs.com)
- [Rust](https://www.rust-lang.org/tools/install)
- [Docker](https://docs.docker.com/get-docker/)

## Install the Project

You should use this subsection to give the user concrete and concise instructions on how to install the project.
Ideally, these should be very short, and if an in depth explanation is required to install extensions or
non-essential software you should address it in the [How Tos](../how_tos/_README.mdx) or
[Tutorials](../tutorials/_README.mdx) folders.

### NPM Install Example

```bash
npm install @iota/client-wasm
```

### Yarn Install Example

```bash
yarn add @iota/client-wasm
```

## Use the Project

You should use this subsection to provide the users with the simplest possible example in which they can use the project
after installing it, as well as minimal explanations if required. Keep in mind that as in the
[Install the Project](#install-the-project) subsection, complex use cases should be addressed in the
[How Tos](../how_tos/_README.mdx) or [Tutorials](../tutorials/_README.mdx). For example:

### NodeJS Usage Example

```js
const iota = require("@iota/client-wasm/node");

async function main() {
  // Get the nodeinfo
  let iota_client = await iota.Client.withNode(
    "https://api.lb-0.h.chrysalis-devnet.iota.cafe/"
  );
  console.log("Nodeinfo: ", await iota_client.getInfo());
}
main();
```
