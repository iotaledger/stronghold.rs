# Documentation

The documentation is built using [Docusaurus 2](https://docusaurus.io/). The deployment is done through a centralized build from [IOTA WIKI](https://github.com/iota-community/iota-wiki). To run a local instance the [IOTA WIKI CLI](https://github.com/iota-community/iota-wiki-cli) is used.

## Prerequisites

- [Node.js v14.14+](https://nodejs.org/en/)
- [yarn](https://yarnpkg.com/getting-started/install)

## Installation

```console
npm i
npm run setup
```

This command checks out a local copy of the wiki and creates links to the content.

## Local Development

```console
npm start
```

This command starts a local development server and opens up a browser window. Most changes are reflected live without having to restart the server.

## Tear Down

```console
npm run clean
```

This command deletes the local wiki and local links.


## Including .md file

```console
{@import <file path>}
```

Example:

```console
{@import ../../../../bindings/wasm/docs/api-reference.md}
```