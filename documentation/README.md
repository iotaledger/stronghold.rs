# Documentation

The documentation is built using [Docusaurus 2](https://docusaurus.io/). The deployment is done through a centralized build from [IOTA WIKI](https://github.com/iota-community/iota-wiki). To run a local instance the [IOTA WIKI CLI](https://github.com/iota-community/iota-wiki-cli) is used.

## Prerequisites

- [Node.js v14.14+](https://nodejs.org/en/)
- [yarn](https://yarnpkg.com/getting-started/install)

## Installation

```console
yarn
```

This command installs all necessary dependencies.

## Local Development

```console
yarn start
```

This command starts a local, wiki themed development server and opens up a browser window. Most changes are reflected live without having to restart the server.

## Features And Tools

You can find guidance and an introduction to the needed tools and syntax on [our wiki](https://wiki.iota.org/participate/contribute-to-wiki/for_devs/developer_guide)


## Default Structure

IOTA projects usually house their Wiki documentation in the `documentation` folder within their repositories. This
template provides a structure to separate reader concerns, applying the [Diataxis framework](https://diataxis.fr/) with
some minor modifications.

You do not have to use all of these sections, so please feel free to delete any which do not suit your needs.

### Getting Started

The [Getting Started folder](documentation/getting_started/_README.md) should be the first section in your documentation. It should give the user a high-level overview of the project, required prior knowledge, prerequisites, and ideally a quick setup guide, or "hello world".

### How Tos

The [How Tos folder](documentation/how_tos/_README.md) should only address concrete examples, or [how-to guides](https://diataxis.fr/how-to-guides/), which are **goal-oriented**.

### Tutorials

The [Tutorials folder](documentation/tutorials/_README.md) should contain articles which guide the user step by step through a series of how-tos with the relevant explanations to achieve a project or real world use case. [Tutorials](https://diataxis.fr/tutorials/) are **learning-oriented**.

### Key Concepts

The [Key concepts folder](documentation/key_concepts/_README.md) revolves around [explanations](https://diataxis.fr/explanation/), and are therefore **understanding-oriented**.

### Reference

The [Reference folder](documentation/reference/_README.md) should describe the [technical information](https://diataxis.fr/reference/) of your project. It is **information-oriented**.

### Troubleshooting

The [Troubleshooting file](documentation/troubleshooting.md) should contain instructions or links to where users can post questions, or create issues if necessary.

## Contribute

The [Contribute file](documentation/contribute.md) should give the users directions and 