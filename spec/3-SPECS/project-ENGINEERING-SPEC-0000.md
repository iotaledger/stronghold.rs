# Engineering Specification
[engineering-spec]: #engineering-spec

## Frontmatter
[frontmatter]: #frontmatter

```yaml
title: Project
stub: project
document: Engineering Specification
version: 0000
maintainer: Firstname Lastname <email@address.tld>
contributors: [Firstname Lastname <email@address.tld>]
sponsors: [Firstname Lastname <email@address.tld>]
licenses: ["License X", "License Y"]
updated: YYYY-MMM-DD
```

<!--
Engineering Specifications inform developers about the exact shape of
the way the piece of software was built, using paradigms relevant to the
programming language that this project has been built with. The document
seeks to describe in exacting detail "how it works". It describes a
specific implementation of a logical design.

In some cases there may not be a separate logical specification, so the
Implementation Specification documents the design of a reference
implementation that satisfies the requirements set out in the
Behavioral and Structural Requirements Specifications.
-->

## Summary
[summary]: #summary
<!--
Short summary of this document.
-->

## Logical System Design
[system-design]: #system-design
<!--
Please describe all of the current components of the system from a logical
perspective.
-->

## Programming Language
[language]: #language
<!--
Please describe the language, minimal version and any other details necessary.
-->

## Environment
[environment]: #environment
<!--
Please describe the environment and any other details necessary.
-->

## Schema
[schema]: #schema
<!--
If appropriate, please add the schema here.
-->

## Functional API
[api]: #api
<!--
Please use the structural needs of the language used. This may be entirely
generated from code / code comments but must always be kept up to date as
the project grows.

Requirements for functions:
- function name
- parameters with:
  - handle
  - description
  - explicit type / length
  - example
- returns
- errors
-->
