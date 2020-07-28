# Requirements Specification
[requirements]: #requirements

## Frontmatter
[frontmatter]: #frontmatter
```yaml
title: Project
stub: project
document: Requirements Specification
version: 0000
maintainer: Firstname Lastname <email@address.tld>
contributors: [Firstname Lastname <email@address.tld>]
sponsors: [Firstname Lastname <email@address.tld>]
licenses: ["License X", "License Y"]
updated: YYYY-MMM-DD
```

<!--
A Requirements Specification informs stakeholders and external parties about the code
and infrastructure; "what it does and why it does it".

The language in which this document is framed shall be the language of the intended
user of the product (NOT the user of the spec to design the product, but the
business language of the end user). This is important in that in some cases, that
end user is themselves a developer, so some technical language is expected but NO
language committing the implementer to one or another design with which to meet
these requirements.

Guidelines for Requirements:
----------------------------
- Requirements shall be formal
- Requirements shall be stated in natural language
- Requirements shall not include or presume any details of any implementation
- Requirements shall be implementable
- Requirements shall be testable
- Requirements shall be discrete (defining a single, atomic thing that the desired application is to do)
- Requirements shall be uniquely identified
- Requirements shall be subject to formal change control
-->

## Summary
[summary]: #summary
<!--
Short summary of this document.
-->


## Conceptual Model
[conceptual-model]: #conceptual-model
<!--
The conceptual model seeks to define at a high level how the product works.
-->

## Structural Model
[structural-model]: #structural-model
<!--
The structural model shows how the parts of the product fit together and exist in the larger ecosystem.
-->

## Behavioral Model
[behavioral-model]: #behavioral-model
<!--
The behavioral model explains how the system behaves at runtime.
-->

## Components
[components]: #components
<!--
Please describe the logical components of the system.  the data and what things mean.
It models database schemas, data structure, etc. at the logical level,
and physical database schemas and message schemas at the physical level.
-->

## Functional Requirements
[functionalrequirements]: #functionalrequirements
<!--
This is the section where functional requirements must be described in Outline form.
-->

## Non-functional Requirements
[nonfunctionalrequirements]: #nonfunctionalrequirements
<!--
- Performance requirements (speeds etc.)
- Capacity or Volume requirements (how many X can be handled)
- Security requirements
- resistance to misuse requirements
-  etc.
-->

## Sequence Diagrams
[sequences]: #sequences

<!--
Where applicable, sequence diagrams should be used to explain the complexity of the business
logic that the solution seeks to resolve. They should be images and stored in this
-->

## Job story examples
[jobstories]: #jobstories

<!--
Where applicable, write from the perspective of the person who will be using
the software, for example using the "Job story" format:

When ＿＿＿ , I want to ＿＿＿, so I can ＿＿＿.
-->

## Important Testing Verifications
[testing]: #testing

<!--
In many cases, spec-compliant implementations will do well to have a list of
important tests that should be run (unit, integration, e2e, smoke, etc.) This is
where such tests should be clearly explained and required - if necessary.
-->
