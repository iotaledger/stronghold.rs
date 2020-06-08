# The 7PEC Lifecycle

7PEC is a formalized approach that seeks to follow the needs of software developement and business development, in order to enhance community involvement and pave the way for potential standardisation.

It is a combination of logbook, documentation and specification system that accompanies the product throughout its entire lifecycle. It has one purpose:

> **Accurately Describe the Current State of the Codebase**

It is very useful for guaranteeing engineering best-practices, maintaining transparency into the methodology and easing the often complicated documentation process.

![drawing](/template/.images/7P-Lifecycle.drawio.svg)

## File Naming Conventions
Files from this template should be renamed, where `project` is replaced with the name of the product. I.e. in the Bee project, there would be:
- `/specifications/1-SCOPE/bee-SCOPE-0000.md`
- `/specifications/3-SPECS/bee-ENGINEERING-SPEC-0000.md`
- etc.

## File Versioning Conventions
Instead of always replacing the spec documents with updated versions, major changes (i.e. not spelling, formatting or grammar) should always bump the zero-padded number at the end of the filename.

The only exception to this is the RFC process, which follows the standard of having the padded number at the beginning, but this is because the RFC process follows the systemic approach of using sequential RFCs.

## Integration into existing projects
Projects that have already started may have finished their prototyping phase entirely and already be in beta or stable. If this is the case, the RFP process is entirely skipped - but the SCOPE document still needs to be written and approved by the stakeholders. The SPECS and BOM need to be written and maintained, and the RFC process is the only way to get major changes into the project. If an RFC is accepted, that change MUST go through the prototyping phase with RFP and PTR.

# Lifecycle in the evolution of specifications
From the perspective of engineering, it is important to evolve a specification throughout the scope of work, offer an "entry point" for stakeholders to participate. Reviewing the state of the work is an activity that should be possible for anyone without guidance. Finally, the documentation of the product depends on the vigilance of the work done here.

Engineering is an iterative process that moves from raw ideas to stable implementations. As projects evolve, specifications evolve, become deprecated and eventually retired. This means that first and foremost, specifications need to be easy to write, modify and publish. There must be a way to discover the current version of any specification and it must be from the perspective of the humans that will be interacting with it.

### Proposal / Ideation
A proposal is a statement of intent that presents the scope of a product from the point of view of the business and the user. This phase is intended to define `what` a project is about.

Common work in this phase would be to get the stakeholders to agree upon the contents of the Scope Document.

It is possible that the team decides to Prune the Proposal (or entire project) in this phase. (Fail-early)

### Prototype / Prealpha
The prototype phase could be aligned closely with "pre-alpha" software in the context of semantic versioning.

As a reminder, "pre-alpha" software is software that generally speaking approaches the ideas of the proposal, but makes no guarantees to fitness or completeness. It is very likely to be buggy and will probably have its interfaces and shape changed one or more times as it matures to alpha state. It is not appropriate for wide dissemination and could be considered "research grade".

This phase seeks to identify the ideal RFI (if there are multiple) and "solidifies" the project scope, technology applied and general architectural patterns.

The first part of the work in this phase is to write and maintain Requests for Proposals (RFP), which serve to log the needs of the SCOPE document from a technical perspective. Then, individuals or teams work on Proposals to Requests (PTR), which concretely address the needs of the RFPs.

To receive the `@prealpha` grading, all of the requirements explained in the RFP must be satisfactorily resolved with PTRs.

It is possible that the team decides to Prune the Prototype (or entire project) in this phase. (Fail-early)

### Proofing / Alpha
Proofing of the product involves building out the

As a reminder, "alpha"-quality software is software that generally speaking works, is likely to be buggy and will quite likely have its interfaces and shape changed one or more times as it matures to Beta state. It is not appropriate for wide dissemination.


In this stage it is imperative that continuous integration systems are implemented, that distributables are validated and that the Engineering Schema matches the specification.

It is imperative in public projects that the community is brought in at this stage, if they have not yet been involved in earlier work. Especially in the context of "intuitive and friendly" libraries, feedback at this stage will help the "social" aspect of the software release.

In this stage, where all things are "mostly finished", an RFC process is absolutely essential for affecting changes in a fashion that enables stakeholder involvement. Similar to the RFI and RFP workflows, an RFC exists as a last chance to modify integral parts of the product before it receives the `@alpha` grading.

This stage is also the first point in time at which it makes sense for the Requirements Specs to be initiated.

### Preproduction / Beta
Proofing of a product is the stage in development where the engineering team focuses on testing, fuzzing, benchmarking and basically proving that the product is secure and of the highest quality. It is the last chance to change the interface or fix underlying problems.

Preparing for the Production phase brings all the stakeholders together and is a ceremony that unites devops, engineering, management and external parties. It should guarantee that documentation is available, well-formed and accurate.

The schema must be finalized, requirements validated...

### Production / Stable

When the Product is `@stable` it means that there is a very strict contract between the contributors to the product and the consumers of the product.


### dePrecation
The deprecation stage of a Product means that it (or one of its constituent parts) will be deprecated at a point in the future.


### Posterity
We don't want to throw away any work, ever. When Products are deprecated, we maintain their histories.

## Component Parts

### Request for Information (RFI)
A request for information is the kickoff for a project, which serves as a basis for discussion. It should be product-driven and user-oriented.

### Request for Proposals (RFP)
A request for proposals is an aspect of the prototyping phase, which seeks to detail a system component and investigate ways to make it work.

### RFC
A request for comments is a proposed change to a system that has stabilised, such as when a project is in beta - or when a (potential) contributor feels that a change is important.

### Engineering Specs
The detailing of Engineering Specs can vary from project to project (and underlying programming language), but generally can be expected to cover the following concerns:

- Introduction
- Implementation Details
  - Naming Convension
  - Programming language(s)
- Constituent parts overview
  - Schemas
  - API / Endpoints
- Flow Diagrams
- Individual parts
  - Name
  - Parameters with name, description, type, example
  - Errors thrown
  - Return values
  - Side Effects
  - Example (in primary language)
- Build tools
- Testing
- Auditing

This is a real "living document" and should reflect the current state of the software at all times. It is a contract between developers of the project and consumers of the project. Where possible, automation SHOULD be used.

### Requirements Specs
<!-- NOTE: This section still requires some more attention -->
A Requirements Spec is a business-layer document that seeks to use as plain an English as possible for the scope of work in order to completely describe the product.

It can be worked upon throughout the lifecycle of a product, however there are a few concerns:

1. Starting too soon may be a waste of time, because during the Proposal and Prototype phases many things can change - and indeed the entire project might get shelved.
2. It is "documentary" and not "executive". This means that it MUST NOT change the shape, meaning or approach of the software.

Generally speaking, there are three major components of a Requirements Specification:

#### 1. Conceptual Model
The conceptual model seeks to define at a high level how the product works.

#### 2. Structural Model
The structural model shows how the parts of the product fit together and exist in the larger ecosystem.

#### 3. Behavioral Model
The behavioral model explains how the system behaves at runtime.
