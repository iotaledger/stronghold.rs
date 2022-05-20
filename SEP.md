# Stronghold Enhancement Proposal

The scope of this document describes a process to enhance and extend the functionality of the IOTA Stronghold software library. This process is influenced by the rust RFC process. 


## Process

1. Look out for Issues
    - The very first step is to look out for issues, API enhancements, feature enhancements, and feature proposals
2. Is the Enhancement Propopsal really necessary?
    - Does the Enhancement bring in any new features, or could this be a bugfix?
3. Copy the template from below and fill in the necessary parts
    - Put in a convincing motivation, a concise guide, and implementation level explanation; if both parts are submitted poorly, this would indicate a lack of understanding
4. Paste your proposal under [Discussions](https://github.com/iotaledger/stronghold.rs/discussion) and tag the maintainer of the repository. 
    - Receive feedback and prepare to incorporate changes 
5. Reach consensus from the community
6. Get your RFC accepted!
    - If the feedback has been incorporated, and all the necessary changes to the RFC brought the document to finality, the feature will be accepted for implementation. 


## License

All software provided by the Stronghold team falls under the Apache License, version 2.0. Please mark all parts of the software with a respective license identifier.

---

# Template 

## Outline

Write one paragraph explanation of the feature.

## Motivation

Describe the motivation behind the proposal. How does this proposal benefit Stronghold? Name a few examples.

## Reference-Level Explanation

This is the technical part of the RFC. Please be precise and explain in sufficient detail:

- How the feature is going to be implemented
- the interaction with other modules / features
- Edges cases are specifically highlighted

## Drawbacks

Bring into discussion why the proposed feature might not be a good idea. 

## Rationale and alternatives

- Show and explain why this is the best in the space of possible designs
- What are possible other designs and what is the rationale for not choosing them?
- How would Stronghold be affected, if this feature would not be accepted?

## Prior art

Discuss prior art, both the good and the bad, in relation to this proposal. 
A few examples could be:

- For memory safety: Check recent developments in cpu hardware. Try to balance cutting edge technologies with widely adopted techniques. examples could be Intel TXT, Arm TrustZone, RISC-V MultiZone

This section shall encourage you to think about lessons learned from other libraries and employed security techniques, provide your readers with a fuller picture of your proposal. 

Sometimes there is no prior art, that is fine. 

## Unresolved Questions

Use this section to discuss unresolved questions in your proposal and how you would resolve them. 

## Future possibilities

Use this section to elaborate on future work. Think about how this feature can be progressed. This section is intented to be less strict and can be used to place first ideas.

If you cannot think of any future ideas, just state it here. 