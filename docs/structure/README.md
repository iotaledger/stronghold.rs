# IOTA Stronghold Libraries

This is the location where bindings to other languages will be made available. The general strategy is that a binding will only expose the top level client interface.

This allows the binding to be simple and easy to audit. 

## Available binding languages

- [ ] C
- [ ] golang
- [ ] node.js (via NEON)

## Why no WASM?
While theoretically possible, we will not be providing full WASM bindings to stronghold, because of a number of very serious concerns regarding memory safety which basically destroys the security model that Stronghold seeks to offer.
