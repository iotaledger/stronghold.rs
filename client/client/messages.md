"a procedure produce a result" vs "a request returns a repsonse"

### Commands: (Procedures)
  - Digest/KDF
  - Sign verify (including multiple signers/verifiers)
  - Derive pubkey
  - Generate private key
  - Encrypt decrypt (note that here we might want to restrict/configure what data are allowed to exist outside of the vault)
    * this also functions as a database's write and read
  - Purge (with optional ttl (0 means request immediate garbage colllect)
  - RNG (does this put unnecessary exposure on the cryptographic source in use?)
  - HD key derivation (slip10 bip32 whatever)
 
### Payloads: (Intents?)
  - key material
  - serializable data
  - signatures

### Expected Response:
  - status code
  - transformation

### Auxiliary commands: (Procedures)
  - relay message to other stronghold via peer ID
  - current time?
  - capability negotiation:
    * security level
    * topology
    * available algorithms
    * software version
    * system metadata
    * peers (with their pubkeys (verifiable identity))
    * whois
