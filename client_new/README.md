# Stronghold Client Interface 

The client gives access to all Stronghold features and holds all state like secrets or insecure custom data. The interface is type based and separates between local Stronghold operations and remote Stronghold operations. 

## Accessing the Client

- Load Clients
- Create Clients
- Writing Secrets
- Reading / Writing from/into Store
- Executing Procedures

## Persisting State via Snapshots

- Writing Client State into Snapshots

## Working with Remote Strongholds

- place a reference to the examples here


## Procedures

### **Requests**: 
- `SLIP10Generate`: Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in the `Location`. 
- `SLIP10Derive`: Derive a Slip10 child key from a seed or parent key. Store the output in a specified `Location` and return the corresponding `ChainCode`. 
- `BIP39Recover`: Use a BIP39 mnemonic sentence (optionally protected by a passphrase) to create or recover a BIP39 seed and store it in the output `Location`.
- `BIP39Generate`: Generate a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a passphrase) and store them in the output `Location`.
- `BIP39MnemonicSentence`: Read a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a passphrase) and store them in the output `Location`.
- `Ed25519PublicKey`: Derive an Ed25519 public key from the corresponding private key stored at the specified `Location`.
- `Ed25519Sign`: Use the specified Ed25519 compatible key to sign the given message. Compatible keys are any record that contain the desired key material in the first 32 bytes, in particular SLIP10 keys are compatible.

### **Responses**:
- `SLIP10Generate`: Returns a `StatusMessage` indicating the result of the request. 
- `SLIP10Derive`: Returns a `ResultMessage` with the `ChainCode` inside of it. 
- `BIP39Recover`: Returns a `StatusMessage` indicating the result of the request. .
- `BIP39Generate`: Returns a `StatusMessage` indicating the result of the request.
- `BIP39MnemonicSentence`: Returns the mnemonic sentence for the corresponding seed.
- `Ed25519PublicKey`: Returns an Ed25519 public key inside of a `ResultMessage`.
- `Ed25519Sign`: Returns an Ed25519 signature inside of a `ResultMessage`.