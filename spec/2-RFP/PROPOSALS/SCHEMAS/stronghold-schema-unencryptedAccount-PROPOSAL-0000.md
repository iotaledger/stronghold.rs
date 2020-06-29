# Uncrypted Account
```json
{
    "info": {
        "name": "Account",
        "description": "Account schema"
    },
    "properties": {
        "id": {
            "type": "string",
            "description": "SHA256 of the first address (m/44'/0'/0'/0/0)",
        },
        "external": {
            "type": "boolean",
            "description": "true if the account was imported or false if it was created in stronghold",
        }
        "created": {
            "type": "number",
            "description": "When the account was stored to stronghold (in unix time)",
        },
        "lastDecryption": {
            "type": "number",
            "description": "Last decryption time (in unix time)",
        },
        "decryptionCounter": {
            "type": "number",
            "description": "How many times this account was decrypted internally",
        },
        "exportCounter": {
            "type": "number",
            "description": "How many times this account was exported",
        },
        "bip39Mnemonic": {
            "type": "string",
            "description": "BIP39 Mnemonic"
        },
        "bip39Passphrase": {
            "type": "string",
            "description": "BIP39 Passphrase"
        }
    }
}
```
