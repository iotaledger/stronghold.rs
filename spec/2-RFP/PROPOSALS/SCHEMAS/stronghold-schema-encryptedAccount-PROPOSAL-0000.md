# Encrypted Account
```json
{
    "info": {
        "name": "Account",
        "description": "Account schema"
    },
    "properties": {
        "id": {
            "type": string,
            "description": "SHA256 of the first address (m/44'/0'/0'/0/0)",
            "access": "public"
        },
        "external": {
            "type": boolean,
            "description": "true if the account was imported or false if it was created in stronghold",
            "access": "public"
        }
        "created": {
            "type": number,
            "description": "When the account was stored to stronghold (in unix time)",
            "access": "public"
        },
        "lastDecryption": {
            "type": number,
            "description": "Last decryption time (in unix time)",
            "access": "public"
        },
        "decryptionCounter": {
            "type": number,
            "description": "How many times this account was decrypted internally",
            "access": "public"
        },
        "exportCounter": {
            "type": number,
            "description": "How many times this account was exported",
            "access": "public"
        },
        "bip39Mnemonic_encrypted": {
            "type": string,
            "description": "Encrypted BIP39 Mnemonic"
            "access": "private"
        },
        "bip39Passphrase_encrypted": {
            "type": string,
            "description": "Encrypted BIP39 Passphrase"
            "access": "private"
        },
        "decryptionPassword_hashed": {
            "type": string,
            "description": "Hashed decryption password",
            "_comment": "To discuss",
            "access": "private"
        }
    }
}
```
