# Proposal to Request (PTR)
[PTR]: #PTR

## Frontmatter
[frontmatter]: #frontmatter
```yaml
title: Project
stub: project
document: PTR
version: 0000
maintainer: Daniel Thompsopn-Yvetot <daniel.yvetot@iota.org>
contributors: [Marcelo <marcelo.bianchi@iota.org>]
sponsors: [Firstname Lastname <email@address.tld>]
licenses: ["Apache 2.0"]
updated: 2020-JUNE-29
```

# Wallet Fixture (Stronghold)
Fixture of stronghold implementation with wallet

```json
[
    {
        "info": {
            "method": "listAccounts",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description":"List accounts stored by stronghold"
        },
        "parameters": [
            {
                "label": "skip",
                "type": "number",
                "description": "Results to skip",
                "required": false,
                "default": 0,
                "regex": /^[0-9]{0,16}$/
            },
            {
                "label": "limit",
                "type": "number",
                "description": "Limit number of results",
                "required": false,
                "default": 100,
                "regex": /^[0-9]{0,16}$/
            }
        ],
        "response": {
            "success": {
                "label": "accounts",
                "description": "Subset of stored accounts",
                "type": "string array",
            },
            "errors": [
                {
                    "label": "Invalid skip",
                    "type": "throw"
                },
                {
                    "label": "Invalid limit",
                    "type": "throw"
                },
                {
                    "label": "Corrupted storage",
                    "type": "throw",
                    "description": "Storage is corrupted and cannot be read or decrypted"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "params": {
                    "endpoint": "listAccounts",
                    "skip": 2,
                    "limit": 1
                }
            },
            "response": {
                "type": "success",
                "response": "listAccounts",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": ["C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53"]
            }
        }]
    },
    {
        "info": {
            "method": "getAccount",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description":"Returns account data"
        },
        "parameters":[
            {
                "label": "accountID",
                "type": "string",
                "required": true,
                "regex": /^[0-9a-f]{64}$/
            }
        ],
        "response": {
            "success": {
                "label": "accounts",
                "description": "Subset of stored accounts",
                "type": "Array of ref#https://hackmd.io/@mrb/SyVWHxBp8",
            },
            "errors": [
                {
                    "label": "Invalid accountID",
                    "type": "throw"
                },
                {
                    "label": "Corrupted storage",
                    "type": "throw",
                    "description": "Storage is corrupted and cannot be read or decrypted"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "params": {
                    "endpoint": "getAccount",
                    "skip": 2,
                    "limit": 1
                }
            },
            "response": {
                "type": "success",
                "response": "getAccount",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": [
                    {
                        "id": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53",
                        "external": false,
                        "created": 1592477131000,
                        "lastDecryption": 1592478031000,
                        "decryptionCounter": 1,
                        "exportCounter": 0
                    }
                ]
            }
        }]
    },
    {
        "info": {
            "method": "createAccount",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description":"Create account"
        },
        "parameters":[
            {
                "label": "bip39Passphrase",
                "type": "string",
                "description": "BIP39 Passphrase",
                "required": false,
                "default": null
            },
            {
                "label": "encryptionPassword",
                "type": "string",
                "description": "Account will be encrypted and stored",
                "required": true
            }
        ],
        "response": {
            "success": {
                "label": "account",
                "description": "Stored account",
                "type": "ref#https://hackmd.io/@mrb/SyVWHxBp8",
            },
            "errors": [
                {
                    "label": "Invalid parameters",
                    "type": "throw"
                },
                {
                    "label": "Cannot storage",
                    "type": "throw",
                    "description": "Storage cannot be written/read"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "params": {
                    "endpoint": "createAccount",
                    "bip39Passphrase": "37xHi6k3",
                    "decryptionPassword": "Notds8QL"
                }
            },
            "response": {
                "type": "success",
                "response": "createAccount",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": [
                    {
                        "id": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53",
                        "external": false,
                        "created": 1592477131000,
                        "lastDecryption": 1592478031000,
                        "decryptionCounter": 1,
                        "exportCounter": 0
                    }
                ]
            }
        }]
    },
    {
        "info": {
            "method": "importAccount",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description":"Import account to stronghold"
        },
        "parameters":[
            {
                "label": "bip39Mnemonic",
                "type": "string",
                "description": "BIP39 Mnemonic",
                "required": true
            },
            {
                "label": "bip39Passphrase",
                "type": "string",
                "description": "",
                "required": false,
                "default": null
            },
            {
                "label": "encryptionPassword",
                "type": "string",
                "description": "Account will be encrypted with this password",
                "required": true
            }
        ],
        "response": {
            "success": {
                "label": "account",
                "description": "Stored account",
                "type": "ref#https://hackmd.io/@mrb/SyVWHxBp8",
            },
            "errors": [
                {
                    "label": "Invalid parameters",
                    "type": "throw"
                },
                {
                    "label": "Cannot storage",
                    "type": "throw",
                    "description": "Storage cannot be written or read"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "params": {
                    "endpoint": "importAccount",
                    "bip39Mnemonic": "merit aisle version evil large grab maze such expect harvest flash flight",
                    "bip39Passphrase": "AuKB66sF",
                    "decryptionPassword": "xCM7qjcj"
                }
            },
            "response": {
                "type": "success",
                "response": "importAccount",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": [
                    {
                        "id": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53",
                        "external": false,
                        "created": 1592477131000,
                        "lastDecryption": 1592478031000,
                        "decryptionCounter": 1,
                        "exportCounter": 0
                    }
                ]
            }
        }]
    },
    {
        "info": {
            "method": "removeAccount",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description":"Remove account from storage"
        },
        "parameters": [
            {
                "label": "accountID",
                "type": "string",
                "required": true,
                "regex": /^[0-9a-f]{64}$/
            }
        ],
        "response": {
            "success": {
                "label": "account",
                "description": "Removed account",
                "type": "ref#https://hackmd.io/@mrb/SyVWHxBp8",
            },
            "errors": [
                {
                    "label": "Inexistent account",
                    "type": "throw",
                    "description": "Specified account does not exists"
                },
                {
                    "label": "Invalid parameters",
                    "type": "throw"
                },
                {
                    "label": "Can't storage",
                    "type": "throw",
                    "description": "Storage cannot be read or written"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "params": {
                    "endpoint": "removeAccount",
                    "id": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53"
                }
            },
            "response": {
                "type": "success",
                "response": "removeAccount",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": [
                    {
                        "id": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53",
                        "external": false,
                        "created": 1592477131000,
                        "lastDecryption": 1592478031000,
                        "decryptionCounter": 1,
                        "exportCounter": 0
                    }
                ]
            }
        }]
    },
    {
        "info": {
            "method": "signTransaction",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description":"Returns given transaction signed"
        },
        "parameters": [
            {
                "label": "trytes",
                "type": "string",
                "description": "Tryte-encoded transaction to sign",
                "required": true,
                "regex": /^[9A-Z]{2673}$/
            },
            {
                "label":"accountID",
                "type":"string",
                "description": "Needed to identify which account seed use to derive.",
                "required":true,
                "regex": /^[0-9a-f]{64}$/
            },
            {
                "label": "decryptionPassword",
                "type": "string",
                "description": "Password for decrypt mnemonic",
                "required": true
            },
            {
                "label": "derivationPaths",
                "type": "string array",
                "description": "Used to get private keys",
                "required": true,
                "regex": /^[m]([\/][0-9]*[']*)*$/
                "_comment": "regex is for only 1 derivation path"
            }
        ],
        "response": {
            "success": {
                "label": "signingResult",
                "description": "tryte-encoded signed transaction",
                "type": "ref#https://hackmd.io/_l6cCVm_RzOT629N5mJqyQ",
                "_comment": "new transaction schema is unkown"
            },
            "errors": [
                {
                    "label": "Inexistent account",
                    "type": "throw"
                },
                {
                    "label": "Invalid decryptionPassword",
                    "type": "throw"
                },
                {
                    "label": "Invalid transaction",
                    "type": "throw",
                    "description": "Transaction is invalid"
                },
                {
                    "label": "Invalid derivationPaths",
                    "type": "throw",
                    "description": "derivationPaths is not well-format"
                },
                {
                    "label": "Bad signatures",
                    "type": "throw",
                    "description": "Derived private keys do not correspond"
                },
                {
                    "label": "Incomplete signed",
                    "type": "throw",
                    "description": "Transaction needs more signatures"
                },
                {
                    "label": "Incomplete signed",
                    "type": "throw",
                    "description": "Transaction needs more cosigners"
                },
                {
                    "label": "Cannot storage",
                    "type": "throw",
                    "description": "Storage cannot be read or written"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "params": {
                    "endpoint": "signTransaction",
                    "raw": "UAVAUAUAUAUAUAUAUAVAUATCXASCYASCYAPCWAXABBXATCQCUAUARCUCABCB9BRCTCXABBUAPC9BZAWAYAUAQCCBUAABABTCCBQCBBQCVATCABUA9BTCUAXAQCPCVABBUCABWASCRCTC9BYAPCRCUAVAUAUAUAUAUAUABBPCYAABXAUAYAYAUAWAWAUAXAZARCVA9BQCZACBTCRCUAYABBPCXABBRCVABBWATCRCBBPCTCUCBBUACBTCVAUAPCZAYAZAQCSCZASCCBUCTCABXAZASCUCZAZAYAVACBBBPCABCBCBBBCBAB9BCBWAUAWAWAUA9BBBPCQCBBPCUAWAVAUCTCQCPCBBQCUAUCBBQCVAPCZATCYAYAUA9BSCCBYAZAVAUARCBB9BVAYABBCBCBYASCWAUASCABQCRCPC9BRCSCWA9BVAXAUCZATCPCXAQCWAUAVAYAVAUAYARCYAQCABPCABUCABQCQCWARCBBCBCBUCYAPCTCPCQCABZAQCYAVAZA9BABRCUAYAUAPCTCABCBZAUA9BSCYAXATCTCABWAUC9BZAUARCCBZAQC9BXAVACBTCYAABYAUAWAUCUAQCPCBBBBSCVARCZAPCWACBYASCUAABZABBBBZAYAYAWA9BABCBSCRCWAYABBBBWATCPCXAABRCXAVATCUASCQCRCBBWARCUCSCZAVATCSCVABBZASCABTCCBYAUCUCUCUCUCUCUCUCUA9BBBUABBYAVATCUAUAUAUAUAUAUAUAUAUAVAABPCCBVAYAABABCBWAXAUCBBTCBBPC9BQCCBUCXAVAUCWAXASCCBSCSCVAABCBXACBWAWATCVAYA9BSCVAABZAQCXABBABYAUAYAQCYARCUAUAUAUAUAUAUAUAUAUAVAABPCCBVAYAZAQCBBSCQCXASCUC9BBBSCCBBBZA9BVAQCCBCBZABBTCVAUAWAYAQCBBUCABWAUASCCBYARCUAABTCPCBBABRCSCUAQCUAWAUAUAUAUAUAUAUAUAUAUAVAABPCCBVAYAQCTCRCSCABUCXAUAXATCSCXAVAYAZA9BABWAWABBABABTCZAYATCZAPCBB9BTCQCBBZATCPCBBXAABBBBBABXAYAUCBBYAVAUAUAUAUAUAUAUAUAUAUAVACBAB9BPCCBVAYAUCABPCQCXAWAWAQCPCWAYAQCTC9BRCCBUCABRC9BTCWAVA9B9BWAZARCUAWAPCVAWATC9BWAUA9BVABBBBBBPCRCZAZAYAVAUACBUAUAUAUAUAUAUAUAUAUAVAABPCCBVAYAQCTCRCSCABUCXAUAXATCSCXAVAYAZA9BABWAWABBABABTCZAYATCZAPCBB9BTCQCBBZATCPCBBXAABBBBBABRCSCCBYAVARCUAWAUAUAUAUAUAUAUAUAVACBAB9BPCCBVAYAABSCSCQCWAXA9BTCABBBABABSCZAUAYAUATCWAPCZACBTCYAQCTCZAYAYARC9BZACBXAYATCZAABXAPCBBBBPCRCUAUAUAUAUAUAUAUA",
                    "accountID": 1,
                    "decryptionPassword": "NDZnDk5R",
                    "derivationPaths": [{
                        "path": "m/44'/0'/0'/1/0",
                        "cosigners": 1
                        },{
                        "path": "m/44'/0'/0'/0/1",
                        "cosigners": 1}],
                    "_comment": "spending utxo from our first receiving address and our first change address"
                }
            },
            "response": {
                "type": "success",
                "response": "signTransaction",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": [{
                    "raw": "BCSBQBXBKBCCDCACOBUAVAUAUAUAUAUAUAUAVAUATCXASCYASCYAPCWAXABBXATCQCUAUARCUCABCB9BRCTCXABBUAPC9BZAWAYAUAQCCBUAABABTCCBQCBBQCVATCABUA9BTCUAXAQCPCVABBUCABWASCRCTC9BYAPCRCUAVAUAUAUAUAUAUABBPCYAABXAUAYAYAUAWAWAUAXAZARCVA9BQCZACBTCRCUAYABBPCXABBRCVABBWATCRCBBPCTCUCBBUACBTCVAUAPCZAYAZAQCSCZASCCBUCTCABXAZASCUCZAZAYAVACBBBPCABCBCBBBCBAB9BCBWAUAWAWAUA9BBBPCQCBBPCUAWAVAUCTCQCPCBBQCUAUCBBQCVAPCZATCYAYAUA9BSCCBYAZAVAUARCBB9BVAYABBCBCBYASCWAUASCABQCRCPC9BRCSCWA9BVAXAUCZATCPCXAQCWAUAVAYAVAUAYARCYAQCABPCABUCABQCQCWARCBBCBCBUCYAPCTCPCQCABZAQCYAVAZA9BABRCUAYAUAPCTCABCBZAUA9BSCYAXATCTCABWAUC9BZAUARCCBZAQC9BXAVACBTCYAABYAUAWAUCUAQCPCBBBBSCVARCZAPCWACBYASCUAABZABBBBZAYAYAWA9BABCBSCRCWAYABBBBWATCPCXAABRCXAVATCUASCQCRCBBWARCUCSCZAVATCSCVABBZASCABTCCBYAUCUCUCUCUCUCUCUCUA9BBBUABBYAVATCUAUAUAUAUAUAUAUAUAUAVAABPCCBVAYAABABCBWAXAUCBBTCBBPC9BQCCBUCXAVAUCWAXASCCBSCSCVAABCBXACBWAWATCVAYA9BSCVAABZAQCXABBABYAUAYAQCYARCUAUAUAUAUAUAUAUAUAUAVAABPCCBVAYAZAQCBBSCQCXASCUC9BBBSCCBBBZA9BVAQCCBCBZABBTCVAUAWAYAQCBBUCABWAUASCCBYARCUAABTCPCBBABRCSCUAQCUAWAUAUAUAUAUAUAUAUAUAUAVAABPCCBVAYAQCTCRCSCABUCXAUAXATCSCXAVAYAZA9BABWAWABBABABTCZAYATCZAPCBB9BTCQCBBZATCPCBBXAABBBBBABXAYAUCBBYAVAUAUAUAUAUAUAUAUAUAUAVACBAB9BPCCBVAYAUCABPCQCXAWAWAQCPCWAYAQCTC9BRCCBUCABRC9BTCWAVA9B9BWAZARCUAWAPCVAWATC9BWAUA9BVABBBBBBPCRCZAZAYAVAUACBUAUAUAUAUAUAUAUAUAUAVAABPCCBVAYAQCTCRCSCABUCXAUAXATCSCXAVAYAZA9BABWAWABBABABTCZAYATCZAPCBB9BTCQCBBZATCPCBBXAABBBBBABRCSCCBYAVARCUAWAUAUAUAUAUAUAUAUAVACBAB9BPCCBVAYAABSCSCQCWAXA9BTCABBBABABSCZAUAYAUATCWAPCZACBTCYAQCTCZAYAYARC9BZACBXAYATCZAABXAPCBBBBPCRCUAUAUAUAUAUAUAUA",
                    "complete": true,
                    "errors": []
                }]
            }
        }]
    },
    {
        "info": {
            "method": "signMessage",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description":"Returns signature"
        },
        "parameters": [
            {
                "label": "message",
                "type": "string",
                "description": "Message to sign",
                "required": true
            },
            {
                "label":"accountID",
                "type":"string",
                "required":true,
                "regex": /^[0-9a-f]{64}$/
            },
            {
                "label": "derivationPath",
                "type": "string",
                "description": "Used to derive to private key",
                "required": true,
                "regex": /^[m]([\/][0-9]*[']*)*$/
            },
            {
                "label": "decryptionPassword",
                "type": "string",
                "description": "Password required for decrypt account seed",
                "required": true
            }
        ],
        "response": {
            "success": {
                "label": "signature",
                "description": "Base64 encoded signature"
                "type": "string"
            },
            "errors": [
                {
                    "label": "Inexistent account",
                    "type": "throw"
                },
                {
                    "label": "Invalid decryptionPassword",
                    "type": "throw"
                },
                {
                    "label": "Invalid derivationPath",
                    "type": "throw",
                    "description": "derivationPath is not well-format"
                },
                {
                    "label": "Can't storage",
                    "type": "throw",
                    "description": "Storage cannot be read or written"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "params": {
                    "endpoint": "signMessage",
                    "message": "I told you that it was my address...",
                    "accountID": 1,
                    "decryptionPassword": "NDZnDk5R",
                    "derivationPath": "m/44'/0'/0'/0/0"
                }
            },
            "response": {
                "type": "success",
                "response": "signMessage",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": "IOj8cUn8boB+Ut4xbXZhDiSWPXP8yvETPUNryaWIKw18KrJVfRfu2eJa6AhjC9htIJIpVTOa7EVZ6FW1gGMzPgY="
            }
        }]
    },
    {
        "info": {
            "method": "decryptMessage",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description":"Return decrypted message"
        },
        "parameters": [
            {
                "label": "encryptedMessage",
                "type": "string",
                "description": "Base64-encoded message to decrypt",
                "required": true
                "regex": /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
            },
            {
                "label":"accountID",
                "type":"string",
                "description": "Needed to identify which account seed use to derive",
                "required":true,
                "regex": /^[0-9a-f]{64}$/
            },
            {
                "label": "derivationPath",
                "type": "string",
                "description": "Used to get private keys",
                "required": true,
                "regex": /^[m]([\/][0-9]*[']*)*$/
            },
            {
                "label": "decryptionPassword",
                "type": "string",
                "description": "Password required for decrypt account seed",
                "required": true
            }
        ],
        "response": {
            "success": {
                "label": "message",
                "description": "decrypted message",
                "type": "string"
            },
            "errors": [
                {
                    "label": "Inexistent account",
                    "type": "throw"
                },
                {
                    "label": "Invalid decryptionPassword",
                    "type": "throw"
                },
                {
                    "label": "Invalid derivationPath",
                    "type": "throw",
                    "description": "derivationPath is not well-format"
                },
                {
                    "label": "Cannot decrypt",
                    "type": "throw",
                    "description": "Derived private key do not correspond"
                },
                {
                    "label": "storage error",
                    "type": "throw",
                    "description": "Storage cannot be read"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "params": {
                    "endpoint": "decryptMessage",
                    "encryptedMessage": "mKqJHuT1pRE=",
                    "accountID": 1,
                    "decryptionPassword": "NDZnDk5R",
                    "derivationPath": "m/44'/0'/0'/0/0"
                }
            },
            "response": {
                "type": "success",
                "response": "decryptMessage",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": "I stole the Alice's chocolate 🙈"
            }
        }]
    },
    {
        "info": {
            "method": "getAddress",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description": "Returns derived address",
        },
        "parameters": [
            {
                "label": "accountID",
                "type": "string",
                "required": true,
                "regex": /^[0-9a-f]{64}$/
            },{
                "label": "decryptionPassword",
                "type": "string",
                "description": "Password required for decrypt account seed",
                "required": true
            },{
                "label":"derivationPath",
                "type":"string",
                "description": "Path to use in the seed derivation",
                "required": true,
                "regex": /^[m]([\/][0-9]*[']*)*$/
            }
        ],
        "response": {
            "success": {
                "label": "address",
                "type": "ref#https://hackmd.io/fETdWvpNSCGYPcSEWGl4Mg",
            },
            "errors": [
                {
                    "label": "Invalid accountID",
                    "type": "throw",
                    "description": "Wrong required parameters"
                },
                {
                    "label": "Invalid decryptionPassword",
                    "type": "throw",
                    "description": "Wrong required parameters"
                },
                {
                    "label": "Corrupted storage",
                    "type": "throw",
                    "description": "Storage is corrupted and cannot be read or decrypted"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "( await stronghold(params) ).withChecksum()",
                "_comment": "ref#https://hackmd.io/fETdWvpNSCGYPcSEWGl4Mg"
                "params": {
                    "endpoint": "getAddress",
                    "accountID": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53",
                    "decryptionPassword": "NDZnDk5R",
                    "derivationPath": "m/44'/0'/0'/0/0"
                }
            },
            "response": {
                "type": "success",
                "response": "getAddress",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": "HORNET99INTEGRATED99SPAMMER999999999999999999999999999999999999999999999999999999NP9HRUAKD"
            }
        }]
    },
    {
        "info": {
            "method": "exportAccount",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description": "Returns account with unencrypted data",
        },
        "parameters": [
            {
                "label": "accountID",
                "type": "string",
                "required": true,
                "regex": /^[0-9a-f]{64}$/
            },{
                "label": "decryptionPassword",
                "type": "string",
                "description": "Password required for decrypt bip39Mnemonic (and bip39Passphrase is set)",
                "required": true
            }
        ],
        "response": {
            "success": {
                "label": "account",
                "type": "ref#https://hackmd.io/@mrb/SyVWHxBp8",
            },
            "errors": [
                {
                    "label": "Invalid accountID",
                    "type": "throw",
                    "description": "Wrong required parameters"
                },
                {
                    "label": "Invalid decryptionPassword",
                    "type": "throw",
                    "description": "Wrong required parameters"
                },
                {
                    "label": "Corrupted storage",
                    "type": "throw",
                    "description": "Storage is corrupted and cannot be read or decrypted"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "_comment": "ref#https://hackmd.io/1OZ8_7hySqW3Yfa3jnLmow"
                "params": {
                    "endpoint": "exportAccount",
                    "accountID": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53",
                    "decryptionPassword": "NDZnDk5R"
                }
            },
            "response": {
                "type": "success",
                "response": "exportAccount",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": {
                    "accountID": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53",
                    "bip39Mnemonic": "mean poet dinner canyon catalog way uniform unfold miracle trade flip gift",
                    "bip39Passphrase": "kVU8omFM",
                    "external": false,
                    "created": 1592477131000,
                    "lastDecryption": 1592478031000,
                    "exportCounter": 1,
                    "decryptionCounter": 3
                }
            }
        }]
    },
    {
        "info": {
            "method": "openSession",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description": "Open an account session",
        },
        "parameters": [
            {
                "label": "accountID",
                "type": "string",
                "required": true,
                "regex": /^[0-9a-f]{64}$/
            },{
                "label": "decryptionPassword",
                "type": "string",
                "description": "Password required for decrypt bip39Mnemonic (and bip39Passphrase is set)",
                "required": true
            },{
                "label": "duration",
                "type": "number",
                "description": "How much time in ms will during the session before expires. With 0 it never expires.",
                "required": false,
                "default": 5000,
                "regex": /^[0-9]{0,12}$/
            }
        ],
        "response": {
            "success": {
                "label": "token",
                "type": "string",
            },
            "errors": [
                {
                    "label": "Invalid accountID",
                    "type": "throw",
                    "description": "Wrong required parameters"
                },
                {
                    "label": "Invalid decryptionPassword",
                    "type": "throw",
                    "description": "Wrong required parameters"
                },
                {
                    "label": "Invalid duration",
                    "type": "throw",
                    "description": "Wrong required parameters"
                },
                {
                    "label": "Corrupted storage",
                    "type": "throw",
                    "description": "Storage is corrupted and cannot be read or decrypted"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "params": {
                    "endpoint": "openSession",
                    "accountID": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53",
                    "decryptionPassword": "NDZnDk5R",
                    "duration": 5000
                }
            },
            "response": {
                "type": "success",
                "response": "openSession",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": {
                    "id": 0,
                    "accountId": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53",
                    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                    "created": 1593437318000,
                    "lastLogin": 1593437318000,
                    "duration": 5000,
                    "loginCounter": 0
                }
            }
        }]
    },
    {
        "info": {
            "method": "closeSession",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description": "Closes an active session",
        },
        "parameters": [
            {
                "label": "token",
                "type": "string",
                "required": true,
                "regex":
            }
        ],
        "response": {
            "success": {
                "label": "session",
                "type": "session",
                "description": "Removed session"
            },
            "errors": [
                {
                    "label": "Invalid token",
                    "type": "throw",
                    "description": "Token does not exists"
                },
                {
                    "label": "Corrupted storage",
                    "type": "throw",
                    "description": "Storage is corrupted and cannot be read or decrypted"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "params": {
                    "endpoint": "closeSession",
                    "token": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53"
                }
            },
            "response": {
                "type": "success",
                "response": "closeSession",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": {
                    "id": 0,
                    "accountId": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53",
                    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                    "created": 1593437318000,
                    "lastLogin": 1593437318000,
                    "duration": 5000,
                    "loginCounter": 3
                }
            }
        }]
    },
    {
        "info": {
            "method": "listSessions",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description": "Returns active sessions",
        },
        "parameters": [
            {
                "label": "skip",
                "type": "number",
                "description": "Results to skip",
                "required": false,
                "default": 0,
                "regex": /^[0-9]{0,16}$/
            },
            {
                "label": "limit",
                "type": "number",
                "description": "Limit number of results",
                "required": false,
                "default": 100,
                "regex": /^[0-9]{0,16}$/
            }
        ],
        "response": {
            "success": {
                "label": "sessions",
                "type": "Session array ref#https://hackmd.io/@mrb/S1EOZPDCI",
            },
            "errors": [
                {
                    "label": "Invalid parameters",
                    "type": "throw",
                    "description": "Wrong parameters"
                },
                {
                    "label": "Corrupted storage",
                    "type": "throw",
                    "description": "Storage is corrupted and cannot be read or decrypted"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "params": {
                    "endpoint": "listSessions"
            },
            "response": {
                "type": "success",
                "response": "listSessions",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body":  [
                    {
                        "id": 0,
                        "accountId": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53",
                        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                        "created": 1593437318000,
                        "lastLogin": 1593437318000,
                        "duration": 5000,
                        "loginCounter": 3
                    },{
                        "id": 1,
                        "accountId": "C63F5EA93B72ASKDJASIDDJMQWKDIQWJMDKM7FD3E1F13D83CF7773FD15FE4B53",
                        "token": "eyJUjUjUjJAUAIkmNUHduwiwkMoPlpokOijsw.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                        "created": 1593437319000,
                        "lastLogin": 1593437319000,
                        "duration": 6000,
                        "loginCounter": 3
                    }
                ]
            }
        }]
    },
    {
        "info": {
            "method": "getSessionData",
            "sender": ["wallet"],
            "recipient": ["stronghold"],
            "description": "Returns session data",
        },
        "parameters": [
            {
                "label": "token",
                "type": "string",
                "description": "Session token",
                "required": true,
                "regex": //
            }
        ],
        "response": {
            "success": {
                "label": "session",
                "type": "Session ref#https://hackmd.io/@mrb/S1EOZPDCI",
            },
            "errors": [
                {
                    "label": "Invalid token",
                    "type": "throw",
                    "description": "Wrong token"
                },
                {
                    "label": "Corrupted storage",
                    "type": "throw",
                    "description": "Storage is corrupted and cannot be read or decrypted"
                }
            ]
        },
        "examples": [{
            "request": {
                "fn": "await stronghold(params)",
                "params": {
                    "endpoint": "listSessions"
            },
            "response": {
                "type": "success",
                "response": "listSessions",
                "messageHash": "F8D60E82EC2143F8BA12CC461A7CB3A4A9924ED8ADFA163F77B3F340A229CCE9"
                "body": {
                  "id": 0,
                  "accountId": "C63F5EA93B725854CBCE809A17FE922541697FD3E1F13D83CF7773FD15FE4B53",
                  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                  "created": 1593437318000,
                  "lastLogin": 1593437318000,
                  "duration": 5000,
                  "loginCounter": 3
                }
            }
        }
    }
]
```

## Referenced schemas
[Encrypted Account](https://hackmd.io/l5a5tF8oRC2PDPZCf3r0QQ)


[Uncrypted Account](https://hackmd.io/1OZ8_7hySqW3Yfa3jnLmow)
[Address](https://hackmd.io/fETdWvpNSCGYPcSEWGl4Mg)
[signingTxResult](https://hackmd.io/_l6cCVm_RzOT629N5mJqyQ)
[Session](https://hackmd.io/@mrb/S1EOZPDCI)
