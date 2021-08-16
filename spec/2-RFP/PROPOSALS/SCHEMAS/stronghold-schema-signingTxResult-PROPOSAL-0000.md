# signingTxResult
```json
{
    "info": {
        "name": "signingTxResult",
        "description": "Result of signing transaction"
    },
    "properties": {
        "raw": {
            "type": "string",
            "description": "The tryte-encoded transaction with signature(s)"
        },
        "complete": {
            "type": "boolean",
            "description": "If transaction has a complete set of signatures"
        },
        "errors": {
            "type": "array",
            "description": "Array containing data about uncompleted",
            "examples": [{
                "txid": "9ZQUFIDGZWACQ99YSGKRGIUDFCABIASGTHMXKGFVSZQVRJ9ZBQUKQDFOKVZYUBJPCXGMOLLBQDIHZ9999",
                "vout":1,
                "error":"Cannot sign it with any provided derivation path"
            },{
                "txid": "XYLLLOOOSKVKROZDKXNPWSD9BKMFSWKLMRKNCTIK9RJDLZVKC9AEZYCZEJYLOFSKVWH9JXJQNGGX99999",
                "vout":42,
                "error":"Incomplete signing, probably cosigners signatures are missing"
            }]
        }
    }
}
```
