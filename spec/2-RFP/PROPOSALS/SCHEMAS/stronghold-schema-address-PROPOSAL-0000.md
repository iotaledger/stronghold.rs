# Address schema

```json
{
    "info": {
        "name": "Address",
        "description": "Address schema"
    },
    "properties": {
        "withChecksum": {
            "type": "function",
            "description": "Returns address with security checksum",
            "async": false,
            "response": {
                "success": {
                    "description": "Tryte encoded address with checksum",
                    "type": "string"
                },
                "errors": []
            },
            "example": "PUBXB9F9XCZS9VJGF9LIGHPYDLRMVVRQPS9AGJSK9DRWVGFKJICUBJMAQBUWCTNQAGQDDRQPFXKGVDWYWZC9ZSFGTX"
        },
        "withoutChecksum": {
            "type": "function",
            "description": "Returns address without security checksum",
            "async": false,
            "response": {
                "success": {
                    "description": "Tryte encoded address without checksum",
                    "type": "string"
                },
                "errors": []
            },
            "example": "PUBXB9F9XCZS9VJGF9LIGHPYDLRMVVRQPS9AGJSK9DRWVGFKJICUBJMAQBUWCTNQAGQDDRQPFXKGVDWYW"
        }
    }
}
```
