# Session schema
```json
{
    "info": {
        "name": "Session",
        "description": "Session schema"
    },
    "properties": {
        "id": {
            "type": int,
            "description": "ID of the session",
            "access": "public"
        },
        "accountId": {
            "type": string,
            "description": "Account to which the session belongs"
            "access": "public"
        },
        "token": {
            "type": string,
            "description": "Session token access",
            "access": "private",
        }
        "created": {
            "type": number,
            "description": "When the session was created (in unix time ms)",
            "access": "public"
        },
        "lastLogin": {
            "type": number,
            "description": "When was the last login (in unix time ms)",
            "access": "public"
        },
        "duration": {
            "type": number,
            "description": "Duration of the session (in unix time ms)",
            "access": "public"
        },
        "expired": {
            "type": boolean,
            "description": "If the session is already expired",
            "access": "public"
        },
        "loginCounter": {
            "type": number,
            "description": "How many times this session was used",
            "access": "public"
        }
    }
}
```
