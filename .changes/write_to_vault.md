---
"iota-stronghold": patch
---

- corrects wrong control flow. `write_to_vault` always returned an error even if the operation was successful. 