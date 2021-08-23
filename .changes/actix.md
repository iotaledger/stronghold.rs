---
"iota-stronghold": minor
---
 
- replace actor system riker with actix
- introduced registry actor for clients as service
- introduced snapshot actor as service
- merge `Internal` and `Client`-Actors into `SecureClient`
- api change in interface for test reading secrets out of a vault. minimal impact. 