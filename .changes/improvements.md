---
"iota-stronghold": patch
---

Loading a snapshot file will now return a new `ClientError` variant `SnapshotFileMissing`, if the snapshot file is not present
Committing `Client` state into a snapshotfile will now check if all paths to the snapshot file are correct and will create the snapshot file, if it doesn't exist.

