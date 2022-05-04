#include <stdlib.h>

#define STRONGHOLD_PTR void *

/*
 * Snapshot paths need to be absolute.
 */

// Creates a new Stronghold instance with an empty snapshot
STRONGHOLD_PTR create(char *snapshot_path, char *key);

// Initializes a new Stronghold instance
STRONGHOLD_PTR load(char *snapshot_path, char *key);

// Frees and deletes instance from pointer
void destroy(STRONGHOLD_PTR stronghold_ptr);

// Generates a new ED25519 private key (seed)
void generate_seed(STRONGHOLD_PTR stronghold_ptr, char *key);
