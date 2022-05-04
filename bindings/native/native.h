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
// *This is required for Stronghold and Signature pointers!*
void destroy_stronghold(STRONGHOLD_PTR stronghold_ptr);
void destroy_signature(STRONGHOLD_PTR signature_ptr);

// Generates a new ED25519 private key (seed)
void generate_seed(STRONGHOLD_PTR stronghold_ptr, char *key);

// Signs an array of bytes, returns a signature with a length if 64 bytes
void *sign(STRONGHOLD_PTR stronghold_ptr, char *data, size_t length);
