#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct StrongholdWrapper StrongholdWrapper;

struct StrongholdWrapper *create(const char *snapshot_path_c, const char *key_c);

struct StrongholdWrapper *load(const char *snapshot_path_c, const char *key_c);

void destroy_stronghold(struct StrongholdWrapper *stronghold_ptr);

void destroy_data_pointer(uint8_t *ptr);

uint8_t *generate_ed25519_keypair(struct StrongholdWrapper *stronghold_ptr,
                                  const char *key_c,
                                  const char *record_path_c);

bool generate_seed(struct StrongholdWrapper *stronghold_ptr, const char *key_c);

bool derive_seed(struct StrongholdWrapper *stronghold_ptr,
                 const char *key_c,
                 uint32_t address_index);

uint8_t *get_public_key(struct StrongholdWrapper *stronghold_ptr, const char *record_path_c);

uint8_t *sign(struct StrongholdWrapper *stronghold_ptr,
              const char *record_path_c,
              const unsigned char *data_c,
              size_t data_length);
