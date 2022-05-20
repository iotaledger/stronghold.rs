#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct StrongholdWrapper StrongholdWrapper;

void stronghold_set_log_level(size_t log_level);

const char *stronghold_get_last_error(void);

void stronghold_destroy_error(char *s);

struct StrongholdWrapper *stronghold_create(const char *snapshot_path_c, const char *key_c);

struct StrongholdWrapper *stronghold_load(const char *snapshot_path_c, const char *key_c);

void stronghold_destroy_stronghold(struct StrongholdWrapper *stronghold_ptr);

void stronghold_destroy_data_pointer(uint8_t *ptr);

uint8_t *stronghold_generate_ed25519_keypair(struct StrongholdWrapper *stronghold_ptr,
                                             const char *key_c,
                                             const char *record_path_c);

bool stronghold_write_vault(struct StrongholdWrapper *stronghold_ptr,
                            const char *key_c,
                            const char *record_path_c,
                            const unsigned char *data_c,
                            size_t data_length);

bool stronghold_generate_seed(struct StrongholdWrapper *stronghold_ptr, const char *key_c);

bool stronghold_derive_seed(struct StrongholdWrapper *stronghold_ptr,
                            const char *key_c,
                            uint32_t address_index);

uint8_t *stronghold_get_public_key(struct StrongholdWrapper *stronghold_ptr,
                                   const char *record_path_c);

uint8_t *stronghold_sign(struct StrongholdWrapper *stronghold_ptr,
                         const char *record_path_c,
                         const unsigned char *data_c,
                         size_t data_length);
