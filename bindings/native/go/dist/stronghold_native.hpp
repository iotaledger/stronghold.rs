#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

struct StrongholdWrapper;

extern "C" {

void stronghold_set_log_level(size_t log_level);

const char *stronghold_get_last_error();

void stronghold_destroy_error(char *s);

StrongholdWrapper *stronghold_create(const char *snapshot_path_c, const char *key_c);

StrongholdWrapper *stronghold_load(const char *snapshot_path_c, const char *key_c);

void stronghold_destroy_stronghold(StrongholdWrapper *stronghold_ptr);

void stronghold_destroy_data_pointer(uint8_t *ptr);

uint8_t *stronghold_generate_ed25519_keypair(StrongholdWrapper *stronghold_ptr,
                                             const char *key_c,
                                             const char *record_path_c);

bool stronghold_write_vault(StrongholdWrapper *stronghold_ptr,
                            const char *key_c,
                            const char *record_path_c,
                            const unsigned char *data_c,
                            size_t data_length);

bool stronghold_generate_seed(StrongholdWrapper *stronghold_ptr, const char *key_c);

bool stronghold_derive_seed(StrongholdWrapper *stronghold_ptr,
                            const char *key_c,
                            uint32_t address_index);

uint8_t *stronghold_get_public_key(StrongholdWrapper *stronghold_ptr, const char *record_path_c);

uint8_t *stronghold_sign(StrongholdWrapper *stronghold_ptr,
                         const char *record_path_c,
                         const unsigned char *data_c,
                         size_t data_length);

} // extern "C"
