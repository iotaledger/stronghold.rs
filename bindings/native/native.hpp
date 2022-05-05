#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

struct StrongholdWrapper;

extern "C" {

StrongholdWrapper *create(const char *snapshot_path_c, const char *key_c);

StrongholdWrapper *load(const char *snapshot_path_c, const char *key_c);

void destroy_stronghold(StrongholdWrapper *stronghold_ptr);

void destroy_data_pointer(uint8_t *ptr);

void generate_ed25519_keypair(StrongholdWrapper *stronghold_ptr,
                              const char *key_c,
                              const char *record_path_c);

void generate_seed(StrongholdWrapper *stronghold_ptr, const char *key_c);

void derive_seed(StrongholdWrapper *stronghold_ptr, const char *key_c, uint32_t address_index);

uint8_t *get_public_key(StrongholdWrapper *stronghold_ptr, const char *record_path_c);

uint8_t *sign(StrongholdWrapper *stronghold_ptr,
              const char *record_path_c,
              const unsigned char *data_c,
              size_t data_length);

} // extern "C"
