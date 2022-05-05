#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

struct StrongholdWrapper;

extern "C" {

StrongholdWrapper *create(const char *snapshot_path_c, const char *key_c);

StrongholdWrapper *load(const char *snapshot_path_c, const char *key_c);

void destroy_stronghold(StrongholdWrapper *ptr);

void destroy_signature(uint8_t *ptr);

void generate_seed(StrongholdWrapper *stronghold_ptr, const char *key);

uint8_t *sign(StrongholdWrapper *stronghold_ptr, const unsigned char *data_c, size_t data_length);

} // extern "C"
