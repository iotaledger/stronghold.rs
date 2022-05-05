#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct StrongholdWrapper StrongholdWrapper;

struct StrongholdWrapper *create(const char *snapshot_path_c, const char *key_c);

struct StrongholdWrapper *load(const char *snapshot_path_c, const char *key_c);

void destroy_stronghold(struct StrongholdWrapper *ptr);

void destroy_signature(uint8_t *ptr);

void generate_seed(struct StrongholdWrapper *stronghold_ptr, const char *key);

uint8_t *sign(struct StrongholdWrapper *stronghold_ptr,
              const unsigned char *data_c,
              size_t data_length);
