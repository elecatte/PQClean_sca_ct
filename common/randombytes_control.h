#ifndef RANDOMBYTES_CONTROL_H
#define RANDOMBYTES_CONTROL_H

// Extra control API added on top of PQClean's randombytes()

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Set/replace the seed used to derive the deterministic stream.
void randombytes_set_fixed_seed(const uint8_t *seed, size_t seed_len);

// Convenience: same as above but seed given as a hex string
int randombytes_set_fixed_seed_hex(const char *hex);

// Turn deterministic mode on / off. 
void randombytes_enable_fixed(void);
void randombytes_disable_fixed(void);

// Query current mode (1 = fixed/deterministic, 0 = real OS randomness).
int randombytes_is_fixed(void);

#ifdef __cplusplus
}
#endif

#endif // RANDOMBYTES_CONTROL_H