#ifndef RANDOMBYTES_CONTROL_H
#define RANDOMBYTES_CONTROL_H

// Extra control API added on top of PQClean's randombytes()
// (declared separately in randombytes.h, and macro-renamed to
// PQCLEAN_randombytes there -- that part is untouched by this header).
//
// Default state: "real" mode. randombytes() behaves exactly as it always
// has, per-platform (getrandom/urandom, arc4random, CryptGenRandom, ...).
//
// Calling randombytes_enable_fixed() switches randombytes() to a
// deterministic byte stream expanded from a seed you provide via
// randombytes_set_fixed_seed[_hex](). As long as the seed doesn't change,
// every keypair/encaps that consumes randombytes() afterward becomes
// reproducible -- same keys, same ciphertext, same shared secret -- across
// runs. Change the seed to get a different (but still reproducible) shared
// secret: that's the "fixed but modifiable" part.
//
// Call randombytes_disable_fixed() as soon as you're done so every other
// caller keeps getting real randomness.

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Set/replace the seed used to derive the deterministic stream. Also resets
// the internal stream position back to byte 0, so re-arming fixed mode with
// the same seed always reproduces the same sequence. Seed is copied in
// (max 256 bytes kept).
void randombytes_set_fixed_seed(const uint8_t *seed, size_t seed_len);

// Convenience: same as above but seed given as a hex string
// Returns 0 on success, -1 on malformed hex.
int randombytes_set_fixed_seed_hex(const char *hex);

// Turn deterministic mode on / off. Both just flip a flag; enabling always
// restarts the stream at the point defined by the current seed.
void randombytes_enable_fixed(void);
void randombytes_disable_fixed(void);

// Query current mode (1 = fixed/deterministic, 0 = real OS randomness).
int randombytes_is_fixed(void);

#ifdef __cplusplus
}
#endif

#endif // RANDOMBYTES_CONTROL_H