#ifndef _HKDF_H_
#define _HKDF_H_

#include <stddef.h>
#include <stdint.h>

struct Hkdf_Out {
	uint8_t peer_key[16];
	uint8_t my_key[16];
	uint8_t peer_IV[4];
	uint8_t my_IV[4];
};

extern int Hkdf(const uint8_t *key, size_t key_size, struct Hkdf_Out *out);

#endif
