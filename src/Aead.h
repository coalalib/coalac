#ifndef _AEAD_H_
#define _AEAD_H_

#include <stddef.h>

#define AEAD_TAG_SIZE	12

enum Aead_Err {
	Aead_Ok = 0,
	Aead_Inval = -1,
	Aead_CryptInit = -2,
	Aead_CryptAad = -3,
	Aead_CryptPlain = -4,
	Aead_CryptPlainFinal = -5,
	Aead_CryptTag = -6
};

struct Aead;

extern struct Aead *Aead(unsigned char *peerkey, size_t peerkey_size,
			 unsigned char *mykey, size_t mykey_size,
			 unsigned char *peerIV, size_t peerIV_size,
			 unsigned char *myIV, size_t myIV_size);

extern void Aead_Free(struct Aead *a);

extern enum Aead_Err Aead_Open(struct Aead *a,
			       unsigned char *cipher, size_t cipher_size,
			       unsigned short counter,
			       unsigned char *data, size_t data_len,
			       unsigned char *plain, size_t *plain_size);

extern enum Aead_Err Aead_Seal(struct Aead *a,
			       unsigned char *plain, size_t plain_size,
			       unsigned short counter,
			       unsigned char *data, size_t data_len,
			       unsigned char *cipher, size_t *cipher_size);

#endif
