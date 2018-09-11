#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <coala/Mem.h>
#include "Aead.h"

struct Aead {
	unsigned char peerkey[16];
	unsigned char mykey[16];
	unsigned char peerIV[4];
	unsigned char myIV[4];
	EVP_CIPHER_CTX *ctx_dec;
	EVP_CIPHER_CTX *ctx_enc;
};

struct Aead *Aead(unsigned char *peerkey, size_t peerkey_size,
		  unsigned char *mykey, size_t mykey_size,
		  unsigned char *peerIV, size_t peerIV_size,
		  unsigned char *myIV, size_t myIV_size)
{
	int errsv = 0;
	struct Aead *a = NULL;

	if (peerkey == NULL || peerkey_size != sizeof a->peerkey ||
	    mykey   == NULL || mykey_size   != sizeof a->mykey   ||
	    peerIV  == NULL || peerIV_size  != sizeof a->peerIV  ||
	    myIV    == NULL || myIV_size    != sizeof a->myIV) {
		errno = EINVAL;
		goto out;
	}

	a = Mem_calloc(1, sizeof *a);
	if (a == NULL)
		goto out;

	memcpy(a->peerkey, peerkey, sizeof a->peerkey);
	memcpy(a->mykey, mykey, sizeof a->mykey);
	memcpy(a->peerIV, peerIV, sizeof a->peerIV);
	memcpy(a->myIV, myIV, sizeof a->myIV);

	a->ctx_dec = EVP_CIPHER_CTX_new();
	if (a->ctx_dec == NULL) {
		errsv = EBADE;
		goto out_free;
	}

	if (!EVP_DecryptInit_ex(a->ctx_dec, EVP_aes_128_gcm(), NULL, a->peerkey,
				NULL)) {
		errsv = EBADE;
		goto out_dec_free;
	}

	a->ctx_enc = EVP_CIPHER_CTX_new();
	if (a->ctx_enc == NULL) {
		errsv = EBADE;
		goto out_dec_free;
	}

	if (!EVP_EncryptInit_ex(a->ctx_enc, EVP_aes_128_gcm(), NULL, a->mykey,
				NULL)) {
		errsv = EBADE;
		goto out_enc_free;
	}

	goto out;

out_enc_free:
	EVP_CIPHER_CTX_free(a->ctx_enc);
out_dec_free:
	EVP_CIPHER_CTX_free(a->ctx_dec);
out_free:
	Mem_free(a);
	a = NULL;
out:
	if (errsv)
		errno = errsv;

	return a;
}

void Aead_Free(struct Aead *a)
{
	if (a == NULL)
		return;

	EVP_CIPHER_CTX_free(a->ctx_dec);
	EVP_CIPHER_CTX_free(a->ctx_enc);

	Mem_free(a);
}

int Aead_Open(struct Aead *a, unsigned char *cipher, size_t cipher_size,
	      unsigned short counter, unsigned char *data, size_t data_len,
	      unsigned char *plain, size_t *plain_size)
{
	enum Aead_Err res;
	int outl;
	unsigned char IV[12], tag[AEAD_TAG_SIZE];
	unsigned short id = htole16(counter);

	if (a == NULL || cipher == NULL || cipher_size <= sizeof tag ||
	    plain == NULL || plain_size == NULL ||
	    *plain_size < cipher_size - sizeof tag) {
		res = Aead_Inval;
		goto out;
	}

	cipher_size -= sizeof tag;
	memcpy(tag, cipher + cipher_size, sizeof tag);

	memset(&IV, 0, sizeof IV);
	memcpy(IV, a->peerIV, sizeof a->peerIV);
	memcpy(IV + sizeof a->peerIV, &id, sizeof id);

	/* Set IV */
	if (!EVP_DecryptInit_ex(a->ctx_dec, NULL, NULL, NULL, IV)) {
		res = Aead_CryptInit;
		goto out;
	}

	/* Provide AAD (optional) */
	if (data && !EVP_DecryptUpdate(a->ctx_dec, NULL, &outl, data,
	    data_len)) {
		res = Aead_CryptAad;
		goto out;
	}

	/* Plain */
	if (!EVP_DecryptUpdate(a->ctx_dec, plain, &outl, cipher, cipher_size)) {
		res = Aead_CryptPlain;
		goto out;
	}

	*plain_size = outl;

	/* Set tag */
	if (!EVP_CIPHER_CTX_ctrl(a->ctx_dec, EVP_CTRL_GCM_SET_TAG, sizeof tag,
				 tag)) {
		res = Aead_CryptTag;
		goto out;
	}

	if (!EVP_DecryptFinal_ex(a->ctx_dec, plain + outl, &outl)) {
		res = Aead_CryptPlainFinal;
		goto out;
	}

	*plain_size += outl;

	res = Aead_Ok;
out:
	return res;
}

enum Aead_Err Aead_Seal(struct Aead *a,
			unsigned char *plain, size_t plain_size,
			unsigned short counter,
			unsigned char *data, size_t data_len,
			unsigned char *cipher, size_t *cipher_size)
{
	enum Aead_Err res;
	int outl;
	unsigned char IV[12], tag[AEAD_TAG_SIZE];
	unsigned short id = htole16(counter);

	if (a == NULL || plain == NULL || !plain_size || cipher == NULL ||
	    cipher_size == NULL || *cipher_size < plain_size + sizeof tag) {
		res = Aead_Inval;
		goto out;
	}

	memset(&IV, 0, sizeof IV);
	memcpy(IV, a->myIV, sizeof a->myIV);
	memcpy(IV + sizeof a->myIV, &id, sizeof id);

	/* Set IV */
	if (!EVP_EncryptInit_ex(a->ctx_enc, NULL, NULL, NULL, IV)) {
		res = Aead_CryptInit;
		goto out;
	}

	/* Provide AAD (optional) */
	if (data && !EVP_EncryptUpdate(a->ctx_enc, NULL, &outl, data,
	    data_len)) {
		res = Aead_CryptAad;
		goto out;
	}

	/* Plain */
	if (!EVP_EncryptUpdate(a->ctx_enc, cipher, &outl, plain, plain_size)) {
		res = Aead_CryptPlain;
		goto out;
	}

	*cipher_size = outl;

	if (!EVP_EncryptFinal_ex(a->ctx_enc, cipher + outl, &outl)) {
		res = Aead_CryptPlainFinal;
		goto out;
	}

	*cipher_size += outl;

	/* Obtain tag */
	if (!EVP_CIPHER_CTX_ctrl(a->ctx_enc, EVP_CTRL_GCM_GET_TAG, sizeof tag,
				 tag)) {
		res = Aead_CryptTag;
		goto out;
	}

	/* Concat cipher & tag */
	memcpy(cipher + *cipher_size, tag, sizeof tag);
	*cipher_size += sizeof tag;

	res = Aead_Ok;
out:
	return res;
}
