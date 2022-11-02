#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "Hkdf.h"

int Hkdf(const uint8_t *key, size_t key_size, struct Hkdf_Out *out)
{
	if (key == NULL || !key_size || out == NULL)
		return -1;

	EVP_PKEY_CTX *pctx;
	if ((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)) == NULL)
		return -1;

	size_t s = sizeof(*out);
	if (EVP_PKEY_derive_init(pctx) <= 0 ||
	    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
	    EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_size) <= 0 ||
	    EVP_PKEY_derive(pctx, (uint8_t *)out, &s) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	EVP_PKEY_CTX_free(pctx);
	return 0;
}

