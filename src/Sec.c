#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <coala/CoAPMessage.h>

#include "Aead.h"
#include "Err.h"
#include "Sec.h"

int Sec_CookieDecrypt(struct CoAPMessage *m, struct Aead *aead, struct Err *err)
{
	int opt = CoAPMessage_OptionCodeCookie;
	int res = -1;
	struct CoAPMessage_OptionHead h = TAILQ_HEAD_INITIALIZER(h);

	if ((CoAPMessage_GetOptions(m, opt, &h)) < 0 &&
	    errno != ENOENT) {
		Err_Set(err, errno, "CoAPMessage_GetOptions:");
		goto out;
	}

	if (TAILQ_EMPTY(&h))
		goto out_ok;

	CoAPMessage_RemoveOptions(m, opt);

	struct CoAPMessage_Option *o;
	TAILQ_FOREACH(o, &h, list) {
		size_t dec_size;
		uint8_t *dec;

		if ((int)o->value_len - AEAD_TAG_SIZE <= 0) {
			res = -2;
			goto out;
		}

		dec_size = o->value_len - AEAD_TAG_SIZE;

		if ((dec = malloc(dec_size)) == NULL) {
			Err_Set(err, errno, "malloc:");
			goto out;
		}

		if (Aead_Open(aead, o->value, o->value_len,
			      CoAPMessage_GetId(m), NULL, 0,
			      dec, &dec_size) < 0) {
			Err_Set(err, 0, "Aead_Open");
			free(dec);
			res = -2;
			goto out;
		}

		if (CoAPMessage_AddOptionOpaque(m, opt, dec, dec_size) < 0) {
			Err_Set(err, errno, "CoAPMessage_AddOptionOpaque:");
			free(dec);
			goto out;
		}

		free(dec);
	}

out_ok:
	res = 0;
out:
	CoAPMessage_GetOptionsFree(&h);
	return res;
}

int Sec_CookieEncrypt(struct CoAPMessage *m, struct Aead *aead, struct Err *err)
{
	int opt = CoAPMessage_OptionCodeCookie;
	int res = -1;
	struct CoAPMessage_OptionHead h = TAILQ_HEAD_INITIALIZER(h);

	if ((CoAPMessage_GetOptions(m, opt, &h)) < 0 &&
	    errno != ENOENT) {
		Err_Set(err, errno, "CoAPMessage_GetOptions:");
		goto out;
	}

	if (TAILQ_EMPTY(&h))
		goto out_ok;

	CoAPMessage_RemoveOptions(m, opt);

	struct CoAPMessage_Option *o;
	TAILQ_FOREACH(o, &h, list) {
		size_t enc_size = o->value_len + AEAD_TAG_SIZE;
		uint8_t *enc;

		if ((enc = malloc(enc_size)) == NULL) {
			Err_Set(err, errno, "malloc:");
			goto out;
		}

		if (Aead_Seal(aead, o->value, o->value_len,
			      CoAPMessage_GetId(m), NULL, 0,
			      enc, &enc_size) < 0) {
			Err_Set(err, 0, "Aead_Seal");
			free(enc);
			goto out;
		}

		if (CoAPMessage_AddOptionOpaque(m, opt, enc, enc_size) < 0) {
			Err_Set(err, errno, "CoAPMessage_AddOptionOpaque:");
			free(enc);
			goto out;
		}

		free(enc);
	}

out_ok:
	res = 0;
out:
	CoAPMessage_GetOptionsFree(&h);
	return res;
}

int Sec_PayloadDecrypt(struct CoAPMessage *m, struct Aead *aead,
		       struct Err *err)
{
	uint8_t *enc;
	size_t enc_size;

	if ((enc = CoAPMessage_GetPayload(m, &enc_size, 0)) == NULL)
		return 0;

	if ((int)enc_size - AEAD_TAG_SIZE <= 0)
		return -2;

	uint8_t *dec;
	size_t dec_size = enc_size - AEAD_TAG_SIZE;
	if ((dec = malloc(dec_size)) == NULL) {
		Err_Set(err, errno, "malloc:");
		return -1;
	}

	if (Aead_Open(aead, enc, enc_size,
		      CoAPMessage_GetId(m),
		      NULL, 0,
		      dec, &dec_size) < 0) {
		Err_Set(err, 0, "Aead_Open");
		free(dec);
		return -2;
	}

	if (CoAPMessage_SetPayload(m, dec, dec_size) < 0) {
		Err_Set(err, errno, "CoAPMessage_SetPayload:");
		free(enc);
		return -1;
	}

	free(dec);
	return 0;
}

int Sec_PayloadEncrypt(struct CoAPMessage *from, struct CoAPMessage *to,
		       struct Aead *aead, struct Err *err)
{
	uint8_t *d;
	size_t d_size;
	if ((d = CoAPMessage_GetPayload(from, &d_size, 0)) == NULL)
		return 0;

	uint8_t *enc;
	size_t enc_size = d_size + AEAD_TAG_SIZE;
	if ((enc = malloc(enc_size)) == NULL) {
		Err_Set(err, errno, "malloc:");
		return -1;
	}

	if (Aead_Seal(aead, d, d_size,
		      CoAPMessage_GetId(to),
		      NULL, 0,
		      enc, &enc_size) < 0) {
		Err_Set(err, 0, "Aead_Seal");
		free(enc);
		return -1;
	}

	if (CoAPMessage_SetPayload(to, enc, enc_size) < 0) {
		Err_Set(err, errno, "CoAPMessage_SetPayload:");
		free(enc);
		return -1;
	}

	free(enc);
	return 0;
}

int Sec_UriDecrypt(struct CoAPMessage *m, struct Aead *aead, struct Err *err)
{
	uint8_t *enc;
	size_t enc_size;
	if ((enc = CoAPMessage_GetOptionOpaque(m,
					CoAPMessage_OptionCodeCoapsUri,
					&enc_size)) == NULL)
		return 0;

	if ((int)enc_size - AEAD_TAG_SIZE <= 0)
		return -2;

	uint8_t *dec;
	size_t dec_size = enc_size - AEAD_TAG_SIZE;
	if ((dec = malloc(dec_size + 1)) == NULL) {
		Err_Set(err, errno, "malloc:");
		return -1;
	}

	int ret;
	if ((ret = Aead_Open(aead, enc, enc_size,
		      CoAPMessage_GetId(m),
		      NULL, 0,
		      dec, &dec_size)) < 0) {
		Err_Set(err, 0, "Aead_Open: %d", ret);
		free(dec);
		return -2;
	}

	dec[dec_size] = '\0';

	if (CoAPMessage_SetUri(m, (char *)dec,
			       CoAPMessage_SetUriFlagOnlyPath |
			       CoAPMessage_SetUriFlagOnlyQuery) < 0) {
		Err_Set(err, errno, "CoAPMessage_SetUri:");
		free(enc);
		return -1;
	}

	free(dec);
	CoAPMessage_RemoveOptions(m, CoAPMessage_OptionCodeCoapsUri);

	return 0;
}

int Sec_UriEncrypt(struct CoAPMessage *m, struct Aead *aead, struct Err *err)
{
	int res = -1;
	char *uri = NULL;
	uint8_t *enc = NULL;

	if ((uri = CoAPMessage_GetUri(m)) == NULL) {
		Err_Set(err, errno, "CoAPMessage_GetUri:");
		goto out;
	}

	size_t enc_size = strlen(uri) + AEAD_TAG_SIZE;
	if ((enc = malloc(enc_size)) == NULL) {
		Err_Set(err, errno, "malloc:");
		goto out;
	}

	if (Aead_Seal(aead, (uint8_t *)uri, strlen(uri),
		      CoAPMessage_GetId(m),
		      NULL, 0,
		      enc, &enc_size) < 0) {
		Err_Set(err, 0, "Aead_Seal");
		goto out;
	}

	CoAPMessage_RemoveOptions(m,
			CoAPMessage_OptionCodeUriPath);
	CoAPMessage_RemoveOptions(m,
			CoAPMessage_OptionCodeUriQuery);

	if (CoAPMessage_AddOptionOpaque(m,
				CoAPMessage_OptionCodeCoapsUri,
				enc,
				enc_size) < 0) {
		Err_Set(err, errno, "CoAPMessage_AddOptionOpaque:");
		goto out;
	}

	res = 0;
out:
	free(enc);
	free(uri);
	return res;
}
