#include <coala/HexString.h>
#include <coala/Mem.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "Str.h"

struct HexString
{
	unsigned char *bin;
	size_t size;
};

struct HexString *HexString(void)
{
	struct HexString *hs;

	if ((hs = Mem_malloc(sizeof(*hs))) == NULL)
		return NULL;

	hs->bin = NULL;
	hs->size = 0;

	return hs;
}

void HexString_Free(struct HexString *hs)
{
	if (hs == NULL)
		return;

	Mem_free(hs->bin);
	Mem_free(hs);
}

static bool HexString_IsValid(const char *s)
{
	size_t l;

	if (s == NULL ||
	    (l = strlen(s)) % 2)
		return false;

	while (isxdigit(*s))
		s++;

	return (*s == '\0');
}

int HexString_Set(struct HexString *hs, const char *s)
{
	if (hs == NULL || s == NULL) {
		errno = EINVAL;
		return -1;
	} else if (!HexString_IsValid(s)) {
		errno = EBADE;
		return -1;
	}

	size_t l = strlen(s);
	uint8_t *b;

	if ((b = Mem_malloc(l / 2)) == NULL)
		return -1;

	hs->bin = b;
	hs->size = l / 2;

	while (*s) {
		uint8_t t;

		t = Str_Char2Hex(*s++) << 4;
		t |= Str_Char2Hex(*s++);

		*b++ = t;
	};

	return 0;
}

char *HexString_Get(struct HexString *hs)
{
	if (hs == NULL) {
		errno = EINVAL;
		return NULL;
	} else if (!hs->size) {
		errno = ENODATA;
		return NULL;
	}

	char *s;
	size_t s_size = hs->size * 2 + 1;

	if ((s = Mem_malloc(s_size)) == NULL)
		return NULL;

	char *p = s;
	for (size_t i = 0; i < hs->size; i++) {
		uint8_t t = hs->bin[i];

		*p++ = Str_Hex2Char((t & 0xf0) >> 4);
		*p++ = Str_Hex2Char(t & 0x0f);
	}

	*p = '\0';

	return s;
}

int HexString_SetBin(struct HexString *hs, const uint8_t *b, size_t s)
{
	if (hs == NULL || b == NULL || !s) {
		errno = EINVAL;
		return -1;
	}

	Mem_free(hs->bin);
	hs->size = 0;

	if ((hs->bin = Mem_malloc(s)) == NULL)
		return -1;

	memcpy(hs->bin, b, s);
	hs->size = s;

	return 0;
}

uint8_t *HexString_GetBin(struct HexString *hs, size_t *s)
{
	uint8_t *d;

	if (hs == NULL || s == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (!hs->size) {
		errno = ENODATA;
		return NULL;
	} else if ((d = Mem_malloc(hs->size)) == NULL) {
		return NULL;
	}

	memcpy(d, hs->bin, hs->size);
	*s = hs->size;

	return d;
}
