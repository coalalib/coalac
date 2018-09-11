#include <arpa/inet.h>
#include <ndm/macro.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <coala/Buf.h>
#include <coala/CoAPMessage.h>
#include <coala/Mem.h>
#include <coala/Uri.h>
#include <ndm/ip_sockaddr.h>

#include "Str.h"

struct CoAPMessage {
	uint8_t type;					/* 2 bits */
	uint8_t code;					/* 8 bits */
	uint16_t id;
	struct ndm_ip_sockaddr_t sa;
	uint8_t *payload;
	size_t payload_len;
	void *handler;
	struct CoAPMessage_OptionHead options_head;
	uint8_t token[COAP_MESSAGE_MAX_TOKEN_SIZE];	/* 0-8 bytes */
	uint8_t token_len;
	uint8_t refcount;
};

static volatile uint16_t message_id_counter;

void CoAPMessage_Init(void)
{
	message_id_counter = random() % UINT16_MAX;
}

/*
 * Создаёт новое сообщение.
 */
struct CoAPMessage *CoAPMessage(enum CoAPMessage_Type type,
				enum CoAPMessage_Code code,
				int id)
{
	struct CoAPMessage *m;

	m = Mem_calloc(1, sizeof *m);
	if (m == NULL)
		return NULL;

	m->type = type;
	m->code = code;
	m->refcount = 1;

	TAILQ_INIT(&m->options_head);

	m->id = (id == -1) ? CoAPMessage_GenId() : id;

	return m;
}

struct CoAPMessage *CoAPMessage_Clone(struct CoAPMessage *m, bool payload)
{
	int errsv = 0;
	size_t s;
	struct CoAPMessage *cp = NULL;
	struct CoAPMessage_Option *o;
	void *d;

	if (m == NULL) {
		errsv = EINVAL;
		goto out;
	}

	if ((cp = CoAPMessage(m->type, m->code, m->id)) == NULL) {
		errsv = errno;
		goto out;
	}

	if (m->token_len) {
		memcpy(cp->token, m->token, m->token_len);
		cp->token_len = m->token_len;
	}

	cp->sa = m->sa;

	TAILQ_FOREACH(o, &m->options_head, list) {
		struct CoAPMessage_Option *d;

		if ((d = CoAPMessage_OptionDup(o)) == NULL) {
			errsv = errno;
			goto out_decref;
		}

		TAILQ_INSERT_TAIL(&cp->options_head, d, list);
	}

	if (payload && (d = CoAPMessage_GetPayload(m, &s, 0))) {
		if (CoAPMessage_SetPayload(cp, d, s) < 0) {
			errsv = errno;
			goto out_decref;
		}
	}

	goto out;

out_decref:
	CoAPMessage_Decref(cp);
	cp = NULL;
out:
	if (errsv)
		errno = errsv;

	return cp;
}

/*
 * Уменьшает число ссылок на сообщение.
 */
void CoAPMessage_Decref(struct CoAPMessage *m)
{
	struct CoAPMessage_Option *o, *t;

	if (m == NULL)
		return;

	if (--m->refcount == 0) {
		Mem_free(m->payload);

		TAILQ_FOREACH_SAFE(o, &m->options_head, list, t) {
			TAILQ_REMOVE(&m->options_head, o, list);
			CoAPMessage_OptionFree(o);
		}

		Mem_free(m);
	}
}

/*
 * Увеличивает количество ссылок на сообщение.
 */
struct CoAPMessage *CoAPMessage_Incref(struct CoAPMessage *m)
{
	if (m)
		m->refcount++;

	return m;
}

uint16_t CoAPMessage_GenId(void)
{
	return message_id_counter++;
}

/*
 * Возвращает идентификатор сообщения.
 */
int CoAPMessage_GetId(struct CoAPMessage *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}

	return m->id;
}

int CoAPMessage_SetId(struct CoAPMessage *m, uint16_t id)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}

	m->id = id;

	return 0;
}

int CoAPMessage_GetType(struct CoAPMessage *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}

	return m->type;
}

const char *CoAPMessage_GetTypeStr(struct CoAPMessage *m)
{
	const char *a[] = {"CON", "NON", "ACK", "RST"};
	int type;

	if ((type = CoAPMessage_GetType(m)) < 0)
		return NULL;

	return a[type];
}

int CoAPMessage_SetType(struct CoAPMessage *m, enum CoAPMessage_Type type)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}

	m->type = type;

	return 0;
}

int CoAPMessage_GetCode(struct CoAPMessage *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}

	return m->code;
}

char *CoAPMessage_GetCodeStr(struct CoAPMessage *m, char *buf, size_t size)
{
	int code;

	if ((code = CoAPMessage_GetCode(m)) < 0)
		return NULL;

	return CoAPMessage_CodeStr(code, buf, size, CoAPMessage_CodeStr_Fmt3);
}

int CoAPMessage_SetCode(struct CoAPMessage *m, enum CoAPMessage_Code code)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}

	m->code = code;
	return 0;
}

/*
 * Возвращает рабочую нагрузку сообщения.
 */
uint8_t *CoAPMessage_GetPayload(struct CoAPMessage *m, size_t *size,
				unsigned flags)
{
	uint8_t *p;

	if (m == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if ((p = m->payload) == NULL) {
		errno = ENODATA;
		return NULL;
	}

	if (flags & CoAPMessage_GetPayload_Alloc) {
		bool zero = flags & CoAPMessage_GetPayload_Zero;
		size_t s = m->payload_len;

		if (zero)
			s++;

		if ((p = Mem_malloc(s)) == NULL)
			return NULL;

		memcpy(p, m->payload, m->payload_len);

		if (zero)
			p[s - 1] = '\0';
	}

	if (size)
		*size = m->payload_len;

	return p;
}

/*
 * Добавляет рабочую нагрузку заданного размера к сообщению.
 */
int CoAPMessage_SetPayload(struct CoAPMessage *m, const uint8_t *payload,
			   size_t size)
{
	uint8_t *p = NULL;

	if (m == NULL || (payload == NULL && size) || (payload && !size)) {
		errno = EINVAL;
		return -1;
	}

	if (payload) {
		if ((p = Mem_malloc(size)) == NULL)
			return -1;

		memcpy(p, payload, size);
	}

	Mem_free(m->payload);

	m->payload = p;
	m->payload_len = size;

	return 0;
}

int CoAPMessage_GenToken(uint8_t *token, size_t size)
{
	if (token == NULL || !size || size > COAP_MESSAGE_MAX_TOKEN_SIZE) {
		errno = EINVAL;
		return -1;
	}

	while (size--)
		*token++ = random() % UINT8_MAX;

	return 0;
}

/*
 * Устанавливает заданную метку в сообщении.
 */
int CoAPMessage_SetToken(struct CoAPMessage *m, const uint8_t *token,
			 size_t size)
{
	if (m == NULL || (token == NULL && size) || (token && !size ) ||
	    size > sizeof m->token) {
		errno = EINVAL;
		return -1;
	}

	if (token)
		memcpy(m->token, token, size);

	m->token_len = size;

	return 0;
}

/*
 * Возвращает метку сообщения в указанный буфер.
 */
int CoAPMessage_GetToken(struct CoAPMessage *m, uint8_t *token, size_t *size)
{
	if (m == NULL || token == NULL ||
	    size == NULL || *size < sizeof m->token) {
		errno = EINVAL;
		return -1;
	}

	if (!m->token_len) {
		errno = ENODATA;
		return -1;
	}

	memcpy(token, m->token, m->token_len);
	*size = m->token_len;

	return 0;
}

int CoAPMessage_CopyToken(struct CoAPMessage *d, struct CoAPMessage *s)
{
	size_t t_s;
	uint8_t t[COAP_MESSAGE_MAX_TOKEN_SIZE];

	if (d == NULL || s == NULL) {
		errno = EINVAL;
		return -1;
	}

	t_s = sizeof t;
	if (!CoAPMessage_GetToken(s, t, &t_s))
		return CoAPMessage_SetToken(d, t, t_s);
	else if (errno == ENODATA)
		return CoAPMessage_SetToken(d, NULL, 0);

	return -1;
}

static inline bool OptionCodeIsRepeatable(enum CoAPMessage_OptionCode code)
{
	switch (code) {
	case CoAPMessage_OptionCodeUriPath:
	case CoAPMessage_OptionCodeUriQuery:
	case CoAPMessage_OptionCodeLocationPath:
	case CoAPMessage_OptionCodeLocationQuery:
	case CoAPMessage_OptionCodeIfMatch:
	case CoAPMessage_OptionCodeEtag:
		return true;
	default:
		return false;
	}
}

/*
 * Добавляет заданную опцию к сообщению с пустым значением.
 */
int CoAPMessage_AddOptionEmpty(struct CoAPMessage *m,
			       enum CoAPMessage_OptionCode code)
{
	return CoAPMessage_AddOptionOpaque(m, code, NULL, 0);
}

/*
 * Добавляет заданную опцию к сообщению с строковым значением.
 */
int CoAPMessage_AddOptionString(struct CoAPMessage *m,
				enum CoAPMessage_OptionCode code,
				const char *s)
{
	if (s == NULL) {
		errno = EINVAL;
		return -1;
	}

	return CoAPMessage_AddOptionOpaque(m, code, (uint8_t *) s, strlen(s));
}

/*
 * Добавляет заданную опцию к сообщению с беззнаковым числом.
 */
int CoAPMessage_AddOptionUint(struct CoAPMessage *m,
			      enum CoAPMessage_OptionCode code,
			      uint32_t val)
{
	size_t len;
	uint8_t buf[4];

	if (!val) {
		len = 0;
	} else if (val <= UINT8_MAX) {
		buf[0] = val;
		len = 1;
	} else if (val <= UINT16_MAX) {
		uint16_t t = htons(val);
		memcpy(buf, &t, sizeof t);
		len = sizeof t;
	} else if (val <= 16777215) { /* 2^24 - 1 */
		uint32_t t = htonl(val);
		memcpy(buf, (unsigned char *)&t + 1, sizeof t - 1);
		len = sizeof t - 1;
	} else {
		uint32_t t = htonl(val);
		memcpy(buf, &t, sizeof t);
		len = sizeof t;
	}

	return CoAPMessage_AddOptionOpaque(m, code, buf, len);
}

struct CoAPMessage_Option *CoAPMessage_Option(enum CoAPMessage_OptionCode code,
					      const uint8_t *value,
					      size_t value_len)
{
	int errsv = 0;
	struct CoAPMessage_Option *o = NULL;
	uint8_t *v;

	o = Mem_calloc(1, sizeof(*o));
	if (o == NULL) {
		errsv = errno;
		goto out;
	}

	o->code = code;

	if (value_len) {
		v = Mem_malloc(value_len);
		if (v == NULL) {
			errsv = errno;
			goto out_free;
		}

		memcpy(v, value, value_len);
		o->value = v;
		o->value_len = value_len;
	}

	goto out;

out_free:
	Mem_free(o);
	o = NULL;
out:
	if (errsv)
		errno = errsv;

	return o;
}

struct CoAPMessage_Option *CoAPMessage_OptionDup(struct CoAPMessage_Option *o)
{
	if (o == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return CoAPMessage_Option(o->code, o->value, o->value_len);
}

void CoAPMessage_OptionFree(struct CoAPMessage_Option *o)
{
	if (o == NULL)
		return;

	Mem_free(o->value);
	Mem_free(o);
}

/*
 * Добавляет заданную опцию к сообщению.
 */
int CoAPMessage_AddOptionOpaque(struct CoAPMessage *m,
				enum CoAPMessage_OptionCode code,
				const uint8_t *data, size_t size)
{
	int res = -1;
	struct CoAPMessage_Option *o;

	if (m == NULL) {
		errno = EINVAL;
		goto out;
	}

	o = CoAPMessage_Option(code, data, size);
	if (o == NULL)
		goto out;

	if (!OptionCodeIsRepeatable(code))
		CoAPMessage_RemoveOptions(m, code);

	TAILQ_INSERT_TAIL(&m->options_head, o, list);
	res = 0;
out:
	return res;
}

/*
 * Удаляет все опции с заданным кодом.
 */
int CoAPMessage_RemoveOptions(struct CoAPMessage *m,
			      enum CoAPMessage_OptionCode code)
{
	bool deleted = false;
	struct CoAPMessage_Option *o, *t;

	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}

	TAILQ_FOREACH_SAFE(o, &m->options_head, list, t) {
		if (o->code != code)
			continue;

		TAILQ_REMOVE(&m->options_head, o, list);
		Mem_free(o->value);
		Mem_free(o);

		deleted = true;
	}

	if (!deleted) {
		errno = ENOENT;
		return -1;
	}

	return 0;
}

int CoAPMessage_CopyOption(struct CoAPMessage *dst,
			   struct CoAPMessage *src,
			   enum CoAPMessage_OptionCode code)
{
	size_t s = 0;
	uint8_t *d;

	if (dst == NULL || src == NULL) {
		errno = EINVAL;
		return -1;
	}

	if ((d = CoAPMessage_GetOptionOpaque(src, code, &s)) == NULL &&
	    errno != ENODATA)
		return -1;

	return CoAPMessage_AddOptionOpaque(dst, code, d, s);
}

#define COAP_VERSION			1
#define COAP_PAYLOAD_MARKER		0xff

#define OPT_DELTA_EXT_UCHAR_MAGIC	13
#define OPT_DELTA_EXT_UCHAR_MAX		(UINT8_MAX + OPT_DELTA_EXT_UCHAR_MAGIC)
#define OPT_DELTA_EXT_USHORT_MAGIC	14
#define OPT_DELTA_EXT_USHORT_MAX	(UINT16_MAX + OPT_DELTA_EXT_UCHAR_MAX)


static int CodeCmp(struct CoAPMessage_Option *a, struct CoAPMessage_Option *b)
{
	return a->code - b->code;
}

static inline bool NoNeedExtra(unsigned val)
{
	return val <= 12;
}

static inline bool NeedExtraByte(unsigned val)
{
	if (val >= 13 && val <= 13 + UINT8_MAX)
		return true;

	return false;
}

static inline bool NeedExtraShort(unsigned val)
{
	if (val >= 13 + UINT8_MAX + 1 && val <= 13 + UINT8_MAX + 1 + UINT16_MAX)
		return true;

	return false;
}

/*
   Message Format

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver| T |  TKL  |      Code     |          Message ID           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Token (if any, TKL bytes) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Options (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1 1 1 1 1 1 1 1|    Payload (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   See: https://tools.ietf.org/html/rfc7252#section-3
*/

/*
   Option Format

     0   1   2   3   4   5   6   7
   +---------------+---------------+
   |               |               |
   |  Option Delta | Option Length |   1 byte
   |               |               |
   +---------------+---------------+
   \                               \
   /         Option Delta          /   0-2 bytes
   \          (extended)           \
   +-------------------------------+
   \                               \
   /         Option Length         /   0-2 bytes
   \          (extended)           \
   +-------------------------------+
   \                               \
   /                               /
   \                               \
   /         Option Value          /   0 or more bytes
   \                               \
   /                               /
   \                               \
   +-------------------------------+

   See: https://tools.ietf.org/html/rfc7252#section-3.1
*/

uint8_t *CoAPMessage_ToBytes(struct CoAPMessage *m, size_t *size)
{
	struct Buf_Handle *b = NULL;
	struct CoAPMessage_Option *o;
	int errsv = 0;
	size_t s;
	uint8_t *res = NULL;
	uint16_t id;
	unsigned lastcode;
	unsigned char c;

	if (m == NULL) {
		errsv = EINVAL;
		goto out;
	}

	if ((b = Buf()) == NULL) {
		errsv = errno;
		goto out;
	}

	/* Fill header */
	c = COAP_VERSION << 6 | m->type << 4 | m->token_len;
	if (Buf_Add(b, &c, sizeof c) < 0) {
		errsv = errno;
		goto out;
	}

	c = m->code;
	if (Buf_Add(b, &c, sizeof c) < 0) {
		errsv = errno;
		goto out;
	}

	id = htons(m->id);
	if (Buf_Add(b, &id, sizeof id) < 0) {
		errsv = errno;
		goto out;
	}

	/* Token */
	if (m->token_len) {
		if (Buf_Add(b, m->token, m->token_len) < 0) {
			errsv = errno;
			goto out;
		}
	}

	/* Options */
	TAILQ_SORT(&m->options_head, CoAPMessage_Option, list, CodeCmp);

	lastcode = 0;
	TAILQ_FOREACH(o, &m->options_head, list) {
		int opt_delta, opt_length;
		unsigned char opt_delta_ext[2], opt_length_ext[2];
		size_t opt_delta_ext_len, opt_length_ext_len;

		/* Delta */
		opt_delta = o->code - lastcode;

		if (NoNeedExtra(opt_delta)) {
			opt_delta_ext_len = 0;
		} else if (NeedExtraByte(opt_delta)) {
			opt_delta_ext_len = 1;
			opt_delta_ext[0] = opt_delta - 13;

			opt_delta = 13;
		} else if (NeedExtraShort(opt_delta)) {
			uint16_t t = htons(opt_delta - 269);
			memcpy(opt_delta_ext, &t, sizeof t);
			opt_delta_ext_len = sizeof t;

			opt_delta = 14;
		} else {
			errsv = EBADMSG;
			goto out;
		}

		/* Length */
		opt_length = o->value_len;

		if (NoNeedExtra(opt_length)) {
			opt_length_ext_len = 0;
		} else if (NeedExtraByte(opt_length)) {
			opt_length_ext_len = 1;
			opt_length_ext[0] = opt_length - 13;

			opt_length = 13;
		} else if (NeedExtraShort(opt_length)) {
			uint16_t t = htons(opt_length - 269);
			memcpy(opt_length_ext, &t, sizeof t);
			opt_length_ext_len = sizeof t;

			opt_length = 14;
		} else {
			errsv = EBADMSG;
			goto out;
		}

		c = opt_delta << 4 | opt_length;
		if (Buf_Add(b, &c, sizeof c) < 0) {
			errsv = errno;
			goto out;
		}

		if (opt_delta_ext_len) {
			if (Buf_Add(b, opt_delta_ext, opt_delta_ext_len) < 0) {
				errsv = errno;
				goto out;
			}
		}

		if (opt_length_ext_len) {
			if (Buf_Add(b, opt_length_ext, opt_length_ext_len) < 0) {
				errsv = errno;
				goto out;
			}
		}

		/* Value */
		if (opt_length) {
			if (Buf_Add(b, o->value, o->value_len) < 0) {
				errsv = errno;
				goto out;
			}
		}

		lastcode = o->code;
	}

	/* Payload */
	if (m->payload_len) {
		c = COAP_PAYLOAD_MARKER;
		if (Buf_Add(b, &c, sizeof c) < 0) {
			errsv = errno;
			goto out;
		}

		if (Buf_Add(b, m->payload, m->payload_len) < 0) {
			errsv = errno;
			goto out;
		}
	}

	if ((res = Buf_GetData(b, &s, true)) == NULL)
		errsv = errno;

	if (size)
		*size = s;

out:
	Buf_Free(b);

	if (errsv)
		errno = errsv;

	return res;
}

#define COAP_FIXED_HEADER_SIZE	4

struct CoAPMessage *CoAPMessage_FromBytes(uint8_t *b, size_t size)
{
	struct CoAPMessage *m;
	unsigned code, token_len, type, ver;
	uint16_t id;

	if (b == NULL || !size) {
		errno = EINVAL;
		return NULL;
	}

	/* Fixed header */
	if (size < COAP_FIXED_HEADER_SIZE) {
		/*
		 * The message format starts with a fixed-size 4-byte header.
		 */
		errno = EBADMSG;
		return NULL;
	}

	ver = b[0] >> 6;
	type = b[0] >> 4 & 0x3;
	token_len = b[0] & 0xf;

	if (ver != COAP_VERSION || type >= CoAPMessage_TypeMax ||
	    token_len >= 9) {
		/*
		 * Lengths 9-15 are reserved, MUST NOT be sent, and MUST be
		 * processed as a message format error.
		 */
		errno = EBADMSG;
		return NULL;
	}

	code = b[1];
	id = ntohs(*(uint16_t *)&b[2]);

	m = CoAPMessage(type, code, id);
	if (m == NULL) {
		/* errno from CoAPMessage */
		return NULL;
	}

	size -= COAP_FIXED_HEADER_SIZE;
	b += COAP_FIXED_HEADER_SIZE;

	/* Token */
	if (token_len) {
		if (size < token_len) {
			CoAPMessage_Decref(m);
			errno = EBADMSG;
			return NULL;
		}

		CoAPMessage_SetToken(m, b, token_len);

		size -= token_len;
		b += token_len;
	}

	if (!size) {
		/* Message without options and payload */
		return m;
	}

	code = 0;
	while (size) {
		unsigned delta, length;

		if (*b == COAP_PAYLOAD_MARKER) {
			size--;
			b++;

			if (!size) {
				/*
				 * The presence of a marker followed by a
				 * zero-length payload MUST be processed as a
				 * message format error.
				 */
				CoAPMessage_Decref(m);
				errno = EBADMSG;
				return NULL;
			}

			break;
		}

		delta = *b >> 4;
		length = *b & 0xf;

		size--;
		b++;

		if ((delta == 0xf) ^ (length == 0xf)) {
			/*
			 * 15: If the field is set to this value but the entire
			 * byte is not the payload marker, this MUST be
			 * processed as a message format error.
			 */
			CoAPMessage_Decref(m);
			errno = EBADMSG;
			return NULL;
		}

		/* Delta */
		if (delta <= 12) {
			code += delta;
		} else if (delta == 13) {
			if (size < sizeof(uint8_t)) {
				CoAPMessage_Decref(m);
				errno = EBADMSG;
				return NULL;
			}

			code += *b + 13;

			size -= sizeof(uint8_t);
			b += sizeof(uint8_t);
		} else if (delta == 14) {
			if (size < sizeof(uint16_t)) {
				CoAPMessage_Decref(m);
				errno = EBADMSG;
				return NULL;
			}

			code += ntohs(*(uint16_t *)b) + 269;

			size -= sizeof(uint16_t);
			b += sizeof(uint16_t);
		}

		/* Length */
		if (length <= 12) {
			;
		} else if (length == 13) {
			if (size < sizeof(uint8_t)) {
				CoAPMessage_Decref(m);
				errno = EBADMSG;
				return NULL;
			}

			length = *b + 13;

			size -= sizeof(uint8_t);
			b += sizeof(uint8_t);
		} else if (length == 14) {
			if (size < sizeof(uint16_t)) {
				CoAPMessage_Decref(m);
				errno = EBADMSG;
				return NULL;
			}

			length = ntohs(*(uint16_t *)b) + 269;

			size -= sizeof(uint16_t);
			b += sizeof(uint16_t);
		}

		if (size < length) {
			errno = EBADMSG;
			return NULL;
		}

		if (CoAPMessage_AddOptionOpaque(m, code, b, length) < 0) {
			/* errno from CoAPMessage_AddOption */
			CoAPMessage_Decref(m);
			return NULL;
		}

		b += length;
		size -= length;
	}

	if (size) {
		if (CoAPMessage_SetPayload(m, b, size) < 0) {
			/* errno from CoAPMessage_SetPayload */
			CoAPMessage_Decref(m);
			m = NULL;
		}
	}

	return m;
}

/*
 * Сравнивает два сообщения.
 */
int CoAPMessage_Equals(struct CoAPMessage *m1, struct CoAPMessage *m2)
{
	int res = -1;
	size_t s1, s2;
	uint8_t *d1 = NULL, *d2 = NULL;

	if (m1 == NULL || m2 == NULL) {
		errno = EINVAL;
		goto out;
	}

	if (!ndm_ip_sockaddr_is_equal(&m1->sa, &m2->sa)) {
		res = 0;
		goto out;
	}

	if ((d1 = CoAPMessage_ToBytes(m1, &s1)) == NULL ||
	    (d2 = CoAPMessage_ToBytes(m2, &s2)) == NULL ) {
		/* errno from the func above */
		goto out;
	}

	res = 0;
	if (s1 == s2 && !memcmp(d1, d2, s1))
		res = 1;
out:
	Mem_free(d1);
	Mem_free(d2);
	return res;
}

int CoAPMessage_ToBuf(struct CoAPMessage *m, struct Buf_Handle *b)
{
	char buf[50];
	int ret;
	struct CoAPMessage_Option *o;

	if (b == NULL || m == NULL) {
		errno = EINVAL;
		return -1;
	}

	ret = Buf_AddFormatStr(b, "%s %s [id%hu]\n",
			       CoAPMessage_GetTypeStr(m),
			       CoAPMessage_GetCodeStr(m, buf, sizeof buf),
			       m->id);
	if (ret < 0)
		return -1;

	/* Token */
	if (m->token_len) {
		if (Buf_AddStr(b, "Token: ") < 0)
			return -1;

		if (Str_ArrIsPrintable(m->token, m->token_len)) {
			if (Buf_AddFormatStr(b, "\"%.*s\"\n",
					     m->token_len,
					     m->token) < 0) {
				return -1;
			}
		} else {
			for (int i = 0; i < m->token_len; i++) {
				if (Buf_AddFormatStr(b, "%02x ", m->token[i]) < 0)
					return -1;
			}

			if (Buf_AddCh(b, '\n') < 0)
				return -1;
		}
	}

	/* Options */
	TAILQ_FOREACH(o, &m->options_head, list) {
		if (Buf_AddFormatStr(b, "Code %d: ", o->code) < 0)
			return -1;

		if (!o->value_len) {
			if (Buf_AddStr(b, "empty") < 0)
				return -1;
		} else {
			if (Str_ArrIsPrintable(o->value, o->value_len)) {
				if (Buf_AddFormatStr(b, "\"%.*s\"", o->value_len, o->value) < 0)
					return -1;
			} else {
				for (unsigned i = 0; i < o->value_len; i++) {
					if (Buf_AddFormatStr(b, "%02x ", o->value[i]) < 0)
						return -1;
				}
			}
		}

		if (Buf_AddCh(b, '\n') < 0)
			return -1;
	}

	/* Payload */
	if (m->payload_len) {
		if (Buf_AddStr(b, "Payload: ") < 0)
			return -1;

		if (Str_ArrIsPrintable(m->payload, m->payload_len)) {
			if (Buf_AddFormatStr(b, "\"%.*s\"\n", m->payload_len, m->payload) < 0)
				return -1;
		} else {
			for (unsigned i = 0; i < m->payload_len; i++) {
				if (Buf_AddFormatStr(b, "%02x ", m->payload[i]) < 0)
					return -1;
			}

			if (Buf_AddCh(b, '\n') < 0)
				return -1;
		}
	}

	Buf_AddCh(b, '\0');

	return 0;
}

int CoAPMessage_Print(struct CoAPMessage *m, FILE *fp)
{
	struct Buf_Handle *b;

	b = Buf();
	if (b == NULL)
		return -1;

	if (CoAPMessage_ToBuf(m, b) < 0) {
		Buf_Free(b);
		return -1;
	}

	fputs(Buf_GetData(b, NULL, false), fp);
	Buf_Free(b);

	return 0;
}

extern uint8_t *CoAPMessage_GetOptionOpaque(struct CoAPMessage *m,
					    enum CoAPMessage_OptionCode code,
					    size_t *size)
{
	struct CoAPMessage_Option *o;

	if (m == NULL) {
		errno = EINVAL;
		return NULL;
	}

	TAILQ_FOREACH(o, &m->options_head, list) {
		if (o->code != code)
			continue;

		if (!o->value_len) {
			errno = ENODATA;
			return NULL;
		}

		if (size)
			*size = o->value_len;

		return o->value;

	}

	errno = ENOENT;
	return NULL;
}

char *CoAPMessage_GetOptionString(struct CoAPMessage *m,
				  enum CoAPMessage_OptionCode code,
				  size_t *len)
{
	uint8_t *d;
	size_t s;

	d = CoAPMessage_GetOptionOpaque(m, code, &s);
	if (d == NULL)
		return NULL;

	if (len)
		*len = s;

	return Mem_strndup((char *)d, s);
}

int CoAPMessage_GetOptionUint(struct CoAPMessage *m,
			      enum CoAPMessage_OptionCode code,
			      uint32_t *val)
{
	struct CoAPMessage_Option *o;
	uint32_t t = 0;

	/*
	 * TODO:
	 * Use CoAPMessage_GetOptionOpaque().
	 */

	if (m == NULL || val == NULL) {
		errno = EINVAL;
		return -1;
	}

	TAILQ_FOREACH(o, &m->options_head, list) {
		if (o->code != code)
			continue;

		switch (o->value_len) {
		case 0:
			*val = 0;
			break;
		case 1:
			*val = *(uint8_t *)o->value;
			break;
		case 2:
			*val = ntohs(*(uint16_t *)o->value);
			break;
		case 3:
			memcpy((uint8_t *)&t + 1, o->value, sizeof t - 1);
			*val = ntohl(t);
			break;
		case 4:
			*val = ntohl(*(uint32_t *)o->value);
			break;
		default:
			errno = EBADMSG;
			return -1;
		}

		return 0;
	}

	errno = ENOENT;
	return -1;
}

int CoAPMessage_IterOptions(struct CoAPMessage *m,
			    CoAPMessage_IterOptionsFunc f,
			    void *data)
{
	int ret;
	struct CoAPMessage_Option *o;

	if (m == NULL || f == NULL) {
		errno = EINVAL;
		return -1;
	}

	TAILQ_FOREACH(o, &m->options_head, list) {
		bool last = TAILQ_NEXT(o, list) ==
			    TAILQ_END(&m->options_head);

		ret = f(o->code, o->value, o->value_len, last, data);
		if (ret <= CoAPMessage_IterOptionsFuncStop)
			return ret;
	}

	return CoAPMessage_IterOptionsFuncOk;
}

int CoAPMessage_GetOptions(struct CoAPMessage *m,
			   enum CoAPMessage_OptionCode code,
			   struct CoAPMessage_OptionHead *h)
{
	bool exist = false;
	int res = -1;
	struct CoAPMessage_Option *o, *d;

	if (m == NULL || h == NULL) {
		errno = EINVAL;
		goto out;
	}

	TAILQ_FOREACH(o, &m->options_head, list) {
		if (o->code != code)
			continue;

		exist = true;

		if ((d = CoAPMessage_OptionDup(o)) == NULL) {
			int errsv = errno;
			CoAPMessage_GetOptionsFree(h);
			errno = errsv;
			goto out;
		}

		TAILQ_INSERT_TAIL(h, d, list);
	}

	res = 0;
	if (!exist) {
		errno = ENOENT;
		res = -1;
	}

out:
	return res;
}

void CoAPMessage_GetOptionsFree(struct CoAPMessage_OptionHead *h)
{
	struct CoAPMessage_Option *o, *t;

	if (h == NULL)
		return;

	TAILQ_FOREACH_SAFE(o, h, list, t)
		CoAPMessage_OptionFree(o);
}

char *CoAPMessage_GetUriPath(struct CoAPMessage *m, bool encode)
{
	char *res = NULL;
	int errsv = 0;
	struct Buf_Handle *b = NULL;
	struct CoAPMessage_Option *e;
	struct CoAPMessage_OptionHead h = TAILQ_HEAD_INITIALIZER(h);

	if (m == NULL) {
		errsv = EINVAL;
		goto out;
	} else if ((b = Buf()) == NULL) {
		errsv = errno;
		goto out;
	}

	if (CoAPMessage_GetOptions(m, CoAPMessage_OptionCodeUriPath, &h) < 0) {
		errsv = errno;
		goto out;
	}

	TAILQ_FOREACH(e, &h, list) {
		if (Buf_AddCh(b, '/') < 0 ||
		    Buf_Add(b, e->value, e->value_len) < 0) {
			errsv = errno;
			goto out;
		}
	}

	if (Buf_AddCh(b, '\0') < 0) {
		errsv = errno;
		goto out;
	}

	if (encode) {
		char *s = Buf_GetData(b, NULL, false);
		if (s == NULL ||
		    (res = Uri_EncodePath(s)) == NULL) {
			errsv = errno;
			goto out;
		}
	} else if ((res = Buf_GetData(b, NULL, true)) == NULL) {
		errsv = errno;
	}

out:
	CoAPMessage_GetOptionsFree(&h);
	Buf_Free(b);

	if (errsv)
		errno = errsv;

	return res;
}

char *CoAPMessage_GetUriQuery(struct CoAPMessage *m, bool encode)
{
	char *res = NULL, *d;
	int errsv = 0;
	size_t s;
	struct Buf_Handle *b = NULL;
	struct CoAPMessage_Option *e;
	struct CoAPMessage_OptionHead h = TAILQ_HEAD_INITIALIZER(h);

	if (m == NULL) {
		errsv = EINVAL;
		goto out;
	} else if ((b = Buf()) == NULL) {
		errsv = errno;
		goto out;
	}

	if (CoAPMessage_GetOptions(m, CoAPMessage_OptionCodeUriQuery, &h) < 0) {
		errsv = errno;
		goto out;
	}

	if (Buf_AddCh(b, '?') < 0) {
		errsv = errno;
		goto out;
	}

	TAILQ_FOREACH(e, &h, list) {
		if (Buf_Add(b, e->value, e->value_len) < 0 ||
		    Buf_AddCh(b, '&') < 0) {
			errno = errsv;
			goto out;
		}
	}

	/* Replace the trailing '&' with zero */
	d = Buf_GetData(b, &s, false);
	d[s - 1] = '\0';

	if (encode) {
		if ((res = Uri_EncodeQuery(d, true)) == NULL)
			errsv = errno;
	} else if ((res = Buf_GetData(b, NULL, true)) == NULL) {
		errsv = errno;
	}

out:
	CoAPMessage_GetOptionsFree(&h);
	Buf_Free(b);

	if (errsv)
		errno = errsv;

	return res;
}

int CoAPMessage_SetUriPath(struct CoAPMessage *m, const char *path)
{
	int errsv = 0, res = -1;
	struct Uri_ParsePathEntry *e;
	struct Uri_ParsePathHead h = STAILQ_HEAD_INITIALIZER(h);

	if (m == NULL) {
		errsv = EINVAL;
		goto out;
	}

	if (Uri_ParsePath(&h, path) < 0) {
		errsv = errno;
		goto out_parse_path_free;
	}

	CoAPMessage_RemoveOptions(m, CoAPMessage_OptionCodeUriPath);

	STAILQ_FOREACH(e, &h, list) {
		if (CoAPMessage_AddOptionString(
					m,
					CoAPMessage_OptionCodeUriPath,
					e->s) < 0) {
			errsv = errno;
			goto out_parse_path_free;
		}
	}

	res = 0;

out_parse_path_free:
	Uri_ParsePathFree(&h);
out:
	if (errsv)
		errno = errsv;

	return res;
}

int CoAPMessage_SetUriQuery(struct CoAPMessage *m, const char *query)
{
	int errsv = 0, res = -1;
	struct Uri_ParseQueryEntry *e;
	struct Uri_ParseQueryHead h = STAILQ_HEAD_INITIALIZER(h);

	if (m == NULL) {
		errsv = EINVAL;
		goto out;
	}

	if (Uri_ParseQuery(&h, query, false) < 0) {
		errsv = errno;
		goto out_parse_query_free;
	}

	CoAPMessage_RemoveOptions(m, CoAPMessage_OptionCodeUriQuery);

	STAILQ_FOREACH(e, &h, list) {
		if (CoAPMessage_AddOptionString(
					m,
					CoAPMessage_OptionCodeUriQuery,
					e->key) < 0) {
			errsv = errno;
			goto out_parse_query_free;
		}
	}

	res = 0;

out_parse_query_free:
	Uri_ParseQueryFree(&h);
out:
	if (errsv)
		errno = errsv;

	return res;
}

int CoAPMessage_SetSecure(struct CoAPMessage *m, bool on)
{
	enum CoAPMessage_OptionCode c = CoAPMessage_OptionCodeUriScheme;

	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}

	CoAPMessage_RemoveOptions(m, c);
	if (on && CoAPMessage_AddOptionUint(m, c, 1) < 0)
		return -1;

	return 0;
}

int CoAPMessage_GetSecure(struct CoAPMessage *m, bool *on)
{
	enum CoAPMessage_OptionCode c = CoAPMessage_OptionCodeUriScheme;
	uint32_t v = 0;

	if (m == NULL || on == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (CoAPMessage_GetOptionUint(m, c, &v) < 0 &&
	    errno != ENOENT)
		return -1;

	*on = v ? true : false;

	return 0;
}

int CoAPMessage_SetUri(struct CoAPMessage *m, const char *uri, unsigned flags)
{
	int res = -1;
	struct Uri u;

	if (m == NULL || uri == NULL || *uri == '\0') {
		errno = EINVAL;
		goto out;
	}

	if (!flags)
		flags = ~0;

	if (Uri_Parse(&u, uri) < 0)
		goto out;

	if (flags & CoAPMessage_SetUri_OnlySecure)
		if (CoAPMessage_SetSecure(m, u.secure) < 0)
			goto out_parse_free;

	CoAPMessage_RemoveOptions(m, CoAPMessage_OptionCodeUriHost);

	/* Try IPv4 */
	if (flags & CoAPMessage_SetUri_OnlyIpPort) {
		bool ipv4 = false, ipv6 = false;
		struct ndm_ip_sockaddr_t sa;
		struct sockaddr_in in;

		memset(&in, 0, sizeof in);
		in.sin_family = AF_INET;
		in.sin_port = htons(u.port);

		ndm_ip_sockaddr_assign(&sa, &in);
		ipv4 = ndm_ip_sockaddr_pton(u.host, &sa);

		if (ipv4) {
			CoAPMessage_SetSockAddr(m, &sa);
		} else {
			/* Try IPv6 */
			struct sockaddr_in6 in6;

			memset(&in6, 0, sizeof in6);
			in6.sin6_family = AF_INET6;
			in6.sin6_port = htons(u.port);

			ndm_ip_sockaddr_assign6(&sa, &in6);
			ipv6 = ndm_ip_sockaddr_pton(u.host, &sa);

			if (ipv6) {
				CoAPMessage_SetSockAddr(m, &sa);
			} else {
				/* Try to resolve */
				int ret;
				struct addrinfo *res, hints = {
					.ai_family = AF_INET
				};

				ret = getaddrinfo(u.host, NULL, &hints, &res);
				if (ret != 0) {
					errno = EADDRNOTAVAIL;
					goto out_parse_free;
				}

				ndm_ip_sockaddr_assign(&sa,
					(struct sockaddr_in *)res->ai_addr);
				ndm_ip_sockaddr_set_port(&sa, u.port);

				CoAPMessage_SetSockAddr(m, &sa);
				freeaddrinfo(res);

				if (CoAPMessage_AddOptionString(m,
						CoAPMessage_OptionCodeUriHost,
						u.host) < 0) {
					goto out_parse_free;
				}
			}
		}
	}

	if (flags & CoAPMessage_SetUri_OnlyPath) {
		if (u.path == NULL)
			CoAPMessage_RemoveOptions(m,
					CoAPMessage_OptionCodeUriPath);
		else if (CoAPMessage_SetUriPath(m, u.path) < 0)
			goto out_parse_free;
	}

	if (flags & CoAPMessage_SetUri_OnlyQuery) {
		if (u.query == NULL)
			CoAPMessage_RemoveOptions(m,
					CoAPMessage_OptionCodeUriQuery);
		else if (CoAPMessage_SetUriQuery(m, u.query) < 0)
			goto out_parse_free;
	}

	res = 0;

out_parse_free:
	Uri_ParseFree(&u);
out:
	return res;
}

char *CoAPMessage_GetUri(struct CoAPMessage *m, bool encode)
{
	char *res = NULL, *s;
	int errsv = 0;
	struct Uri u = {};
	uint32_t port;

	if (m == NULL) {
		errsv = EINVAL;
		goto out;
	}

	if ((s = CoAPMessage_GetUriPath(m, encode)) == NULL &&
	    errno != ENOENT) {
		errsv = errno;
		goto out;
	}
	u.path = s;

	if ((s = CoAPMessage_GetUriQuery(m, encode)) == NULL &&
	    errno != ENOENT) {
		errsv = errno;
		goto out;
	}
	u.query = s;

	struct ndm_ip_sockaddr_t sa;
	if (CoAPMessage_GetSockAddr(m, &sa) < 0) {
		errsv = errno;
		goto out;
	}
	u.port = ndm_ip_sockaddr_port(&sa);

	if (!CoAPMessage_GetOptionUint(m, CoAPMessage_OptionCodeUriPort,
				       &port)) {
		u.port = port;
	} else if (errno != ENOENT) {
		errsv = errno;
		goto out;
	}

	char a[NDM_IP_SOCKADDR_LEN];
	if (ndm_ip_sockaddr_ntop(&sa, a, sizeof a) == NULL ||
	    (u.host = Mem_strdup(a)) == NULL) {
		errsv = errno;
		goto out;
	}

	if ((s = CoAPMessage_GetOptionString(m, CoAPMessage_OptionCodeUriHost,
					     NULL))) {
		Mem_free(u.host);
		u.host = s;
	} else if (errno != ENOENT) {
		errsv = errno;
		goto out;
	}

	if (CoAPMessage_GetSecure(m, &u.secure) < 0) {
		errsv = errno;
		goto out;
	}

	if ((res = Uri_Gen(&u)) == NULL)
		errsv = errno;

out:
	Mem_free(u.host);
	Mem_free(u.path);
	Mem_free(u.query);

	if (errsv)
		errno = errsv;

	return res;
}

int CoAPMessage_AddOptionBlock(struct CoAPMessage *m,
			       enum CoAPMessage_OptionCode code,
			       struct CoAPMessage_Block *b)
{
	uint32_t val = 0;

	if (m == NULL || b == NULL) {
		errno = EINVAL;
		return -1;
	}

	CoAPMessage_RemoveOptions(m, code);

	val = b->szx | b->m << 3 | b->num << 4;

	return CoAPMessage_AddOptionUint(m, code, val);
}

int CoAPMessage_GetOptionBlock(struct CoAPMessage *m,
			       enum CoAPMessage_OptionCode code,
			       struct CoAPMessage_Block *b)
{
	uint32_t val;

	if (m == NULL || b == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (CoAPMessage_GetOptionUint(m, code, &val) < 0)
		return -1;

	memset(b, 0, sizeof(*b));

	b->num = val >> 4;
	b->szx = val & 7;
	b->m = val & 8;

	return 0;
}

int CoAPMessage_GetSockAddr(struct CoAPMessage *m,
			    struct ndm_ip_sockaddr_t *sa)
{
	if (m == NULL || sa == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (!(ndm_ip_sockaddr_is_v4(&m->sa) ||
	      ndm_ip_sockaddr_is_v6(&m->sa))) {
		errno = ENODATA;
		return -1;
	}

	*sa = m->sa;

	return 0;
}

int CoAPMessage_SetSockAddr(struct CoAPMessage *m,
			    struct ndm_ip_sockaddr_t *sa)
{
	if (m == NULL || sa == NULL ||
	    !(ndm_ip_sockaddr_is_v4(sa) ||
	      ndm_ip_sockaddr_is_v6(sa))) {
		errno = EINVAL;
		return -1;
	}

	m->sa = *sa;

	return 0;
}

int CoAPMessage_CopySockAddr(struct CoAPMessage *d, struct CoAPMessage *s)
{
	if (d == NULL || s == NULL) {
		errno = EINVAL;
		return -1;
	}

	d->sa = s->sa;

	return 0;
}

static struct {
	enum CoAPMessage_OptionCode code;
	const char *s;
} OptionCodeStr[] = {
	{
		CoAPMessage_OptionCodeIfMatch,
		"If-Match"
	}, {
		CoAPMessage_OptionCodeUriHost,
		"Uri-Host"
	}, {
		CoAPMessage_OptionCodeEtag,
		"ETag"
	}, {
		CoAPMessage_OptionCodeIfNoneMatch,
		"If-None-Match"
	}, {
		CoAPMessage_OptionCodeObserve,
		"Observe"
	}, {
		CoAPMessage_OptionCodeUriPort,
		"Uri-Port"
	}, {
		CoAPMessage_OptionCodeLocationPath,
		"Location-Path"
	}, {
		CoAPMessage_OptionCodeUriPath,
		"Uri-Path"
	}, {
		CoAPMessage_OptionCodeContentFormat,
		"Content-Format"
	}, {
		CoAPMessage_OptionCodeMaxAge,
		"Max-Age"
	}, {
		CoAPMessage_OptionCodeUriQuery,
		"Uri-Query"
	}, {
		CoAPMessage_OptionCodeAccept,
		"Accept"
	}, {
		CoAPMessage_OptionCodeLocationQuery,
		"Location-Query"
	}, {
		CoAPMessage_OptionCodeBlock2,
		"Block2"
	}, {
		CoAPMessage_OptionCodeBlock1,
		"Block1"
	}, {
		CoAPMessage_OptionCodeSize2,
		"Size2"
	}, {
		CoAPMessage_OptionCodeProxyUri,
		"Proxy-Uri"
	}, {
		CoAPMessage_OptionCodeProxyScheme,
		"Proxy-Scheme"
	}, {
		CoAPMessage_OptionCodeSize1,
		"Size1"
	}, {
		CoAPMessage_OptionCodeUriScheme,
		"Uri-Scheme"
	}, {
		CoAPMessage_OptionCodeSelectiveRepeatWindowSize,
		"Selective-Repeat-Window-Size"
	}, {
		CoAPMessage_OptionCodeHandshakeType,
		"Handshake-Type"
	}, {
		CoAPMessage_OptionCodeSessionNotFound,
		"Session-Not-Found"
	}, {
		CoAPMessage_OptionCodeSessionExpired,
		"Session-Expired"
	}, {
		CoAPMessage_OptionCodeCoapsUri,
		"Coaps-Uri"
	}
};

char *CoAPMessage_OptionCodeStr(enum CoAPMessage_OptionCode code, char *buf,
				size_t size)
{
	for (size_t i = 0; i < NDM_ARRAY_SIZE(OptionCodeStr); i++) {
		if (code == OptionCodeStr[i].code) {
			strncpy(buf, OptionCodeStr[i].s, size - 1);
			buf[size - 1] = '\0';
			return buf;
		}
	}

	snprintf(buf, size, "0x%x", (unsigned)code);
	return buf;
}

int CoAPMessage_SetHandler(struct CoAPMessage *m, CoAPMessage_Handler_t h)
{
	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}

	m->handler = h;

	return 0;
}

CoAPMessage_Handler_t CoAPMessage_GetHandler(struct CoAPMessage *m)
{
	if (m == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (m->handler == NULL)
		errno = ENODATA;

	return m->handler;
}

static struct {
	enum CoAPMessage_Code code;
	const char *s;
} CodeStr[] = {
	/* Request */
	{
		CoAPMessage_CodeEmpty,
		"Empty",
	}, {
		CoAPMessage_CodeGet,
		"Get"
	}, {
		CoAPMessage_CodePost,
		"Post"
	}, {
		CoAPMessage_CodePut,
		"Put"
	}, {
		CoAPMessage_CodeDelete,
		"Delete"
	},
	/* Response */
	{
		CoAPMessage_CodeCreated,
		"Created"
	}, {
		CoAPMessage_CodeDeleted,
		"Deleted"
	}, {
		CoAPMessage_CodeValid,
		"Valid"
	}, {
		CoAPMessage_CodeChanged,
		"Changed"
	}, {
		CoAPMessage_CodeContent,
		"Content"
	}, {
		CoAPMessage_CodeContinue,
		"Continue"
	}, {
		CoAPMessage_CodeBadRequest,
		"Bad request"
	}, {
		CoAPMessage_CodeUnauthorized,
		"Unauthorized"
	}, {
		CoAPMessage_CodeBadOption,
		"Bad option"
	}, {
		CoAPMessage_CodeForbidden,
		"Forbidden"
	}, {
		CoAPMessage_CodeNotFound,
		"Not Found"
	}, {
		CoAPMessage_CodeMethodNotAllowed,
		"Method not allowed"
	}, {
		CoAPMessage_CodeNotAcceptable,
		"Not acceptable"
	}, {
		CoAPMessage_CodeRequestEntityIncomplete,
		"Request entity incomplete"
	}, {
		CoAPMessage_CodePreconditionFailed,
		"Precondition failed"
	}, {
		CoAPMessage_CodeRequestEntityTooLarge,
		"Request entity too large"
	}, {
		CoAPMessage_CodeUnsupportedContentFormat,
		"Unsupported content format"
	}, {
		CoAPMessage_CodeInternalServerError,
		"Internal server error"
	}, {
		CoAPMessage_CodeNotImplemented,
		"Not implemented"
	}, {
		CoAPMessage_CodeBadGateway,
		"Bad gateway"
	}, {
		CoAPMessage_CodeServiceUnavailable,
		"Service unavailable"
	}, {
		CoAPMessage_CodeGatewayTimeout,
		"Gateway timeout"
	}, {
		CoAPMessage_CodeProxyingNotSupported,
		"Proxying not supported"
	}
};

char *CoAPMessage_CodeStr(enum CoAPMessage_Code code, char *buf, size_t size,
			  enum CoAPMessage_CodeStr_Fmt fmt)
{
	char code_s[sizeof "0.00"];
	const char *s = NULL;

	if (buf == NULL || !size) {
		errno = EINVAL;
		return NULL;
	}

	if (fmt) {
		for (size_t i = 0; i < NDM_ARRAY_SIZE(CodeStr); i++) {
			if (code == CodeStr[i].code) {
				s = CodeStr[i].s;
				break;
			}
		}
	}

	snprintf(code_s, sizeof code_s, "%u.%02u", code >> 5, code & 0x1f);

	if (s == NULL) {
		strncpy(buf, code_s, size - 1);
		buf[size - 1] = '\0';
	} else if (fmt == CoAPMessage_CodeStr_Fmt2) {
		strncpy(buf, s, size - 1);
		buf[size - 1] = '\0';
	} else if (fmt == CoAPMessage_CodeStr_Fmt3) {
		snprintf(buf, size, "%s (%s)", code_s, s);
	}

	return buf;
}

bool CoAPMessage_IsMulticast(struct CoAPMessage *m)
{
	struct ndm_ip_sockaddr_t sa;

	if (CoAPMessage_GetSockAddr(m, &sa) < 0)
		return false;

	return IN_MULTICAST(ntohl(sa.un.in.sin_addr.s_addr));
}
