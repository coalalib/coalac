#define _GNU_SOURCE

#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <regex.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <coala/Buf.h>
#include <coala/Mem.h>
#include <coala/Uri.h>
#include <coala/queue.h>

#include "Str.h"

/*
 * Simple URI parser.
 */

#define PORT_DEFAULT	5683

enum {
	MATCH_FULL,
	MATCH_SCHEME,
	MATCH_HOST,
	MATCH_PORT,
	MATCH_PATH,
	MATCH_QUERY,
	MATCH_MAX
};

int Uri_Parse(struct Uri *u, const char *uri)
{
	int errsv = 0, res = -1, ret, so, eo;
	regex_t reg;
	regmatch_t match[MATCH_MAX];

	/*
	 * TODO: Support URI with IPv6 addresses
	 */
	if (u == NULL || uri == NULL || *uri == '\0') {
		errsv = EINVAL;
		goto out;
	}

	memset(u, 0, sizeof(*u));

	ret = regcomp(&reg, "^coap(s)?://"
			    "([^:/?#]+)"	/* host */
			    "(:[0-9]{1,5})?"	/* port */
			    "(/[^?#]+)?/?"	/* path */
			    "(\\?[^#]+)?"	/* query */
			    "(#.+)?$",		/* fragment */
			    REG_EXTENDED);
	if (ret) {
		errsv = EBADF;
		goto out_regfree;
	}

	ret = regexec(&reg, uri, MATCH_MAX, match, 0);
	if (ret) {
		errsv = EBADE;
		goto out_regfree;
	}

	so = match[MATCH_SCHEME].rm_so;
	if (so != -1)
		u->secure = true;

	so = match[MATCH_HOST].rm_so;
	eo = match[MATCH_HOST].rm_eo;
	if ((u->host = Mem_strndup(uri + so, eo - so)) == NULL)
		goto out_regfree;

	so = match[MATCH_PORT].rm_so;
	eo = match[MATCH_PORT].rm_eo;
	if (so == -1) {
		u->port = PORT_DEFAULT;
	} else {
		char *e;
		const char *s = uri + so + 1; /* Skip colon */
		unsigned long t;

		t = strtoul(s, &e, 10);
		if (e != uri + eo || t > UINT16_MAX) {
			errsv = EBADE;
			goto out_free;
		}

		u->port = t;
	}

	so = match[MATCH_PATH].rm_so;
	eo = match[MATCH_PATH].rm_eo;
	if (so != -1) {
		/* Skip trailing slash */
		if (*(uri + eo - 1) == '/')
			eo--;

		if ((u->path = Mem_strndup(uri + so, eo - so)) == NULL)
			goto out_free;
	}

	so = match[MATCH_QUERY].rm_so;
	eo = match[MATCH_QUERY].rm_eo;
	if (so != -1) {
		if ((u->query = Mem_strndup(uri + so, eo - so)) == NULL)
			goto out_free;
	}

	res = 0;
	goto out_regfree;

out_free:
	Mem_free(u->host);
	Mem_free(u->path);
	Mem_free(u->query);
out_regfree:
	regfree(&reg);
out:
	if (errsv)
		errno = errsv;

	return res;
}

void Uri_ParseFree(struct Uri *u)
{
	if (u == NULL)
		return;

	Mem_free(u->host);
	Mem_free(u->path);
	Mem_free(u->query);
}

int Uri_ParsePath(struct Uri_ParsePathHead *head, const char *path)
{
	char *path_dec = NULL;
	const char *p, *q;
	int errsv = 0, res = -1;

	if (head == NULL || path == NULL || *path != '/') {
		errsv = EINVAL;
		goto out;
	}

	path++;

	path_dec = Uri_DecodeStr(path);
	if (path_dec == NULL) {
		errsv = errno;
		goto out;
	}

	p = q = path_dec;
	while (true) {
		if (*p == '/' || *p == '\0') {
			size_t n = p - q;
			struct Uri_ParsePathEntry *e;

			if (n) {
				e = Mem_calloc(1, sizeof(*e));
				if (e == NULL ||
				    (e->s = Mem_strndup(q, n)) == NULL) {
					errsv = errno;
					Mem_free(e);
					goto out_free;
				}

				STAILQ_INSERT_TAIL(head, e, list);
			}
			q = p + 1;
		}

		if (*p == '\0')
			break;
		p++;
	}

	res = 0;
	goto out;

out_free:
	Uri_ParsePathFree(head);
out:
	Mem_free(path_dec);

	if (errsv)
		errno = errsv;

	return res;
}

void Uri_ParsePathFree(struct Uri_ParsePathHead *head)
{
	struct Uri_ParsePathEntry *e, *t;

	if (head == NULL)
		return;

	STAILQ_FOREACH_SAFE(e, head, list, t) {
		STAILQ_REMOVE(head, e, Uri_ParsePathEntry, list);
		Mem_free(e->s);
		Mem_free(e);
	}
}

int Uri_ParseQuery(struct Uri_ParseQueryHead *head, const char *query,
		   bool parse_key_value)
{
	char *query_dec = NULL;
	const char *p, *q;
	int errsv = 0, res = -1;

	if (head == NULL || query == NULL || *query != '?') {
		errsv = EINVAL;
		goto out;
	}

	query++;

	query_dec = Uri_DecodeStr(query);
	if (query_dec == NULL) {
		errsv = errno;
		goto out;
	}

	p = q = query_dec;
	while (true) {
		if (*p == '&' || *p == '\0') {
			size_t n = p - q;
			struct Uri_ParseQueryEntry *e;

			if (n) {
				const char *v;

				if ((e = Mem_calloc(1, sizeof(*e))) == NULL)
					goto out_free;

				if (parse_key_value) {
					v = Str_strnchr(q, n, '=');
					if (v) {
						size_t value_len;
						n = v - q;
						v++;

						value_len = p - v;
						if (value_len &&
						    (e->value = Mem_strndup(v, value_len)) == NULL) {
							errsv = errno;
							Mem_free(e);
							goto out_free;
						}
					}
				}

				if ((e->key = Mem_strndup(q, n)) == NULL) {
					errsv = errno;
					Mem_free(e);
					goto out_free;
				}

				STAILQ_INSERT_TAIL(head, e, list);
			}
			q = p + 1;
		}

		if (*p == '\0')
			break;
		p++;
	}

	res = 0;
	goto out;

out_free:
	Uri_ParseQueryFree(head);
out:
	Mem_free(query_dec);

	if (errsv)
		errno = errsv;

	return res;
}

void Uri_ParseQueryFree(struct Uri_ParseQueryHead *head)
{
	struct Uri_ParseQueryEntry *e, *t;

	if (head == NULL)
		return;

	STAILQ_FOREACH_SAFE(e, head, list, t) {
		STAILQ_REMOVE(head, e, Uri_ParseQueryEntry, list);
		Mem_free(e->key);
		Mem_free(e->value);
		Mem_free(e);
	}
}

char *Uri_EncodeStr(const char *s)
{
	char *r, *rp;

	if (s == NULL || *s == '\0') {
		errno = EINVAL;
		return NULL;
	}

	if ((r = Mem_malloc(strlen(s) * 3 + 1)) == NULL)
		return NULL;

	rp = r;

	while (*s) {
		if (isalnum(*s) || *s == '-' || *s == '_' || *s == '.' || *s == '~') {
			*rp++ = *s;
		} else if (*s == ' ') {
			*rp++ = '+';
		} else {
			*rp++ = '%';
			*rp++ = toupper(Str_Hex2Char(*s >> 4));
			*rp++ = toupper(Str_Hex2Char(*s & 0xf));
		}

		s++;
	}

	*rp = '\0';

	return r;
}

char *Uri_DecodeStr(const char *s)
{
	char *r, *rp;

	if (s == NULL || *s == '\0') {
		errno = EINVAL;
		return NULL;
	}

	if ((r = Mem_malloc(strlen(s) + 1)) == NULL)
		return NULL;

	rp = r;

	while (*s) {
		if (*s == '%') {
			if (isxdigit(*(s + 1)) && isxdigit(*(s + 2))) {
				unsigned char t;
				t = Str_Char2Hex(*(s + 1)) << 4;
				t |= Str_Char2Hex(*(s + 2));
				*rp++ = t;
				s += 2;
			} else {
				Mem_free(r);
				errno = EBADMSG;
				return NULL;
			}
		} else if (*s == '+') {
			*rp++ = ' ';
		} else {
			*rp++ = *s;
		}

		s++;
	}

	*rp = '\0';

	return r;
}

char *Uri_Gen(struct Uri *u)
{
	char port[sizeof ":65535"] = "";
	char *res = NULL, *s;
	int errsv = 0;

	if (u == NULL ||
	    u->host == NULL || *u->host == '\0' ||
	    (u->path && *u->path != '/') ||
	    (u->query && *u->query != '?')) {
		errno = EINVAL;
		goto out;
	}

	if (u->port != PORT_DEFAULT)
		sprintf(port, ":%u", (unsigned)u->port);

	if (asprintf(&s, "%s://%s%s%s%s", u->secure ? "coaps" : "coap",
					   u->host,
					   port,
					   u->path ? u->path : "",
					   u->query ? u->query : "") < 0) {
		errno = ENOMEM;
		goto out;
	}

	res = s;
out:
	if (errsv)
		errno = errsv;

	return res;
}

char *Uri_EncodePath(const char *path)
{
	char *pathd = NULL, *res = NULL, *saveptr;
	int errsv = 0;
	struct Buf_Handle *b = NULL;

	if (path == NULL || *path != '/') {
		errsv = EINVAL;
		goto out;
	}

	path++;

	if ((pathd = Mem_strdup(path)) == NULL) {
		errsv = errno;
		goto out;
	}

	if ((b = Buf()) == NULL) {
		errsv = errno;
		goto out;
	}

	for (char *s = pathd; ; s = NULL) {
		char *it, *it_enc;

		if ((it = strtok_r(s, "/", &saveptr)) == NULL)
			break;

		if ((it_enc = Uri_EncodeStr(it)) == NULL) {
			errsv = errno;
			goto out;
		}

		if (Buf_AddCh(b, '/') < 0 ||
		    Buf_AddStr(b, it_enc) < 0) {
			errsv = errno;
			Mem_free(it_enc);
			goto out;
		}

		Mem_free(it_enc);
	}

	if (Buf_AddCh(b, '\0') < 0) {
		errsv = errno;
		goto out;
	}

	if ((res = Buf_GetData(b, NULL, true)) == NULL)
		errsv = errno;

out:
	Mem_free(pathd);
	Buf_Free(b);

	if (errsv)
		errno = errsv;

	return res;
}

char *Uri_EncodeQuery(const char *query, bool encode_key_value)
{
	char *res = NULL, *saveptr, *queryd = NULL;
	int errsv = 0;
	size_t s;
	struct Buf_Handle *b = NULL;

	if (query == NULL || *query != '?') {
		errsv = EINVAL;
		goto out;
	}

	query++;

	if ((queryd = Mem_strdup(query)) == NULL) {
		errsv = errno;
		goto out;
	}

	if ((b = Buf()) == NULL ||
	    Buf_AddCh(b, '?') < 0) {
		errsv = errno;
		goto out;
	}

	for (char *s = queryd; ; s = NULL) {
		char *it, *t;

		if ((it = strtok_r(s, "&", &saveptr)) == NULL)
			break;

		if (encode_key_value && (t = strchr(it, '='))) {
			char *key = it, *val = t + 1;
			char *key_enc = NULL, *val_enc = NULL;

			*t = '\0';

			if ((key_enc = Uri_EncodeStr(key)) == NULL ||
			    (val_enc = Uri_EncodeStr(val)) == NULL ||
			    Buf_AddFormatStr(b, "%s=%s", key_enc, val_enc) < 0) {
				errsv = errno;
				Mem_free(key_enc);
				Mem_free(val_enc);
				goto out;
			}

			Mem_free(key_enc);
			Mem_free(val_enc);
		} else {
			char *it_enc = Uri_EncodeStr(it);
			if (it_enc == NULL) {
				errsv = errno;
				goto out;
			}

			if (Buf_AddStr(b, it_enc) < 0) {
				errsv = errno;
				Mem_free(it_enc);
				goto out;
			}

			Mem_free(it_enc);
		}

		if (Buf_AddCh(b, '&') < 0) {
			errsv = errno;
			goto out;
		}
	}

	if (Buf_AddCh(b, '\0') < 0) {
		errsv = errno;
		goto out;
	}

	if ((res = Buf_GetData(b, &s, true)) == NULL) {
		errsv = errno;
		goto out;
	}

	s -= 2;
	if (res[s] == '&')
		res[s] = '\0';

out:
	Mem_free(queryd);
	Buf_Free(b);

	if (errsv)
		errno = errsv;

	return res;
}
