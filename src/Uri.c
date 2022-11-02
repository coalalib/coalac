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
#include <coala/Str.h>
#include <coala/Uri.h>
#include <coala/queue.h>


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
	if ((u->host = strndup(uri + so, eo - so)) == NULL)
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

		if ((u->path = strndup(uri + so, eo - so)) == NULL)
			goto out_free;
	}

	so = match[MATCH_QUERY].rm_so;
	eo = match[MATCH_QUERY].rm_eo;
	if (so != -1) {
		if ((u->query = strndup(uri + so, eo - so)) == NULL)
			goto out_free;
	}

	res = 0;
	goto out_regfree;

out_free:
	free(u->host);
	free(u->path);
	free(u->query);
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

	free(u->host);
	free(u->path);
	free(u->query);
}

int Uri_PathParse(const char *path, struct Uri_PathHead *head)
{
	const char *p, *q;
	int errsv = 0, res = -1;

	if (head == NULL || path == NULL || *path != '/') {
		errsv = EINVAL;
		goto out;
	}

	path++;

	if (*path == '\0') {
		errsv = EINVAL;
		goto out;
	}

	p = q = path;
	while (true) {
		if (*p == '/' || *p == '\0') {
			size_t n = p - q;
			struct Uri_PathEntry *e;

			if (n) {
				e = calloc(1, sizeof(*e));
				if (e == NULL ||
				    (e->val = Uri_StrDecode(q, n)) == NULL) {
					errsv = errno;
					free(e);
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
	Uri_PathHeadFree(head);
out:
	if (errsv)
		errno = errsv;

	return res;
}

struct Uri_PathEntry *Uri_PathEntry(const char *val)
{
	if (val == NULL) {
		errno = EINVAL;
		return NULL;
	}

	struct Uri_PathEntry *e;
	if ((e = calloc(1, sizeof(*e))) == NULL ||
	    (e->val = strdup(val)) == NULL) {
		free(e);
		return NULL;
	}

	return e;
}

void Uri_PathEntryFree(struct Uri_PathEntry *e)
{
	if (e == NULL)
		return;

	free(e->val);
	free(e);
}

void Uri_PathHeadFree(struct Uri_PathHead *head)
{
	struct Uri_PathEntry *e, *t;

	if (head == NULL)
		return;

	STAILQ_FOREACH_SAFE(e, head, list, t) {
		STAILQ_REMOVE(head, e, Uri_PathEntry, list);
		Uri_PathEntryFree(e);
	}
}

int Uri_QueryParse(const char *query, struct Uri_QueryHead *head,
		   bool parse_key_value)
{
	const char *p, *q;
	int errsv = 0, res = -1;

	if (head == NULL || query == NULL || *query != '?') {
		errsv = EINVAL;
		goto out;
	}

	query++;

	if (*query == '\0') {
		errsv = EINVAL;
		goto out;
	}

	p = q = query;
	while (true) {
		if (*p == '&' || *p == '\0') {
			size_t n = p - q;
			struct Uri_QueryEntry *e;

			if (n) {
				const char *v;

				if ((e = calloc(1, sizeof(*e))) == NULL)
					goto out_free;

				if (parse_key_value) {
					v = Str_strnchr(q, n, '=');
					if (v) {
						size_t val_len;
						n = v - q;
						v++;

						val_len = p - v;
						if (val_len &&
						    (e->val = Uri_StrDecode(v, val_len)) == NULL) {
							errsv = errno;
							free(e);
							goto out_free;
						}
					}
				}

				if ((e->key = Uri_StrDecode(q, n)) == NULL) {
					errsv = errno;
					free(e->val);
					free(e);
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
	Uri_QueryHeadFree(head);
out:
	if (errsv)
		errno = errsv;

	return res;
}

struct Uri_QueryEntry *Uri_QueryEntry(const char *key, const char *val)
{
	if (key == NULL) {
		errno = EINVAL;
		return NULL;
	}

	struct Uri_QueryEntry *e = calloc(1, sizeof(*e));
	if (e == NULL)
		return NULL;

	if ((e->key = strdup(key)) == NULL) {
		free(e);
		return NULL;
	}

	if (val && ((e->val = strdup(val)) == NULL)) {
		free(e->key);
		free(e);
		return NULL;
	}

	return e;
}

void Uri_QueryEntryFree(struct Uri_QueryEntry *e)
{
	if (e == NULL)
		return;

	free(e->key);
	free(e->val);
	free(e);
}

void Uri_QueryHeadFree(struct Uri_QueryHead *head)
{
	struct Uri_QueryEntry *e, *t;

	if (head == NULL)
		return;

	STAILQ_FOREACH_SAFE(e, head, list, t) {
		STAILQ_REMOVE(head, e, Uri_QueryEntry, list);
		Uri_QueryEntryFree(e);
	}
}

char *Uri_StrEncode(const char *s)
{
	char *r, *rp;

	if (s == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if ((r = malloc(strlen(s) * 3 + 1)) == NULL)
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

char *Uri_StrDecode(const char *s, size_t n)
{
	char *r, *rp;
	size_t l;

	if (s == NULL || *s == '\0') {
		errno = EINVAL;
		return NULL;
	}

	l = strlen(s);
	if (!n) {
		n = l;
	} else if (n > l) {
		errno = EINVAL;
		return NULL;
	}

	if ((r = malloc(n + 1)) == NULL)
		return NULL;

	rp = r;

	while (n > 0) {
		if (*s == '%') {
			if (n >= 3 &&
			    isxdigit(*(s + 1)) &&
			    isxdigit(*(s + 2))) {
				unsigned char t;
				t = Str_Char2Hex(*(s + 1)) << 4;
				t |= Str_Char2Hex(*(s + 2));
				*rp++ = t;
				s += 2;
				n -= 2;
			} else {
				free(r);
				errno = EBADMSG;
				return NULL;
			}
		} else if (*s == '+') {
			*rp++ = ' ';
		} else {
			*rp++ = *s;
		}

		s++;
		n--;
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

char *Uri_PathGen(struct Uri_PathHead *head)
{
	char *res = NULL;
	int errsv = 0;
	struct Buf_Handle *b = NULL;

	if (head == NULL) {
		errsv = EINVAL;
		goto out;
	}

	if ((b = Buf()) == NULL) {
		errsv = errno;
		goto out;
	}

	struct Uri_PathEntry *e;
	STAILQ_FOREACH(e, head, list) {
		char *s_enc;

		if ((s_enc = Uri_StrEncode(e->val)) == NULL) {
			errsv = errno;
			goto out;
		}

		if (Buf_AddCh(b, '/') < 0) {
			errsv = errno;
			free(s_enc);
			goto out;
		}

		if (*s_enc && Buf_AddStr(b, s_enc) < 0) {
			errsv = errno;
			free(s_enc);
			goto out;
		}

		free(s_enc);
	}

	if (Buf_AddCh(b, '\0') < 0) {
		errsv = errno;
		goto out;
	}

	if ((res = Buf_GetData(b, NULL, true)) == NULL)
		errsv = errno;

out:
	Buf_Free(b);

	if (errsv)
		errno = errsv;

	return res;
}

char *Uri_QueryGen(struct Uri_QueryHead *head)
{
	char *res = NULL;
	int errsv = 0;
	size_t s;
	struct Buf_Handle *b = NULL;

	if (head == NULL) {
		errsv = EINVAL;
		goto out;
	}

	if ((b = Buf()) == NULL ||
	    Buf_AddCh(b, '?') < 0) {
		errsv = errno;
		goto out;
	}

	struct Uri_QueryEntry *e;
	STAILQ_FOREACH(e, head, list) {
		if (e->key && e->val) {
			char *key_enc = NULL, *val_enc = NULL;

			if ((key_enc = Uri_StrEncode(e->key)) == NULL ||
			    (val_enc = Uri_StrEncode(e->val)) == NULL ||
			    Buf_AddFormatStr(b, "%s=%s", key_enc, val_enc) < 0) {
				errsv = errno;
				free(key_enc);
				free(val_enc);
				goto out;
			}

			free(key_enc);
			free(val_enc);
		} else if (e->key && e->val == NULL) {
			char *key_enc;

			if ((key_enc = Uri_StrEncode(e->key)) == NULL ||
			    Buf_AddStr(b, key_enc) < 0) {
				errsv = errno;
				free(key_enc);
				goto out;
			}

			free(key_enc);
		} else {
			errsv = EINVAL;
			goto out;
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
	Buf_Free(b);

	if (errsv)
		errno = errsv;

	return res;
}
