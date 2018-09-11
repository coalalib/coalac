#ifndef _URI_H_
#define _URI_H_

#include <stdbool.h>	/* bool */
#include <stdint.h>	/* uint16_t */

#include <coala/queue.h>

/* URI */
struct Uri {
	bool secure;	/* mandatory */
	uint16_t port;	/* optional */
	char *host;	/* mandatory */
	char *path;	/* optional */
	char *query;	/* optional */
};

/* Generating */
extern char *Uri_Gen(struct Uri *u);

/* Parsing */
extern int Uri_Parse(struct Uri *u, const char *uri);
extern void Uri_ParseFree(struct Uri *u);

/* Path */
struct Uri_ParsePathEntry {
	char *s;
	STAILQ_ENTRY(Uri_ParsePathEntry) list;
};

STAILQ_HEAD(Uri_ParsePathHead, Uri_ParsePathEntry);

extern int Uri_ParsePath(struct Uri_ParsePathHead *head, const char *path);
extern void Uri_ParsePathFree(struct Uri_ParsePathHead *head);

/* Query */
struct Uri_ParseQueryEntry {
	char *key;
	char *value;
	STAILQ_ENTRY(Uri_ParseQueryEntry) list;
};

STAILQ_HEAD(Uri_ParseQueryHead, Uri_ParseQueryEntry);

extern int Uri_ParseQuery(struct Uri_ParseQueryHead *head, const char *query,
			  bool parse_key_value);
extern void Uri_ParseQueryFree(struct Uri_ParseQueryHead *head);

/* Encode */
extern char *Uri_EncodeStr(const char *s);
extern char *Uri_DecodeStr(const char *s);
extern char *Uri_EncodePath(const char *path);
extern char *Uri_EncodeQuery(const char *query, bool encode_key_value);

#endif
