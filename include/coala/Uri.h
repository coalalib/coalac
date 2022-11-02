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

extern char *Uri_Gen(struct Uri *u);

extern int Uri_Parse(struct Uri *u, const char *uri);
extern void Uri_ParseFree(struct Uri *u);

/* Path */
struct Uri_PathEntry {
	char *val;
	STAILQ_ENTRY(Uri_PathEntry) list;
};

STAILQ_HEAD(Uri_PathHead, Uri_PathEntry);

extern struct Uri_PathEntry *Uri_PathEntry(const char *s);
extern void Uri_PathEntryFree(struct Uri_PathEntry *e);

extern char *Uri_PathGen(struct Uri_PathHead *head);
extern int Uri_PathParse(const char *path, struct Uri_PathHead *head);

extern void Uri_PathHeadFree(struct Uri_PathHead *head);

/* Query */
struct Uri_QueryEntry {
	char *key;
	char *val;
	STAILQ_ENTRY(Uri_QueryEntry) list;
};

STAILQ_HEAD(Uri_QueryHead, Uri_QueryEntry);

extern struct Uri_QueryEntry *Uri_QueryEntry(const char *key, const char *val);
extern void Uri_QueryEntryFree(struct Uri_QueryEntry *e);

extern char *Uri_QueryGen(struct Uri_QueryHead *head);
extern int Uri_QueryParse(const char *query, struct Uri_QueryHead *head,
			  bool parse_key_val);

extern void Uri_QueryHeadFree(struct Uri_QueryHead *head);

/* Str */
extern char *Uri_StrEncode(const char *s);
extern char *Uri_StrDecode(const char *s, size_t n);

#endif
