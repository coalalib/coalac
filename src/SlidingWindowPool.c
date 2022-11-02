#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <coala/queue.h>
#include <coala/Str.h>
#include <ndm/log.h>
#include <ndm/time.h>

#include "SlidingWindowPool.h"

#define EXPIRE_SEC	30

struct PoolEntry {
	char *tok;
	struct SlidingWindow *sw;
	struct CoAPMessage *m;
	int code;
	struct timespec expire;
	SLIST_ENTRY(PoolEntry) list;
};

SLIST_HEAD(PoolHead, PoolEntry);

struct SlidingWindowPool {
	struct PoolHead head;
	uint32_t current;
	uint32_t total;
	uint32_t orphan;
};

static void PoolEntryFree(struct PoolEntry *e)
{
	if (e == NULL)
		return;

	free(e->tok);
	CoAPMessage_Free(e->m);
	SlidingWindow_Free(e->sw);
	free(e);
}

struct SlidingWindowPool *SlidingWindowPool(void)
{
	struct SlidingWindowPool *p;

	if ((p = calloc(1, sizeof(*p))) == NULL)
		return NULL;

	SLIST_INIT(&p->head);

	return p;
}

void SlidingWindowPool_Free(struct SlidingWindowPool *p)
{
	struct PoolEntry *e, *t;

	if (p == NULL)
		return;

	SLIST_FOREACH_SAFE(e, &p->head, list, t) {
		SLIST_REMOVE(&p->head, e, PoolEntry, list);
		PoolEntryFree(e);
	}

	free(p);
}

void SlidingWindowPool_Cleaner(struct SlidingWindowPool *p)
{
	struct PoolEntry *e, *t;

	if (p == NULL)
		return;

	SLIST_FOREACH_SAFE(e, &p->head, list, t) {
		if (ndm_time_left_monotonic_msec(&e->expire) >= 0)
			continue;

		SLIST_REMOVE(&p->head, e, PoolEntry, list);
		PoolEntryFree(e);

		p->current--;
		p->orphan++;
	}
}

struct SlidingWindow *SlidingWindowPool_Get(struct SlidingWindowPool *p,
					    const char *tok,
					    struct CoAPMessage **m)
{
	struct PoolEntry *e;
	struct SlidingWindow *sw = NULL;

	if (p == NULL || tok == NULL) {
		errno = EINVAL;
		return NULL;
	}

	SLIST_FOREACH(e, &p->head, list) {
		if (strcmp(e->tok, tok) != 0)
			continue;

		ndm_time_get_monotonic(&e->expire);
		ndm_time_add_sec(&e->expire, EXPIRE_SEC);

		sw = e->sw;
		if (m)
			*m = e->m;
		break;
	}

	if (sw == NULL)
		errno = ENOENT;

	return sw;
}

int SlidingWindowPool_Set(struct SlidingWindowPool *p, const char *tok,
			  struct SlidingWindow *sw, struct CoAPMessage *m)
{
	char *d = NULL;
	struct CoAPMessage *cp = NULL;
	struct PoolEntry *e = NULL;

	if (p == NULL || tok == NULL || sw == NULL) {
		errno = EINVAL;
		return -1;
	} else if (SlidingWindowPool_Get(p, tok, NULL) != NULL) {
		errno = EEXIST;
		return -1;
	} else if ((e = calloc(1, sizeof(*e))) == NULL ||
		   (d = strdup(tok)) == NULL) {
		free(e);
		errno = ENOMEM;
		return -1;
	} else if (m && (cp = CoAPMessage_Clone(m,
					CoAPMessage_CloneFlagCb)) == NULL) {
		free(e);
		free(d);
		errno = ENOMEM;
		return -1;
	}

	ndm_time_get_monotonic(&e->expire);
	ndm_time_add_sec(&e->expire, EXPIRE_SEC);
	e->m = cp;
	e->sw = sw;
	e->tok = d;

	SLIST_INSERT_HEAD(&p->head, e, list);

	p->current++;
	p->total++;

	return 0;
}

int SlidingWindowPool_GetCode(struct SlidingWindowPool *p, const char *tok)
{
	struct PoolEntry *e;

	int code = -1;
	SLIST_FOREACH(e, &p->head, list) {
		if (strcmp(e->tok, tok) != 0)
			continue;

		ndm_time_get_monotonic(&e->expire);
		ndm_time_add_sec(&e->expire, EXPIRE_SEC);

		code = e->code;
		break;
	}

	if (code == -1)
		errno = ENOENT;

	return code;
}

int SlidingWindowPool_SetCode(struct SlidingWindowPool *p, const char *tok,
			      int code)
{
	bool found = false;
	struct PoolEntry *e;

	SLIST_FOREACH(e, &p->head, list) {
		if (strcmp(e->tok, tok) != 0)
			continue;

		ndm_time_get_monotonic(&e->expire);
		ndm_time_add_sec(&e->expire, EXPIRE_SEC);
		e->code = code;

		found = true;
		break;
	}

	if (!found)
		errno = ENOENT;

	return 0;
}

int SlidingWindowPool_Del(struct SlidingWindowPool *p, const char *tok)
{
	bool del = false;
	struct PoolEntry *e, *t;

	if (p == NULL || tok == NULL) {
		errno = EINVAL;
		return -1;
	}

	SLIST_FOREACH_SAFE(e, &p->head, list, t) {
		if (strcmp(e->tok, tok) != 0)
			continue;

#ifndef NDEBUG
		size_t s;
		if (ndm_log_get_debug() >= LDEBUG_1 &&
		    (s = SlidingWindow_GetSize(e->sw))) {
			char buf_sz[20];

			NDM_LOG_DEBUG("ARQ %s transfer %s %s",
				      SlidingWindow_IsRx(e->sw) ? "rx" : "tx",
				      e->tok,
				      Str_SizeFormat(s, buf_sz, sizeof buf_sz));
		}
#endif

		SLIST_REMOVE(&p->head, e, PoolEntry, list);
		PoolEntryFree(e);

		p->current--;
		del = true;
		break;
	}

	if (!del) {
		errno = ENOENT;
		return -1;
	}

	return 0;
}

int SlidingWindowPool_Stats(struct SlidingWindowPool *p,
			    struct SlidingWindowPool_Stats *st)
{
	if (p == NULL || st == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(st, 0, sizeof(*st));
	st->current = p->current;
	st->total = p->total;
	st->orphan = p->orphan;

	return 0;
}
