#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <coala/Mem.h>
#include <coala/queue.h>
#include <ndm/log.h>

#include "SlidingWindowPool.h"
#include "Str.h"
#include "TimeMono.h"

static pthread_mutex_t PoolMutex = PTHREAD_MUTEX_INITIALIZER;

struct PoolEntry {
	char *tok;
	struct SlidingWindow *sw;
	struct CoAPMessage *m;
	CoAPMessage_Handler_t handler;
	int code;
	uint64_t timestamp;
	SLIST_ENTRY(PoolEntry) list;
};

SLIST_HEAD(PoolHead, PoolEntry);

struct SlidingWindowPool {
	struct PoolHead head;
};

struct SlidingWindowPool *SlidingWindowPool(void)
{
	struct SlidingWindowPool *p;

	if ((p = Mem_calloc(1, sizeof(*p))) == NULL)
		return NULL;

	SLIST_INIT(&p->head);

	return p;
}

struct SlidingWindow *SlidingWindowPool_Get(struct SlidingWindowPool *p,
					    const char *tok,
					    struct CoAPMessage **m,
					    CoAPMessage_Handler_t *handler)
{
	int ret;
	struct PoolEntry *e;
	struct SlidingWindow *sw = NULL;

	if (p == NULL || tok == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if ((ret = pthread_mutex_lock(&PoolMutex))) {
		errno = ret;
		return NULL;
	}

	SLIST_FOREACH(e, &p->head, list) {
		if (strcmp(e->tok, tok) != 0)
			continue;

		sw = e->sw;
		if (m)
			*m = e->m;
		if (handler)
			*handler = e->handler;
		break;
	}

	pthread_mutex_unlock(&PoolMutex);

	if (sw == NULL)
		errno = ENOENT;

	return sw;
}

int SlidingWindowPool_Set(struct SlidingWindowPool *p, const char *tok,
			  struct SlidingWindow *sw, struct CoAPMessage *m,
			  CoAPMessage_Handler_t handler)
{
	char *d = NULL;
	int ret;
	struct PoolEntry *e = NULL;

	if (p == NULL || tok == NULL || sw == NULL) {
		errno = EINVAL;
		return -1;
	} else if (SlidingWindowPool_Get(p, tok, NULL, NULL) != NULL) {
		errno = EEXIST;
		return -1;
	} else if ((e = Mem_calloc(1, sizeof(*e))) == NULL ||
		   (d = Mem_strdup(tok)) == NULL) {
		Mem_free(e);
		errno = ENOMEM;
		return -1;
	} else if ((ret = pthread_mutex_lock(&PoolMutex))) {
		Mem_free(e);
		Mem_free(d);
		errno = ret;
		return -1;
	}

	e->timestamp = TimeMono_Us();
	e->m = m;
	e->sw = sw;
	e->tok = d;
	e->handler = handler;
	SLIST_INSERT_HEAD(&p->head, e, list);

	pthread_mutex_unlock(&PoolMutex);

	return 0;
}

int SlidingWindowPool_GetCode(struct SlidingWindowPool *p, const char *tok)
{
	int ret;
	struct PoolEntry *e;

	if ((ret = pthread_mutex_lock(&PoolMutex))) {
		errno = ret;
		return -1;
	}

	int code = -1;
	SLIST_FOREACH(e, &p->head, list) {
		if (strcmp(e->tok, tok) != 0)
			continue;

		code = e->code;
		break;
	}
	pthread_mutex_unlock(&PoolMutex);

	if (code == -1)
		errno = ENOENT;

	return code;
}

int SlidingWindowPool_SetCode(struct SlidingWindowPool *p, const char *tok,
			      int code)
{
	bool found = false;
	int ret;
	struct PoolEntry *e;

	if ((ret = pthread_mutex_lock(&PoolMutex))) {
		errno = ret;
		return -1;
	}

	SLIST_FOREACH(e, &p->head, list) {
		if (strcmp(e->tok, tok) != 0)
			continue;

		e->code = code;
		found = true;
		break;
	}
	pthread_mutex_unlock(&PoolMutex);

	if (!found)
		errno = ENOENT;

	return 0;
}

int SlidingWindowPool_Del(struct SlidingWindowPool *p, const char *tok)
{
	bool del = false;
	int ret;
	struct PoolEntry *e, *t;

	if (p == NULL || tok == NULL) {
		errno = EINVAL;
		return -1;
	} else if ((ret = pthread_mutex_lock(&PoolMutex))) {
		errno = ret;
		return -1;
	}

	SLIST_FOREACH_SAFE(e, &p->head, list, t) {
		size_t s;

		if (strcmp(e->tok, tok) != 0)
			continue;

		if (ndm_log_get_debug() >= LDEBUG_1 &&
		    (s = SlidingWindow_GetSize(e->sw))) {
			char buf_sz[20], buf_sp[30];
			double sp;
			uint64_t now = TimeMono_Us();

			sp = s / ((now - e->timestamp) / 1000000.0);

			NDM_LOG_DEBUG("ARQ %s transfer %s %s at %s",
				      SlidingWindow_IsRx(e->sw) ? "rx" : "tx",
				      e->tok,
				      Str_SizeFormat(s, buf_sz, sizeof buf_sz),
				      Str_SpeedFormat(sp, buf_sp, sizeof buf_sp));
		}

		Mem_free(e->tok);
		CoAPMessage_Decref(e->m);
		SlidingWindow_Free(e->sw);

		SLIST_REMOVE(&p->head, e, PoolEntry, list);
		Mem_free(e);

		del = true;
		break;
	}

	pthread_mutex_unlock(&PoolMutex);

	if (!del) {
		errno = ENOENT;
		return -1;
	}

	return 0;
}

void SlidingWindowPool_Free(struct SlidingWindowPool *p)
{
	struct PoolEntry *e, *t;

	if (p == NULL ||
	    pthread_mutex_lock(&PoolMutex))
		return;


	SLIST_FOREACH_SAFE(e, &p->head, list, t) {
		Mem_free(e->tok);
		CoAPMessage_Decref(e->m);
		SlidingWindow_Free(e->sw);
		Mem_free(e);
	}

	Mem_free(p);

	pthread_mutex_unlock(&PoolMutex);
}
