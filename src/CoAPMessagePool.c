#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <coala/uthash.h>
#include <coala/Mem.h>

#include "CoAPMessagePool.h"
#include "TimeMono.h"

#define MAX_PICK_ATTEMPTS	3
#define EXPIRATION_PERIOD	60000
#define RESEND_PERIOD		3000
#define GARBAGE_PERIOD		25000

struct PoolItem {
	uint64_t send_time;
	uint64_t create_time;
	struct CoAPMessage *msg;
	uint16_t id;
	uint8_t send_attemps;
	uint8_t flags;
	bool sent;
	UT_hash_handle hh;
};

struct CoAPMessagePool {
	struct PoolItem *pool;
};

static pthread_cond_t pool_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;

struct CoAPMessagePool *CoAPMessagePool(void)
{
	struct CoAPMessagePool *mp = NULL;

	mp = Mem_calloc(1, sizeof *mp);
	if (mp == NULL)
		return NULL;

	mp->pool = NULL;
	return mp;
}

void CoAPMessagePool_Free(struct CoAPMessagePool *mp)
{
	if (mp == NULL)
		return;

	CoAPMessagePool_Clear(mp);
	Mem_free(mp);
}

struct CoAPMessage *CoAPMessagePool_Next(struct CoAPMessagePool *mp,
					 unsigned *flags)
{
	struct CoAPMessage *m = NULL;
	struct PoolItem *el, *tmp;
	uint64_t now;

	if (mp == NULL)
		goto out;

	pthread_mutex_lock(&pool_mutex);
	if (!HASH_COUNT(mp->pool))
		pthread_cond_wait(&pool_cond, &pool_mutex);

	HASH_ITER(hh, mp->pool, el, tmp) {
		now = TimeMono_Ms();

		if (now - el->create_time >= EXPIRATION_PERIOD) {
			HASH_DEL(mp->pool, el);
			CoAPMessage_Decref(el->msg);
			Mem_free(el);
			continue;
		}

		if (el->send_time && now - el->send_time >= GARBAGE_PERIOD) {
			HASH_DEL(mp->pool, el);
			CoAPMessage_Decref(el->msg);
			Mem_free(el);
			continue;
		}

		if (!el->sent) {
			if (el->send_attemps >= MAX_PICK_ATTEMPTS) {
				HASH_DEL(mp->pool, el);
				CoAPMessage_Decref(el->msg);
				Mem_free(el);
				continue;
			}

			el->sent = true;
			el->send_time = TimeMono_Ms();
			el->send_attemps++;

			if (flags)
				*flags = el->flags;

			m = CoAPMessage_Incref(el->msg);
			goto out_unlock;
		} else {
			if (!CoAPMessage_IsMulticast(el->msg) &&
			    el->send_time && now - el->send_time >= RESEND_PERIOD)
				el->sent = false;
		}

		usleep(250);
	}

out_unlock:
	pthread_mutex_unlock(&pool_mutex);
out:
	return m;
}

int CoAPMessagePool_Add(struct CoAPMessagePool *mp, struct CoAPMessage *m,
		        unsigned flags)
{
	struct PoolItem *el;

	if (mp == NULL || m == NULL) {
		errno = EINVAL;
		return -1;
	}

	CoAPMessage_Incref(m);

	el = Mem_calloc(1, sizeof *el);
	if (el == NULL) {
		CoAPMessage_Decref(m);
		errno = ENOMEM;
		return -1;
	}

	el->id = CoAPMessage_GetId(m);
	el->msg = m;
	el->create_time = TimeMono_Ms();
	el->flags = flags;

	pthread_mutex_lock(&pool_mutex);
	HASH_ADD(hh, mp->pool, id, sizeof(el->id), el);
	pthread_cond_signal(&pool_cond);
	pthread_mutex_unlock(&pool_mutex);

	return 0;
}

struct CoAPMessage *CoAPMessagePool_Get(struct CoAPMessagePool *mp,
				        unsigned short id, unsigned *flags)
{
	struct CoAPMessage *m = NULL;
	struct PoolItem *el;

	if (mp == NULL)
		goto out;

	pthread_mutex_lock(&pool_mutex);
	HASH_FIND(hh, mp->pool, &id, sizeof id, el);
	if (el == NULL)
		goto out_unlock;

	m = CoAPMessage_Incref(el->msg);
	if (flags)
		*flags = el->flags;
out_unlock:
	pthread_mutex_unlock(&pool_mutex);
out:
	return m;
}

int CoAPMessagePool_Remove(struct CoAPMessagePool *mp, unsigned short id)
{
	int res = -1;
	struct PoolItem *el;

	if (mp == NULL) {
		errno = EINVAL;
		goto out;
	}

	pthread_mutex_lock(&pool_mutex);
	HASH_FIND(hh, mp->pool, &id, sizeof id, el);
	if (el == NULL) {
		errno = ENOENT;
		goto out_unlock;
	}

	HASH_DEL(mp->pool, el);
	CoAPMessage_Decref(el->msg);
	Mem_free(el);

	res = 0;

out_unlock:
	pthread_mutex_unlock(&pool_mutex);
out:
	return res;
}

int CoAPMessagePool_Clear(struct CoAPMessagePool *mp)
{
	struct PoolItem *el, *tmp;

	if (mp == NULL) {
		errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&pool_mutex);
	HASH_ITER(hh, mp->pool, el, tmp) {
		HASH_DEL(mp->pool, el);
		CoAPMessage_Decref(el->msg);
		Mem_free(el);
	}
	pthread_mutex_unlock(&pool_mutex);

	return 0;
}
