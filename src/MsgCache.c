#include <errno.h>
#include <inttypes.h>
#include <stddef.h>

#include <coala/khash.h>
#include <coala/CoAPMessage.h>
#include <coala/Str.h>
#include <ndm/ip_sockaddr.h>
#include <ndm/time.h>

#include "MsgCache.h"

#ifdef UNIT_TEST
  #define STATIC
  #define STATIC_INLINE
#else
  #define STATIC        static
  #define STATIC_INLINE static inline
#endif

#define EXPIRE_SEC		20
#define CACHE_MAP_MAX_SIZE	64

struct CacheMapEntry {
	struct CoAPMessage *m;
	struct timespec expire;
};

KHASH_MAP_INIT_STR(CacheMap_t, struct CacheMapEntry *);

static khash_t(CacheMap_t) *CacheMap;
static uint32_t counter_match;
static uint32_t counter_total;
static uint32_t counter_over;

STATIC void CacheMapEntryFree(struct CacheMapEntry *e)
{
	if (e == NULL)
		return;

	CoAPMessage_Free(e->m);
	free(e);
}

STATIC int KeyGen(struct CoAPMessage *m, char buf[MSGCACHE_KEY_SIZE])
{
	char ip[INET_ADDRSTRLEN];
	char tok_s[COAP_MESSAGE_MAX_TOKEN_SIZE * 2 + 1] = {'\0'};
	size_t tok_sz;
	struct ndm_ip_sockaddr_t sa;
	uint8_t tok[COAP_MESSAGE_MAX_TOKEN_SIZE];

	if (CoAPMessage_GetSockAddr(m, &sa) < 0)
		return -1;

	ndm_ip_sockaddr_ntop(&sa, ip, sizeof ip);

	tok_sz = sizeof tok;
	if (!CoAPMessage_GetToken(m, tok, &tok_sz))
		Str_FromArr(tok, tok_sz, tok_s, sizeof tok_s);

	snprintf(buf, MSGCACHE_KEY_SIZE, "%s:%" PRIu16 "_%d_%s",
		 ip, ndm_ip_sockaddr_port(&sa), CoAPMessage_GetId(m), tok_s);

	return 0;
}

int MsgCache_Init(void)
{
	if ((CacheMap = kh_init(CacheMap_t)) == NULL)
		return -1;

	return 0;
}

void MsgCache_Deinit(void)
{
	for (khiter_t it = kh_begin(CacheMap);
             it != kh_end(CacheMap);
             it++) {
		const char *k;
		struct CacheMapEntry *e;

                if (!kh_exist(CacheMap, it))
                        continue;

		e = kh_val(CacheMap, it);
		CacheMapEntryFree(e);

		k = kh_key(CacheMap, it);
		free((void *)k);

		kh_del(CacheMap_t, CacheMap, it);
        }

	kh_destroy(CacheMap_t, CacheMap);

	counter_match = counter_total = counter_over = 0;
}

int MsgCache_Add(int fd, struct CoAPMessage *m)
{
	char *k = NULL, key[MSGCACHE_KEY_SIZE];
	unsigned flags = CoAPMessage_CloneFlagPayload;
	int errsv = 0, res = -1, ret;
	khiter_t it;
	struct CacheMapEntry *e = NULL;
	struct CoAPMessage *mc = NULL;

	if (m == NULL) {
		errsv = EINVAL;
		goto out_free;
	}

	if (kh_size(CacheMap) >= CACHE_MAP_MAX_SIZE) {
		errsv = ENOSPC;
		counter_over++;
		goto out_free;
	}

	if (KeyGen(m, key) < 0) {
		errsv = errno;
		goto out_free;
	}

	if ((e = calloc(1, sizeof(*e))) == NULL ||
	    (k = strdup(key)) == NULL ||
	    (mc = CoAPMessage_Clone(m, flags)) == NULL) {
		errsv = errno;
		goto out_free;
	}

	it = kh_put(CacheMap_t, CacheMap, k, &ret);
	if (ret < 0) {
		errsv = errno;
		goto out_free;
	}

	if (!ret) {
		errsv = EEXIST;
		goto out_free;
	}

	ndm_time_get_monotonic(&e->expire);
	ndm_time_add_sec(&e->expire, EXPIRE_SEC);
	e->m = mc;

	kh_val(CacheMap, it) = e;

	counter_total++;

	res = 0;
	goto out;

out_free:
	free(e);
	free(k);
	CoAPMessage_Free(mc);
out:
	if (errsv)
		errno = errsv;

	return res;
}

struct CoAPMessage *MsgCache_Get(int fd, struct CoAPMessage *m)
{
	char key[MSGCACHE_KEY_SIZE];
	khiter_t it;
	struct CacheMapEntry *e;

	if (m == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (KeyGen(m, key) < 0)
		return NULL;

	if ((it = kh_get(CacheMap_t, CacheMap, key)) == kh_end(CacheMap)) {
		errno = ENOENT;
		return NULL;
	}

	e = kh_val(CacheMap, it);
	counter_match++;

	return e->m;
}

void MsgCache_Cleaner(void)
{
	for (khiter_t it = kh_begin(CacheMap);
             it != kh_end(CacheMap);
             it++) {
		const char *k;
		struct CacheMapEntry *e;

                if (!kh_exist(CacheMap, it))
                        continue;

		e = kh_val(CacheMap, it);

		if (ndm_time_left_monotonic_msec(&e->expire) >= 0)
			continue;

		CacheMapEntryFree(e);

		k = kh_key(CacheMap, it);
		free((void *)k);

		kh_del(CacheMap_t, CacheMap, it);
	}
}

int MsgCache_Stats(struct MsgCache_Stats *st)
{
	if (st == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(st, 0, sizeof(*st));
	st->current = kh_size(CacheMap);
	st->match = counter_match;
	st->total = counter_total;
	st->over = counter_over;

	return 0;
}
