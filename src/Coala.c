#include <arpa/inet.h>
#include <netinet/in.h>
#include <ndm/ip_sockaddr.h>
#include <ndm/log.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <coala/Buf.h>
#include <coala/CoAPMessage.h>

#include "Err.h"
#include "LayerStack.h"
#include "MsgCache.h"
#include "MsgQueue.h"
#include "Private.h"
#include "SecLayer.h"
#include "SlidingWindowPool.h"

#define COAP_URI_WELLKNOWN	"/.well-known/core"
#define RECEIVE_BUFFER_SIZE	1500

struct ResEntry {
	const char *path;
	res_handler_t handler;
	void *arg;
	SLIST_ENTRY(ResEntry) list;
	uint8_t mask;
};

static void Coala_FreeResources(struct Coala *c);

static int WellKnownHandler(struct Coala *c,
			    int fd,
			    struct CoAPMessage *req,
			    struct CoAPMessage *rsp,
			    void *arg)
{
	bool first;
	int res = -1;
	size_t s;
	struct Buf_Handle *b = NULL;
	enum CoAPMessage_OptionCode opt_code =
		CoAPMessage_OptionCodeContentFormat;
	enum CoAPMessage_ContentFormat fmt = CoAPMessage_ContentFormatLink;
	struct ResEntry *e;
	uint8_t *d;

	if ((b = Buf()) == NULL)
		goto out;

	first = true;

	SLIST_FOREACH(e, &c->resources_head, list) {
		const char *fmt = ",<%s>";

		if (!strcmp(e->path, COAP_URI_WELLKNOWN))
			continue;

		if (first) {
			fmt = "<%s>";
			first = false;
		}

		if (Buf_AddFormatStr(b, fmt, e->path) < 0)
			goto out;
	}

	CoAPMessage_SetCode(rsp, CoAPMessage_CodeContent);

	d = Buf_GetData(b, &s, false);

	if (CoAPMessage_AddOptionUint(rsp, opt_code, fmt) < 0 ||
	   (d && CoAPMessage_SetPayload(rsp, d, s) < 0))
		goto out;

	res = 0;
out:
	Buf_Free(b);
	return res;
}

struct Coala *Coala(const uint8_t *key, size_t key_size, unsigned flags)
{
	struct Coala *c;

	CoAPMessage_Init();

	if (key && key_size != COALA_KEY_SIZE)
		goto out_null;

	if ((c = calloc(1, sizeof *c)) == NULL)
		goto out_null;

	uint8_t private_key[COALA_KEY_SIZE];
	if (key) {
		memcpy(private_key, key, key_size);
	} else {
		for (size_t i = 0; i < sizeof private_key; i++)
			private_key[i] = random() % UINT8_MAX;
	}

	if ((c->key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
			private_key, sizeof private_key)) == NULL)
		goto out_free;

	SLIST_INIT(&c->resources_head);

	if ((c->sw_pool = SlidingWindowPool()) == NULL)
		goto out_free_key;

	struct Err e;
	if (LayerStack_Init(c, &e) < 0) {
		NDM_LOG_ERROR("[%s] %s", e.src, e.dsc);
		goto out_free_pools;
	}

	if (flags & Coala_FlagWellKnownResource &&
	    Coala_AddRes(c, COAP_URI_WELLKNOWN,
			 BIT(CoAPMessage_CodeGet),
			 WellKnownHandler, NULL) < 0) {
		NDM_LOG_ERROR("%s (Coala_AddRes): %s", __func__,
			      strerror(errno));
		goto out_layers_deinit;
	}

	goto out;

out_layers_deinit:
	LayerStack_Deinit(c);
out_free_key:
	EVP_PKEY_free(c->key);
out_free_pools:
	SlidingWindowPool_Free(c->sw_pool);
out_free:
	free(c);
out_null:
	c = NULL;
out:
	return c;
}

void Coala_Free(struct Coala *c)
{
	if (c == NULL)
		return;

	LayerStack_Deinit(c);
	MsgQueue_Free();
	SlidingWindowPool_Free(c->sw_pool);
	Coala_FreeResources(c);
	EVP_PKEY_free(c->key);

	free(c);
}

int Coala_GetRes(struct Coala *c, const char *path,
		 enum CoAPMessage_Code code, res_handler_t *h,
		 void **arg)
{
	int errsv = 0, res = -1;
	struct ResEntry *e;

	if (c == NULL || path == NULL || h == NULL ||
	    !CoAPMessage_CodeIsRequest(code)) {
		errsv = EINVAL;
		goto out;
	}

	*h = NULL;

	SLIST_FOREACH(e, &c->resources_head, list) {
		if (strcmp(e->path, path) != 0)
			continue;

		if (e->mask & BIT(code)) {
			*h = e->handler;

			if (arg)
				*arg = e->arg;

			res = 0;
			goto out;
		} else {
			errsv = ENOKEY;
			goto out;
		}
	}

	errsv = ENOENT;

out:
	if (errsv)
		errno = errsv;

	return res;
}

int Coala_AddRes(struct Coala *c, const char *path,
		 unsigned mask, res_handler_t h, void *arg)
{
	struct ResEntry *e;

	if (c == NULL || path == NULL || !mask || h == NULL) {
		errno = EINVAL;
		return -1;
	}

	if ((e = calloc(1, sizeof *e)) == NULL)
		return -1;

	e->path = path;
	e->handler = h;
	e->arg = arg;
	e->mask = mask;
	SLIST_INSERT_HEAD(&c->resources_head, e, list);

	return 0;
}

int Coala_RemRes(struct Coala *c, const char *path)
{
	int errsv = 0, res = -1;
	struct ResEntry *e, *t;

	if (c == NULL || path == NULL) {
		errsv = EINVAL;
		goto out;
	}

	SLIST_FOREACH_SAFE(e, &c->resources_head, list, t) {
		if (!strcmp(e->path, path)) {
			SLIST_REMOVE(&c->resources_head, e, ResEntry, list);
			free(e);
			res = 0;
			goto out;
		}
	}

	errsv = ENOENT;
out:
	if (errsv)
		errno = errsv;

	return res;
}

static void Coala_FreeResources(struct Coala *c)
{
	struct ResEntry *e, *t;

	if (c == NULL)
		return;

	SLIST_FOREACH_SAFE(e, &c->resources_head, list, t) {
		SLIST_REMOVE(&c->resources_head, e, ResEntry, list);
		free(e);
	}
}

int Coala_SendLow(struct Coala *c, int fd, struct CoAPMessage *m)
{
	size_t s;
	struct ndm_ip_sockaddr_t sa;
	uint8_t *d;

	if (c == NULL || m == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (CoAPMessage_GetSockAddr(m, &sa) < 0 ||
	    (d = CoAPMessage_ToBytes(m, &s)) == NULL)
		return -1;

	if (sendto(fd, d, s, 0,
		   (struct sockaddr *)&sa,
		   ndm_ip_sockaddr_size(&sa)) < 0) {
		free(d);
		return -1;
	}

	free(d);

	return 0;
}

int Coala_Send(struct Coala *c, int fd, struct CoAPMessage *m)
{
	int ret;
	struct Err e;
	struct ndm_ip_sockaddr_t sa;

	if (c == NULL || m == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (CoAPMessage_GetSockAddr(m, &sa) < 0)
		return -1;

	ret = LayerStack_OnSend(c, fd, m, 0, &e);
	if (ret == LayerStack_Err) {
		NDM_LOG_ERROR("[%s] %s", e.src, e.dsc);
		errno = EBADE;
		return -1;
	}

	if (ret == LayerStack_Stop)
		return 0;

	if (CoAPMessage_TypeIsResponse(CoAPMessage_GetType(m)) &&
	    CoAPMessage_GetCode(m) != CoAPMessage_CodeUnauthorized)
		/* XXX: Don't cache another errors? */
		MsgCache_Add(fd, m);

	if (Coala_SendLow(c, fd, m) < 0)
		return -1;

	if (CoAPMessage_GetType(m) == CoAPMessage_TypeCon &&
	    MsgQueue_Add(fd, m) < 0)
		return -1;

	return 0;
}

int Coala_Recv(struct Coala *c, int fd)
{
	unsigned char buf[RECEIVE_BUFFER_SIZE];
	int ret;
	socklen_t len;
	struct CoAPMessage *m;
	struct Err e;
	struct ndm_ip_sockaddr_t sa;
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof sin);

	len = sizeof sin;
	ret = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&sin, &len);
	if (ret < 0)
		return -1;

	if ((m = CoAPMessage_FromBytes(buf, ret)) == NULL)
		return -1;

	ndm_ip_sockaddr_assign(&sa, &sin);
	CoAPMessage_SetSockAddr(m, &sa);

	if (LayerStack_OnReceive(c, fd, m, 0, &e) ==
	    LayerStack_Err)
		NDM_LOG_ERROR("[%s] %s", e.src, e.dsc);

	CoAPMessage_Free(m);

	return 0;
}

void Coala_Tick(struct Coala *c)
{
	if (c == NULL)
		return;

	MsgQueue_Tick(c);

	MsgCache_Cleaner();
	SecLayer_Cleaner();
	SlidingWindowPool_Cleaner(c->sw_pool);
}

int Coala_Stats(struct Coala *c, struct Coala_Stats *st)
{
	struct MsgCache_Stats mc_st;
	struct SecLayer_Stats sl_st;
	struct SlidingWindowPool_Stats swp_st;

	if (c == NULL || st == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(st, 0, sizeof(*st));

	if (!MsgCache_Stats(&mc_st)) {
		st->msgcache_current = mc_st.current;
		st->msgcache_match = mc_st.match;
		st->msgcache_total = mc_st.total;
		st->msgcache_over = mc_st.over;
	}

	if (!SecLayer_Stats(&sl_st)) {
		st->seclayer_current = sl_st.current;
		st->seclayer_total = sl_st.total;
	}

	if (!SlidingWindowPool_Stats(c->sw_pool, &swp_st)) {
		st->swp_current = swp_st.current;
		st->swp_total = swp_st.total;
		st->swp_orphan = swp_st.orphan;
	}

	return 0;
}
