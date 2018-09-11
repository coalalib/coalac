#define _GNU_SOURCE	/* GNU variant of strerror_r */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <ndm/ip_sockaddr.h>
#include <ndm/log.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <coala/Buf.h>
#include <coala/Coala.h>
#include <coala/CoAPMessage.h>
#include <coala/Mem.h>
#include <coala/queue.h>

#include "CoAPMessagePool.h"
#include "Err.h"
#include "LayerStack.h"
#include "SlidingWindowPool.h"
#include "curve25519-donna.h"

#define COAP_URI_WELLKNOWN	"/.well-known/core"

#define SLEEP_GRANULARITY_MS	333
#define SLEEP_GRANULARITY_US	(SLEEP_GRANULARITY_MS * 1000)

#define RECEIVE_BUFFER_SIZE	1500
#define THREAD_STACK_SIZE	0x40000

static void Coala_FreeResources(struct Coala *c);

struct ResEntry {
	const char *path;
	res_handler_t handler;
	SLIST_ENTRY(ResEntry) list;
	uint8_t mask;
};

SLIST_HEAD(ResHead, ResEntry);

struct Coala_Priv {
	volatile bool stop;
	int sock_fd;
	pthread_t receiver_tid;
	pthread_t sender_tid;
	struct ResHead resources_head;
};

static void *CoAPReceiver(void *arg)
{
	unsigned char buf[RECEIVE_BUFFER_SIZE];
	int ret;
	struct Coala *c = (struct Coala *) arg;

	while (!c->priv->stop) {
		socklen_t len;
		struct ndm_ip_sockaddr_t sa;
		struct sockaddr_in sin;
		struct CoAPMessage *m;
		struct Err e;

		len = sizeof sin;
		ret = recvfrom(c->priv->sock_fd, buf, sizeof buf, 0,
			       (struct sockaddr *) &sin, &len);
		if (ret < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				NDM_LOG_WARNING("%s (recvfrom): %s", __func__,
						strerror_r(errno, (char *)buf,
						sizeof buf));
			}
			continue;
		}

		if ((m = CoAPMessage_FromBytes(buf, ret)) == NULL)
			continue;

		ndm_ip_sockaddr_assign(&sa, &sin);
		CoAPMessage_SetSockAddr(m, &sa);

		ret = LayerStack_OnReceive(c, m, 0, &e);
		if (ret == LayerStack_Err)
			NDM_LOG_ERROR("[%s] %s", e.src, e.dsc);

		CoAPMessage_Decref(m);
	}

	return (void *) 0;
}

static void *CoAPSender(void *arg)
{
	char buf[100];
	int ret;
	struct Coala *c = (struct Coala *) arg;

	while (!c->priv->stop) {
		size_t s;
		struct CoAPMessage *m;
		unsigned flags;

		m = CoAPMessagePool_Next(c->mes_pool, &flags);
		if (m == NULL)
			continue;

		struct ndm_ip_sockaddr_t sa;
		if (CoAPMessage_GetSockAddr(m, &sa) < 0) {
			/* Delete message */
			CoAPMessage_Decref(m);
			continue;
		}

		struct Err e;
		ret = LayerStack_OnSend(c, m, flags, &e);
		if (ret == LayerStack_Err) {
			NDM_LOG_ERROR("[%s] %s", e.src, e.dsc);
			CoAPMessage_Decref(m);
			continue;
		} else if (ret == LayerStack_Stop) {
			CoAPMessage_Decref(m);
			continue;
		}

		uint8_t *d;
		if ((d = CoAPMessage_ToBytes(m, &s)) == NULL) {
			NDM_LOG_ERROR("%s (CoAPMessage_ToBytes): %s",
				      __func__,
				      strerror_r(errno, buf,
				      sizeof buf));
			CoAPMessage_Decref(m);
			continue;
		}

		ret = sendto(c->priv->sock_fd, d, s, 0,
			     (struct sockaddr *)&sa,
			     ndm_ip_sockaddr_size(&sa));
		if (ret < 0) {
			NDM_LOG_DEBUG("%s (sendto): %s",
				      __func__,
				      strerror_r(errno, buf,
				      sizeof buf));
		}

		Mem_free(d);

		if (CoAPMessage_GetType(m) != CoAPMessage_TypeCon) {
			CoAPMessagePool_Remove(c->mes_pool,
					       CoAPMessage_GetId(m));
		}

		CoAPMessage_Decref(m);
	}

	return (void *) 0;
}

static int WellKnownHandler(struct Coala *c,
			    struct CoAPMessage *req,
			    struct CoAPMessage *resp)
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

	SLIST_FOREACH(e, &c->priv->resources_head, list) {
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

	CoAPMessage_SetCode(resp, CoAPMessage_CodeContent);

	d = Buf_GetData(b, &s, false);

	if (CoAPMessage_AddOptionUint(resp, opt_code, fmt) < 0 ||
	   (d && CoAPMessage_SetPayload(resp, d, s) < 0))
		goto out;

	res = 0;
out:
	Buf_Free(b);
	return res;
}

struct Coala *Coala(int port, in_addr_t addr)
{
	char buf[100];
	int fd, ret;
	pthread_t tid;
	struct Coala *c;
	struct Coala_Priv *c_priv;
	struct ip_mreqn mreqn;
	struct sockaddr_in sin;
	struct timeval tv;

	CoAPMessage_Init();

	c = Mem_calloc(1, sizeof *c);
	if (c == NULL)
		return NULL;

	c_priv = Mem_calloc(1, sizeof *c_priv);
	if (c_priv == NULL)
		goto out_free;

	c->priv = c_priv;

	SLIST_INIT(&c_priv->resources_head);

	if ((c->mes_pool = CoAPMessagePool()) == NULL ||
	    (c->sw_pool = SlidingWindowPool()) == NULL) {
		goto out_free_pools;
	}

	struct Err e;
	if (LayerStack_Init(c, &e) < 0) {
		NDM_LOG_ERROR("[%s] %s", e.src, e.dsc);
		goto out_layers_deinit;
	}

	ret = Coala_AddRes(c, COAP_URI_WELLKNOWN, BIT(CoAPMessage_CodeGet),
			   WellKnownHandler);
	if (ret < 0) {
		NDM_LOG_ERROR("%s (coala_res_add): %s", __func__,
			      strerror_r(errno, buf, sizeof buf));
		goto out_free_pools;
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		NDM_LOG_ERROR("%s: socket", __func__);
		goto out_res_free;
	}
	c_priv->sock_fd = fd;

	int on = 1;
	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
	if (ret < 0) {
		NDM_LOG_ERROR("%s: setsockopt (reuse)", __func__);
		goto out_fd_close;
	}

	tv.tv_sec = 0;
	tv.tv_usec = SLEEP_GRANULARITY_US;
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	if (ret < 0) {
		NDM_LOG_ERROR("%s: setsockopt (timeout)", __func__);
		goto out_fd_close;
	}

	memset(&mreqn, 0, sizeof mreqn);
	mreqn.imr_multiaddr.s_addr = inet_addr(COALA_MCAST_ADDR);
	mreqn.imr_address.s_addr = addr;

	int off = 0;
	if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqn, sizeof mreqn) < 0 ||
	    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof addr) < 0 ||
	    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof off) < 0) {
		NDM_LOG_ERROR("%s: setsockopt", __func__);
		goto out_fd_close;
	}

	memset(&sin, 0, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(port);

	ret = bind(fd, (struct sockaddr *) &sin, sizeof sin);
	if (ret < 0) {
		NDM_LOG_ERROR("%s: bind", __func__);
		goto out_fd_close;
	}

	pthread_attr_t attr;

	ret = pthread_attr_init(&attr);
	if (ret != 0)
		goto out_fd_close;

	ret = pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
	if (ret != 0)
		goto out_destroy_attr;

	ret = pthread_create(&tid, &attr, CoAPReceiver, c);
	if (ret != 0) {
		NDM_LOG_ERROR("%s: pthread_create", __func__);
		goto out_destroy_attr;
	}

	c_priv->receiver_tid = tid;

	ret = pthread_create(&tid, &attr, CoAPSender, c);
	if (ret != 0) {
		NDM_LOG_ERROR("%s: pthread_create", __func__);
		goto out_thr_receiver_cancel;
	}

	c_priv->sender_tid = tid;

	pthread_attr_destroy(&attr);
	goto out;

out_thr_receiver_cancel:
	pthread_cancel(c_priv->receiver_tid);
	pthread_join(c_priv->receiver_tid, NULL);
out_destroy_attr:
	pthread_attr_destroy(&attr);
out_fd_close:
	close(fd);
out_res_free:
	Coala_FreeResources(c);
out_layers_deinit:
	LayerStack_Deinit(c);
out_free_pools:
	SlidingWindowPool_Free(c->sw_pool);
	CoAPMessagePool_Free(c->mes_pool);
	Mem_free(c_priv);
out_free:
	Mem_free(c);
	c = NULL;
out:
	return c;
}

void Coala_Free(struct Coala *c)
{
	struct Coala_Priv *c_priv;

	if (c == NULL)
		return;

	c_priv = c->priv;

	c_priv->stop = true;
	pthread_join(c_priv->receiver_tid, NULL);
	pthread_join(c_priv->sender_tid, NULL);

	LayerStack_Deinit(c);

	CoAPMessagePool_Free(c->mes_pool);
	SlidingWindowPool_Free(c->sw_pool);
	Coala_FreeResources(c);

	close(c_priv->sock_fd);

	Mem_free(c_priv);
	Mem_free(c);
}

int Coala_SetPrivateKey(struct Coala *c, const uint8_t *k, size_t s)
{
	uint8_t bp[CURVE25519_DONNA_KEY_SIZE] = {9};

	if (c == NULL || k == NULL || s != CURVE25519_DONNA_KEY_SIZE) {
		errno = EINVAL;
		return -1;
	}

	memcpy(c->private_key, k, s);
	curve25519_donna(c->public_key, c->private_key, bp);

	return 0;
}

int Coala_GetRes(struct Coala *c, const char *path,
		 enum CoAPMessage_Code code, res_handler_t *h)
{
	struct ResEntry *e;

	if (c == NULL || path == NULL || h == NULL ||
	    !CoAPMessage_CodeIsRequest(code)) {
		errno = EINVAL;
		return -1;
	}

	*h = NULL;

	SLIST_FOREACH(e, &c->priv->resources_head, list) {
		if (strcmp(e->path, path) != 0)
			continue;

		if (e->mask & BIT(code)) {
			*h = e->handler;
			return 0;
		} else {
			errno = ENOKEY;
			return -1;
		}
	}

	errno = ENOENT;
	return -1;
}

int Coala_AddRes(struct Coala *c, const char *path,
		 unsigned mask, res_handler_t h)
{
	struct ResEntry *e;

	if (c == NULL || path == NULL || !mask || h == NULL) {
		errno = EINVAL;
		return -1;
	}

	if ((e = Mem_calloc(1, sizeof *e)) == NULL)
		return -1;

	e->path = path;
	e->handler = h;
	e->mask = mask;

	SLIST_INSERT_HEAD(&c->priv->resources_head, e, list);

	return 0;
}

int Coala_RemRes(struct Coala *c, const char *path)
{
	struct ResEntry *e, *t;

	if (c == NULL || path == NULL) {
		errno = EINVAL;
		return -1;
	}

	SLIST_FOREACH_SAFE(e, &c->priv->resources_head, list, t) {
		if (!strcmp(e->path, path)) {
			SLIST_REMOVE(&c->priv->resources_head, e, ResEntry,
				     list);
			Mem_free(e);
			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

static void Coala_FreeResources(struct Coala *c)
{
	struct ResEntry *e, *t;

	if (c == NULL)
		return;

	SLIST_FOREACH_SAFE(e, &c->priv->resources_head, list, t) {
		SLIST_REMOVE(&c->priv->resources_head, e, ResEntry, list);
		Mem_free(e);
	}
}

int Coala_Send(struct Coala *c, struct CoAPMessage *m)
{
	if (c == NULL || m == NULL) {
		errno = EINVAL;
		return -1;
	}

	return CoAPMessagePool_Add(c->mes_pool, m, 0);
}
