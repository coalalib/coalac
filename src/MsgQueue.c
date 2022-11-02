#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <coala/queue.h>
#include <coala/Coala.h>
#include <coala/CoAPMessage.h>
#include <ndm/time.h>
#include "constants.h"

#include "MsgQueue.h"

struct MsgQueueEntry {
	int fd;
	struct CoAPMessage *m;
	struct timespec expire;
	unsigned char attemp;
	unsigned char max_attemps;
	TAILQ_ENTRY(MsgQueueEntry) list;
};

static TAILQ_HEAD(MsgQueueHead, MsgQueueEntry) QueueHead =
	TAILQ_HEAD_INITIALIZER(QueueHead);

static void MsgQueueEntryFree(struct MsgQueueEntry *e)
{
	if (e == NULL)
		return;

	CoAPMessage_Free(e->m);
	free(e);
}

int MsgQueue_Add(int fd, struct CoAPMessage *m)
{
	struct MsgQueueEntry *e;

	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (MsgQueue_Get(m) != NULL)
		return 0;

	if ((e = calloc(1, sizeof(*e))) == NULL)
		return -1;

	if ((e->m = CoAPMessage_Clone(m,
			CoAPMessage_CloneFlagCb |
			CoAPMessage_CloneFlagPayload)) == NULL) {
		int errsv = errno;
		free(e);
		errno = errsv;
		return -1;
	}

	e->fd = fd;
	e->attemp = 1;
	e->max_attemps = CoAPMessage_IsMulticast(m) ? 1 : MAX_ATTEMPS;

	ndm_time_get_monotonic(&e->expire);
	ndm_time_add_msec(&e->expire, EXPIRATION_TIME);

	TAILQ_INSERT_TAIL(&QueueHead, e, list);

	return 0;
}

void MsgQueue_Free(void)
{
	struct MsgQueueEntry *e, *t;

	TAILQ_FOREACH_SAFE(e, &QueueHead, list, t) {
		TAILQ_REMOVE(&QueueHead, e, list);
		MsgQueueEntryFree(e);
	}
}

int MsgQueue_RemoveAll(struct CoAPMessage *m){
	int res = -1;
	struct MsgQueueEntry *e, *t;

	int removeCount = 0;

	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}
	TAILQ_FOREACH_SAFE(e, &QueueHead, list, t) {
		const unsigned eflags = CoAPMessage_EqualsFlagOnlyToken;

		if (CoAPMessage_Equals(m, e->m, eflags) != 1)
			continue;

		TAILQ_REMOVE(&QueueHead, e, list);
		removeCount += 1;
		res = 0;
	}
	MsgQueueEntryFree(e);
	if (res == -1)
		errno = ENOENT;

	return res;
}

int MsgQueue_Remove(struct CoAPMessage *m)
{
	int res = -1;
	struct MsgQueueEntry *e, *t;

	if (m == NULL) {
		errno = EINVAL;
		return -1;
	}

	TAILQ_FOREACH_SAFE(e, &QueueHead, list, t) {
		const unsigned eflags = CoAPMessage_EqualsFlagOnlyId |
					CoAPMessage_EqualsFlagOnlyToken;

		if (CoAPMessage_Equals(m, e->m, eflags) != 1)
			continue;

		TAILQ_REMOVE(&QueueHead, e, list);
		MsgQueueEntryFree(e);

		res = 0;
		break;
	}

	if (res == -1)
		errno = ENOENT;

	return res;
}

struct CoAPMessage *MsgQueue_Get(struct CoAPMessage *m)
{
	int id;
	size_t s;
	struct MsgQueueEntry *e;
	uint8_t t[COAP_MESSAGE_MAX_TOKEN_SIZE];

	if (m == NULL) {
		errno = EINVAL;
		return NULL;
	}

	id = CoAPMessage_GetId(m);

	s = sizeof t;
	CoAPMessage_GetToken(m, t, &s);

	TAILQ_FOREACH(e, &QueueHead, list) {
		size_t m_s;
		uint8_t m_t[COAP_MESSAGE_MAX_TOKEN_SIZE];

		if (id != CoAPMessage_GetId(e->m))
			continue;

		m_s = sizeof m_t;
		CoAPMessage_GetToken(e->m, m_t, &m_s);

		if (s != m_s)
			continue;

		if (memcmp(t, m_t, s) != 0)
			continue;

		return e->m;
	}

	errno = ENOENT;
	return NULL;
}

void MsgQueue_Tick(struct Coala *c)
{
	struct MsgQueueEntry *e, *t;

	TAILQ_FOREACH_SAFE(e, &QueueHead, list, t) {
		if (ndm_time_left_monotonic_msec(&e->expire) >= 0)
			continue;

		if (e->attemp < e->max_attemps)  {
			/* resend */
			Coala_Send(c, e->fd, e->m);
			ndm_time_get_monotonic(&e->expire);
			ndm_time_add_msec(&e->expire, EXPIRATION_TIME);
			e->attemp++;
		} else {
			/* remove */
			CoAPMessage_Cb_t cb = NULL;
			void *arg = NULL;

			if (!CoAPMessage_GetCb(e->m, &cb, &arg) &&
			    cb)
				cb(c, e->fd, CoAPMessage_CbErrExpire, NULL, arg);

			TAILQ_REMOVE(&QueueHead, e, list);
			MsgQueueEntryFree(e);
		}
	}
}
