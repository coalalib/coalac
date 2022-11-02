#include <errno.h>
#include <inttypes.h>

#include <coala/CoAPMessage.h>
#include <coala/khash.h>
#include <coala/queue.h>
#include <ndm/ip_sockaddr.h>
#include <ndm/time.h>

#include "Aead.h"
#include "Err.h"
#include "Hkdf.h"
#include "Private.h"
#include "Sec.h"
#include "SecLayer.h"

				/* <ip>:<port>_<security_id> */
#define KEY_SIZE		sizeof("127.127.127.127:65535_4294967295")

#define HELLO_EXPIRE_SEC	10
#define EXCHANGE_EXPIRE_SEC	(3 * 60)
#define MESSAGE_EXPIRE_SEC	3

enum HandshakeType {
	HandshakeType_Client = 1,
	HandshakeType_Peer
};

enum SessionError {
	SessionError_Expired,
	SessionError_NotFound
};

/*
 * Список сообщений для отправки
 */
struct MsgListEntry {
	bool sent;
	struct CoAPMessage *m;
	struct timespec expire;
	STAILQ_ENTRY(MsgListEntry) list;
};

STAILQ_HEAD(MsgListHead, MsgListEntry);

/*
 * Хэш-таблица
 */
enum SessionState {
	SessionState_Init,
	SessionState_HelloSend,
	SessionState_Exchange
};

struct ProxySecurityId {
	uint32_t id;
	bool set;
};

struct Session {
	enum SessionState state;
	struct Aead *aead;
	struct MsgListHead head;
	struct timespec expire;
	struct ProxySecurityId psi;
};

KHASH_MAP_INIT_STR(SessionMap_t, struct Session *);

static khash_t(SessionMap_t) *SessionMap;
static uint32_t counter_total;

static int SessionMapDel_(khiter_t it)
{
	struct Session *s = kh_val(SessionMap, it);

	struct MsgListEntry *e, *t;
	STAILQ_FOREACH_SAFE(e, &s->head, list, t) {
		CoAPMessage_Free(e->m);
		STAILQ_REMOVE(&s->head, e, MsgListEntry, list);
		free(e);
	}

	Aead_Free(s->aead);
	free(s);

	const char *k = kh_key(SessionMap, it);
	free((void *)k);
	kh_del(SessionMap_t, SessionMap, it);

	return 0;
}

static int SessionMapDel(const char *key)
{
	khiter_t it = kh_get(SessionMap_t, SessionMap, key);
	if (it == kh_end(SessionMap)) {
		errno = ENOENT;
		return -1;
	}

	return SessionMapDel_(it);
}

void SecLayer_Cleaner(void)
{
	for (khiter_t it = kh_begin(SessionMap);
	     it != kh_end(SessionMap);
	     it++) {
		struct MsgListEntry *e, *t;
		struct Session *s;

		if (!kh_exist(SessionMap, it))
			continue;

		s = kh_val(SessionMap, it);

		if (ndm_time_left_monotonic_msec(&s->expire) < 0) {
			SessionMapDel_(it);
			continue;
		}

		STAILQ_FOREACH_SAFE(e, &s->head, list, t) {
			if (!e->sent)
				continue;

			if (ndm_time_left_monotonic_msec(&e->expire) >= 0)
				continue;

			CoAPMessage_Free(e->m);
			STAILQ_REMOVE(&s->head, e, MsgListEntry, list);
			free(e);
		}
	}
}

/*
 * Обработчики
 */
int SecLayer_Init(struct Coala *c, struct Err *err)
{
	if ((SessionMap = kh_init(SessionMap_t)) == NULL) {
		Err_Set(err, errno, "kh_init:");
		return -1;
	}

	/*
	 * Init openssl
	 */

	return 0;
}

void SecLayer_Deinit(struct Coala *c)
{
	for (khiter_t it = kh_begin(SessionMap);
	     it != kh_end(SessionMap);
	     it++) {
		if (!kh_exist(SessionMap, it))
			continue;

		SessionMapDel_(it);
	}

	kh_destroy(SessionMap_t, SessionMap);

	counter_total = 0;
}

static int SharedKeyGen(struct Coala *c, const uint8_t *peer_key,
			uint8_t *shared_key)
{
	int res = 0;
	size_t len = COALA_KEY_SIZE;
	EVP_PKEY *peer = NULL;
	EVP_PKEY_CTX *ctx = NULL;

	if ((peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
			peer_key, COALA_KEY_SIZE)) == NULL ||
	    (ctx = EVP_PKEY_CTX_new(c->key, NULL)) == NULL ||
	    EVP_PKEY_derive_init(ctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
	    EVP_PKEY_derive(ctx, shared_key, &len) <= 0 ||
	    len != COALA_KEY_SIZE)
		res = -1;

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peer);

	return res;
}

static int KeyGen(struct CoAPMessage *m, char *buf, size_t buf_size,
		  struct ProxySecurityId *psi)
{
	char ip[INET_ADDRSTRLEN];
	struct ndm_ip_sockaddr_t sa;

	if (CoAPMessage_GetSockAddr(m, &sa) < 0 ||
	    ndm_ip_sockaddr_ntop(&sa, ip, sizeof ip) == NULL)
		return -1;

	if (psi)
		memset(psi, 0, sizeof *psi);

	uint32_t id;
	if (!CoAPMessage_GetProxySecurityId(m, &id)) {
		snprintf(buf, buf_size, "%s:%" PRIu16 "_%" PRIu32,
			 ip, ndm_ip_sockaddr_port(&sa), id);

		if (psi) {
			psi->set = true;
			psi->id = id;
		}
	} else {
		snprintf(buf, buf_size, "%s:%" PRIu16,
			 ip, ndm_ip_sockaddr_port(&sa));
	}

	return 0;
}

static bool IsHello(struct CoAPMessage *m, enum HandshakeType ht)
{
	int t;
	uint32_t v;

	t = CoAPMessage_GetType(m);

	if (ht == HandshakeType_Client &&
	    t != CoAPMessage_TypeCon)
		return false;

	if (ht == HandshakeType_Peer &&
	    t != CoAPMessage_TypeAck)
		return false;

	if ((CoAPMessage_GetOptionUint(m, CoAPMessage_OptionCodeHandshakeType,
				       &v)) < 0 ||
	    v != ht)
		return false;

	return true;
}

static int MsgListSendEncrypt(struct Coala *c, int fd, struct Session *s,
			      struct Err *err)
{
	struct MsgListEntry *e, *t;
	STAILQ_FOREACH_SAFE(e, &s->head, list, t) {
		const unsigned cflags = CoAPMessage_CloneFlagCb;
		struct CoAPMessage *m;

		if (e->sent)
			continue;

		if ((m = CoAPMessage_Clone(e->m, cflags)) == NULL) {
			Err_Set(err, errno, "CoAPMessage_Clone:");
			return -1;
		}

		if (s->psi.set &&
		    CoAPMessage_SetProxySecurityId(m, s->psi.id) < 0) {
			Err_Set(err, errno, "CoAPMessage_SetProxySecurityId:");
			CoAPMessage_Free(m);
			return -1;
		}

		if (Sec_PayloadEncrypt(e->m, m, s->aead, err) < 0 ||
		    Sec_UriEncrypt(m, s->aead, err) < 0 ||
		    Sec_CookieEncrypt(m, s->aead, err) < 0) {
			CoAPMessage_Free(m);
			return -1;
		}

		CoAPMessage_SetFlag(m, SECLAYER_FLAG_SKIP_BLK_SEC);

		if (Coala_Send(c, fd, m) < 0) {
			Err_Set(err, errno, "Coala_Send:");
			CoAPMessage_Free(m);
			return -1;
		}

		CoAPMessage_Free(m);

		ndm_time_get_monotonic(&e->expire);
		ndm_time_add_sec(&e->expire, MESSAGE_EXPIRE_SEC);
		e->sent = true;
	}

	return 0;
}

static enum LayerStack_Ret
SecLayer_OnReceive_HelloPeer(struct Coala *c,
			     int fd,
			     struct CoAPMessage *msg,
			     unsigned flags,
			     struct Err *err)
{
	/* Содержит ключ? */
	uint8_t *data;
	size_t data_size;
	if ((data = CoAPMessage_GetPayload(msg, &data_size, 0)) == NULL ||
	    data_size != COALA_KEY_SIZE) {
		return LayerStack_Stop;
	}

	char key[KEY_SIZE];
	if (KeyGen(msg, key, sizeof key, NULL) < 0) {
		Err_Set(err, errno, "KeyGen:");
		return LayerStack_Err;
	}

	/* Нет записи в хэш-таблице? */
	khiter_t it = kh_get(SessionMap_t, SessionMap, key);
	if (it == kh_end(SessionMap))
		/* Игнорируем сообщение */
		return LayerStack_Stop;

	/* Генерация shared key */
	uint8_t shared[COALA_KEY_SIZE];
	if (SharedKeyGen(c, data, shared) < 0) {
		Err_Set(err, 0, "SharedKeyGen");
		return LayerStack_Err;
	}

	/* Усиление ключа */
	struct Hkdf_Out okm;
	if (Hkdf(shared, sizeof shared, &okm) < 0) {
		Err_Set(err, 0, "Hkdf");
		return LayerStack_Err;
	}

	struct Aead *aead;
	if ((aead = Aead(okm.peer_key, sizeof okm.peer_key,
			 okm.my_key, sizeof okm.my_key,
			 okm.peer_IV, sizeof okm.peer_IV,
			 okm.my_IV, sizeof okm.my_IV)) == NULL) {
		Err_Set(err, errno, "aead:");
		return LayerStack_Err;
	}

	struct Session *s = kh_val(SessionMap, it);
	s->aead = aead;
	ndm_time_get_monotonic(&s->expire);
	ndm_time_add_sec(&s->expire, EXCHANGE_EXPIRE_SEC);
	s->state = SessionState_Exchange;

	/* Отправка сообщений с подменой payload и опций */
	if (MsgListSendEncrypt(c, fd, s, err) < 0)
		return LayerStack_Err;

	/* Пропускаем дальше для удаление парного */
	return LayerStack_Con;
}

static int SendHello(struct Coala *c, int fd, struct CoAPMessage *msg,
		     enum HandshakeType htype, struct Err *err)
{
	int code, type, id;
	if (htype == HandshakeType_Client) {
		type = CoAPMessage_TypeCon;
		code = CoAPMessage_CodeGet;
		id = -1;
	} else {
		type = CoAPMessage_TypeAck;
		code = CoAPMessage_CodeContent;
		id = CoAPMessage_GetId(msg);
	}

	struct CoAPMessage *m;
	if ((m = CoAPMessage(type, code, id, 0)) == NULL) {
		Err_Set(err, errno, "CoAPMessage:");
		return -1;
	}

	CoAPMessage_CopyCb(m, msg);
	CoAPMessage_SetFlag(m, SECLAYER_FLAG_CB_ONLY_ERR);

	CoAPMessage_CopySockAddr(m, msg);
	CoAPMessage_CopyToken(m, msg);
	CoAPMessage_CopyProxySecurityId(m, msg);


	if (CoAPMessage_AddOptionUint(m,
				CoAPMessage_OptionCodeHandshakeType,
				htype) < 0) {
		Err_Set(err, errno, "CoAPMessage_AddOptionUint:");
		CoAPMessage_Free(m);
		return -1;
	}

	uint8_t public_key[COALA_KEY_SIZE];
	size_t len = sizeof public_key;
	if (!EVP_PKEY_get_raw_public_key(c->key, public_key, &len) ||
	    len != sizeof public_key)
	{
		Err_Set(err, 0, "EVP_PKEY_get_raw_public_key");
		CoAPMessage_Free(m);
		return -1;
	}

	if (CoAPMessage_SetPayload(m, public_key, sizeof public_key) < 0) {
		Err_Set(err, errno, "CoAPMessage_AddOptionUint:");
		CoAPMessage_Free(m);
		return -1;
	}

	if (Coala_Send(c, fd, m) < 0) {
		Err_Set(err, errno, "Coala_Send:");
		CoAPMessage_Free(m);
		return -1;
	}

	CoAPMessage_Free(m);
	return 0;
}

static enum LayerStack_Ret
SecLayer_OnReceive_HelloClient(struct Coala *c,
			       int fd,
			       struct CoAPMessage *msg,
			       unsigned flags,
			       struct Err *err)
{
	int ret;
	uint8_t *data;
	size_t data_size;
	if ((data = CoAPMessage_GetPayload(msg, &data_size, 0)) == NULL ||
	    data_size != COALA_KEY_SIZE) {
		return LayerStack_Stop;
	}

	char key[KEY_SIZE];
	struct ProxySecurityId psi;
	if (KeyGen(msg, key, sizeof key, &psi) < 0)
	{
		Err_Set(err, errno, "KeyGen:");
		return LayerStack_Err;
	}

	SessionMapDel(key);

	/* Создание сессии */
	char *k;
	if ((k = strdup(key)) == NULL) {
		Err_Set(err, errno, "strdup:");
		return LayerStack_Err;
	}

	khiter_t it;
	if ((it = kh_put(SessionMap_t, SessionMap, k, &ret)),
	    ret < 0) {
		Err_Set(err, errno, "kh_put:");
		free(k);
		return LayerStack_Err;
	}

	struct Session *s;
	if ((s = calloc(1, sizeof *s)) == NULL) {
		Err_Set(err, errno, "malloc:");
		kh_del(SessionMap_t, SessionMap, it);
		free(k);
		return LayerStack_Err;
	}

	STAILQ_INIT(&s->head);
	kh_val(SessionMap, it) = s;

	counter_total++;

	/* Генерация shared key */
	uint8_t shared[COALA_KEY_SIZE];
	if (SharedKeyGen(c, data, shared) < 0) {
		Err_Set(err, 0, "SharedKeyGen");
		return LayerStack_Err;
	}

	/* Усиление ключа */
	struct Hkdf_Out okm;
	if (Hkdf(shared, sizeof shared, &okm) < 0) {
		Err_Set(err, 0, "Hkdf");
		return LayerStack_Err;
	}

	struct Aead *aead;
	if ((aead = Aead(okm.my_key, sizeof okm.my_key,
			 okm.peer_key, sizeof okm.peer_key,
			 okm.my_IV, sizeof okm.my_IV,
			 okm.peer_IV, sizeof okm.peer_IV)) == NULL) {
		Err_Set(err, errno, "aead:");
		return LayerStack_Err;
	}

	s->aead = aead;
	ndm_time_get_monotonic(&s->expire);
	ndm_time_add_sec(&s->expire, EXCHANGE_EXPIRE_SEC);
	s->state = SessionState_Exchange;
	s->psi = psi;

	/* Отправка публичного ключа */
	if (SendHello(c, fd, msg, HandshakeType_Peer, err) < 0)
		return LayerStack_Err;

	return LayerStack_Stop;
}

static int SendUnauthorized(struct Coala *c, int fd, struct CoAPMessage *msg,
			    enum CoAPMessage_OptionCode code,
			    struct Err *err)
{
	struct CoAPMessage *m;
	if ((m = CoAPMessage(CoAPMessage_TypeAck,
			     CoAPMessage_CodeUnauthorized,
			     CoAPMessage_GetId(msg), 0)) == NULL) {
		Err_Set(err, errno, "CoAPMessage:");
		return -1;
	}

	CoAPMessage_CopySockAddr(m, msg);
	CoAPMessage_CopyToken(m, msg);
	CoAPMessage_CopyProxySecurityId(m, msg);

	if (CoAPMessage_AddOptionUint(m, code, 1) < 0) {
		Err_Set(err, errno, "CoAPMessage_AddOptionUint:");
		CoAPMessage_Free(m);
		return -1;
	}

	if (Coala_Send(c, fd, m) < 0) {
		Err_Set(err, errno, "Coala_Send:");
		CoAPMessage_Free(m);
		return -1;
	}

	CoAPMessage_Free(m);

	return 0;
}


static enum LayerStack_Ret
SecLayer_OnReceive_Secure(struct Coala *c,
			  int fd,
			  struct CoAPMessage *msg,
			  unsigned flags,
			  struct Err *err)
{
	char key[KEY_SIZE];
	int ret;

	if (KeyGen(msg, key, sizeof key, NULL) < 0)
	{
		Err_Set(err, errno, "KeyGen:");
		return LayerStack_Err;
	}

	khiter_t it = kh_get(SessionMap_t, SessionMap, key);
	if (it == kh_end(SessionMap)) {
		if (CoAPMessage_IsRequest(msg)) {
			if (SendUnauthorized(c, fd, msg,
					CoAPMessage_OptionCodeSessionNotFound,
					err) < 0)
				return LayerStack_Err;
		}

		return LayerStack_Stop;
	}

	struct Session *s = kh_val(SessionMap, it);
	if (s->state != SessionState_Exchange)
		/* XXX: Сессия устанавливается => игнорирование */
		return LayerStack_Stop;

	if ((ret = Sec_PayloadDecrypt(msg, s->aead, err)) < 0 ||
	    (ret = Sec_UriDecrypt(msg, s->aead, err)) < 0 ||
	    (ret = Sec_CookieDecrypt(msg, s->aead, err)) < 0) {
		if (ret == -1) {
			Err_Set(err, errno, "Decrypt:");
			return LayerStack_Err;
		} else if (ret == -2) {
			int opt = CoAPMessage_OptionCodeSessionExpired;

			if (SendUnauthorized(c, fd, msg, opt, err) < 0)
				return LayerStack_Err;

			return LayerStack_Stop;
		}
	}

	ndm_time_get_monotonic(&s->expire);
	ndm_time_add_sec(&s->expire, EXCHANGE_EXPIRE_SEC);

	return LayerStack_Con;
}

static bool IsSessionError(struct CoAPMessage *m, enum SessionError se)
{
	const int o_expired = CoAPMessage_OptionCodeSessionExpired;
	const int o_nofound = CoAPMessage_OptionCodeSessionNotFound;
	uint32_t v;

	if (CoAPMessage_GetType(m) != CoAPMessage_TypeAck)
		return false;

	if (CoAPMessage_GetCode(m) != CoAPMessage_CodeUnauthorized)
		return false;

	if (se == SessionError_NotFound &&
	    !CoAPMessage_GetOptionUint(m, o_nofound, &v))
		return true;

	if (se == SessionError_Expired &&
	    !CoAPMessage_GetOptionUint(m, o_expired, &v))
		return true;

	return false;
}

enum LayerStack_Ret
SecLayer_OnReceive_Expired(
	struct Coala *c,
	struct CoAPMessage *msg,
	unsigned flags,
	struct Err *err)
{
	char key[KEY_SIZE];

	if (KeyGen(msg, key, sizeof key, NULL) < 0)
	{
		Err_Set(err, errno, "KeyGen:");
		return LayerStack_Err;
	}

	SessionMapDel(key);

	return LayerStack_Con;
}

enum LayerStack_Ret
SecLayer_OnReceive_NotFound(
	struct Coala *c,
	int fd,
	struct CoAPMessage *msg,
	unsigned flags,
	struct Err *err)
{
	bool found = false;
	char key[KEY_SIZE];
	struct MsgListEntry *e;
	struct Session *s;

	if (KeyGen(msg, key, sizeof key, NULL) < 0)
	{
		Err_Set(err, errno, "KeyGen:");
		return LayerStack_Err;
	}

	khiter_t it = kh_get(SessionMap_t, SessionMap, key);
	if (it == kh_end(SessionMap))
		return LayerStack_Stop;

	s = kh_val(SessionMap, it);

	STAILQ_FOREACH(e, &s->head, list) {
		const unsigned eflags = CoAPMessage_EqualsFlagOnlyId |
					CoAPMessage_EqualsFlagOnlyToken;

		if (CoAPMessage_Equals(msg, e->m, eflags) != 1)
			continue;

		e->sent = false;
		found = true;
		break;
	}

	if (found && s->state == SessionState_Exchange) {
		Aead_Free(s->aead);
		s->aead = NULL;
		s->state = SessionState_Init;

		if (SendHello(c, fd, msg, HandshakeType_Client, err) < 0)
			return LayerStack_Err;

		ndm_time_get_monotonic(&s->expire);
		ndm_time_add_sec(&s->expire, HELLO_EXPIRE_SEC);
		s->state = SessionState_HelloSend;
	}

	return LayerStack_Stop;
}

enum LayerStack_Ret
SecLayer_OnReceive(
	struct Coala *c,
	int fd,
	struct CoAPMessage *msg,
	unsigned flags,
	struct Err *err)
{
	Err_Init(err, __func__);

	if (IsHello(msg, HandshakeType_Peer))
		return SecLayer_OnReceive_HelloPeer(c, fd, msg, flags, err);
	else if (IsHello(msg, HandshakeType_Client))
		return SecLayer_OnReceive_HelloClient(c, fd, msg, flags, err);
	else if (CoAPMessage_IsSecure(msg))
		return SecLayer_OnReceive_Secure(c, fd, msg, flags, err);
	else if (IsSessionError(msg, SessionError_Expired))
		return SecLayer_OnReceive_Expired(c, msg, flags, err);
	else if (IsSessionError(msg, SessionError_NotFound))
		return SecLayer_OnReceive_NotFound(c, fd, msg, flags, err);

	return LayerStack_Con;
}

enum LayerStack_Ret
SecLayer_OnSend(
	struct Coala *c,
	int fd,
	struct CoAPMessage *msg,
	unsigned flags,
	struct Err *err)
{
	if (CoAPMessage_TestFlag(msg, 0))
		return LayerStack_Con;

	if (!CoAPMessage_IsSecure(msg))
		return LayerStack_Con;

	Err_Init(err, __func__);

	/* Формирование ключа */
	char key[KEY_SIZE];
	if (KeyGen(msg, key, sizeof key, NULL) < 0)
	{
		Err_Set(err, errno, "KeyGen:");
		return LayerStack_Err;
	}

	/* Нет записи в хэш-таблице? */
	khiter_t it = kh_get(SessionMap_t, SessionMap, key);
	if (it == kh_end(SessionMap)) {
		/* Создание записи */
		char *k;
		if ((k = strdup(key)) == NULL) {
			Err_Set(err, errno, "strdup:");
			return LayerStack_Err;
		}

		int ret;
		if ((it = kh_put(SessionMap_t, SessionMap, k, &ret)),
		    ret < 0) {
			Err_Set(err, errno, "kh_put:");
			free(k);
			return LayerStack_Err;
		}

		struct Session *s;
		if ((s = calloc(1, sizeof *s)) == NULL) {
			Err_Set(err, errno, "malloc:");
			kh_del(SessionMap_t, SessionMap, it);
			free(k);
			return LayerStack_Err;
		}

		s->state = SessionState_Init;
		STAILQ_INIT(&s->head);
		kh_val(SessionMap, it) = s;

		counter_total++;
	}

	/* Запись сообщения в список из хэш-таблицы */
	struct Session *s = kh_val(SessionMap, it);

	struct MsgListEntry *e;
	if ((e = calloc(1, sizeof *e)) == NULL) {
		Err_Set(err, errno, "calloc:");
		return LayerStack_Err;
	}

	if ((e->m = CoAPMessage_Clone(msg,
				      CoAPMessage_CloneFlagCb |
				      CoAPMessage_CloneFlagPayload)) == NULL) {
		Err_Set(err, errno, "CoAPMessage_Clone:");
		free(e);
		return LayerStack_Err;
	}

	STAILQ_INSERT_TAIL(&s->head, e, list);

	if (s->state == SessionState_Init) {
		/* Новая сессия => отправка публичного ключа */
		if (SendHello(c, fd, msg, HandshakeType_Client, err) < 0)
			return LayerStack_Err;

		ndm_time_get_monotonic(&s->expire);
		ndm_time_add_sec(&s->expire, HELLO_EXPIRE_SEC);
		s->state = SessionState_HelloSend;
	} else if (s->state == SessionState_Exchange) {
		/* Установленная => отправка всех незашифрованных */
		if (MsgListSendEncrypt(c, fd, s, err) < 0)
			return LayerStack_Err;

		ndm_time_get_monotonic(&s->expire);
		ndm_time_add_sec(&s->expire, EXCHANGE_EXPIRE_SEC);
	}

	return LayerStack_Stop;
}

int SecLayer_Stats(struct SecLayer_Stats *st)
{
	if (st == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(st, 0, sizeof(*st));
	st->current = kh_size(SessionMap);
	st->total = counter_total;

	return 0;
}
