#include <coala/Coala.h>
#include <coala/CoAPMessage.h>
#include <coala/Mem.h>
#include <coala/khash.h>
#include <coala/queue.h>
#include <ndm/ip_sockaddr.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <errno.h>
#include <pthread.h>

#include "Aead.h"
#include "CoAPMessagePool.h"
#include "Err.h"
#include "SecurityLayer.h"
#include "curve25519-donna.h"

#define KEY_SIZE	sizeof("127.127.127.127:1234")

enum HandshakeType {
	HandshakeType_Client = 1,
	HandshakeType_Peer
};

/*
 * Список сообщений для отправки
 */
struct MsgListEntry {
	struct CoAPMessage *m;
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

struct Session {
	enum SessionState state;
	struct Aead *aead;
	struct MsgListHead head;
};

KHASH_MAP_INIT_STR(SessionMap_t, struct Session *);

static khash_t(SessionMap_t) *SessionMap;

static pthread_mutex_t SessionMapMutex = PTHREAD_MUTEX_INITIALIZER;

static int SessionMapDel(const char *key)
{
	khiter_t it = kh_get(SessionMap_t, SessionMap, key);
	if (it == kh_end(SessionMap)) {
		errno = ENOENT;
		return -1;
	}

	struct Session *s = kh_val(SessionMap, it);

	struct MsgListEntry *e, *t;
	STAILQ_FOREACH_SAFE(e, &s->head, list, t) {
		CoAPMessage_Decref(e->m);
		STAILQ_REMOVE(&s->head, e, MsgListEntry, list);
		Mem_free(e);
	}

	Aead_Free(s->aead);
	Mem_free(s);

	const char *k = kh_key(SessionMap, it);
	Mem_free((void *)k);
	kh_del(SessionMap_t, SessionMap, it);

	return 0;
}

struct HkdfOut {
	uint8_t peer_key[16];
	uint8_t my_key[16];
	uint8_t peer_IV[4];
	uint8_t my_IV[4];
};

int Hkdf(const uint8_t *key, size_t key_size, struct HkdfOut *out)
{
	if (key == NULL || !key_size || out == NULL)
		return -1;

	EVP_PKEY_CTX *pctx;
	if ((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)) == NULL)
		return -1;

	size_t s = sizeof(*out);
	if (EVP_PKEY_derive_init(pctx) <= 0 ||
	    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
	    EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_size) <= 0 ||
	    EVP_PKEY_derive(pctx, (uint8_t *)out, &s) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	EVP_PKEY_CTX_free(pctx);
	return 0;
}

/*
 * Обработчики
 */
int SecurityLayer_Init(struct Coala *c,
			struct Err *err)
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

void SecurityLayer_Deinit(struct Coala *c)
{
	for (khiter_t it = kh_begin(SessionMap);
	     it != kh_end(SessionMap);
	     it++) {
		if (!kh_exist(SessionMap, it))
			continue;

		struct Session *s = kh_val(SessionMap, it);

		struct MsgListEntry *e, *t;
		STAILQ_FOREACH_SAFE(e, &s->head, list, t) {
			CoAPMessage_Decref(e->m);
			STAILQ_REMOVE(&s->head, e, MsgListEntry, list);
			Mem_free(e);
		}

		Aead_Free(s->aead);
		Mem_free(s);

		const char *k = kh_key(SessionMap, it);
		Mem_free((void *)k);
	}

	kh_destroy(SessionMap_t, SessionMap);
}

static void KeyGen(struct CoAPMessage *m, char *buf, size_t buf_size)
{
	struct ndm_ip_sockaddr_t sa;
	CoAPMessage_GetSockAddr(m, &sa);

	char ip[NDM_IP_SOCKADDR_LEN];
	ndm_ip_sockaddr_ntop(&sa, ip, sizeof ip);

	snprintf(buf, buf_size, "%s:%u",
		 ip,
		 (unsigned)ndm_ip_sockaddr_port(&sa));
}

static bool IsHelloClient(struct CoAPMessage *m)
{
	if (CoAPMessage_GetType(m) != CoAPMessage_TypeCon)
		return false;

	uint32_t v;
	if ((CoAPMessage_GetOptionUint(m, CoAPMessage_OptionCodeHandshakeType,
                                       &v)) < 0 ||
	    v != HandshakeType_Client)
		return false;

	return true;
}

static bool IsHelloPeer(struct CoAPMessage *m)
{
	if (CoAPMessage_GetType(m) != CoAPMessage_TypeAck)
		return false;

	uint32_t v;
	if ((CoAPMessage_GetOptionUint(m, CoAPMessage_OptionCodeHandshakeType,
                                       &v)) < 0 ||
	    v != HandshakeType_Peer)
		return false;

	return true;
}

static int EncryptPayload(struct CoAPMessage *m, struct Aead *aead,
			  struct Err *err)
{
	uint8_t *d;
	size_t d_size;
	if ((d = CoAPMessage_GetPayload(m, &d_size, 0)) == NULL)
		return 0;

	uint8_t *enc;
	size_t enc_size = d_size + AEAD_TAG_SIZE;
	if ((enc = Mem_malloc(enc_size)) == NULL) {
		Err_Set(err, errno, "Mem_malloc:");
		return -1;
	}

	if (Aead_Seal(aead, d, d_size,
		      CoAPMessage_GetId(m),
		      NULL, 0,
		      enc, &enc_size) < 0) {
		Err_Set(err, 0, "Aead_Seal");
		Mem_free(enc);
		return -1;
	}

	if (CoAPMessage_SetPayload(m, enc, enc_size) < 0) {
		Err_Set(err, errno, "CoAPMessage_SetPayload:");
		Mem_free(enc);
		return -1;
	}

	Mem_free(enc);
	return 0;
}

static int EncryptUri(struct CoAPMessage *m, struct Aead *aead,
		      struct Err *err)
{
	int res = -1;
	char *uri = NULL;
	uint8_t *enc = NULL;

	if ((uri = CoAPMessage_GetUri(m, true)) == NULL) {
		Err_Set(err, errno, "CoAPMessage_GetUri:");
		goto out;
	}

	size_t enc_size = strlen(uri) + AEAD_TAG_SIZE;
	if ((enc = Mem_malloc(enc_size)) == NULL) {
		Err_Set(err, errno, "Mem_malloc:");
		goto out;
	}

	if (Aead_Seal(aead, (uint8_t *)uri, strlen(uri),
		      CoAPMessage_GetId(m),
		      NULL, 0,
		      enc, &enc_size) < 0) {
		Err_Set(err, 0, "Aead_Seal");
		goto out;
	}

	CoAPMessage_RemoveOptions(m,
			CoAPMessage_OptionCodeUriPath);
	CoAPMessage_RemoveOptions(m,
			CoAPMessage_OptionCodeUriQuery);

	if (CoAPMessage_AddOptionOpaque(m,
				CoAPMessage_OptionCodeCoapsUri,
				enc,
				enc_size) < 0) {
		Err_Set(err, errno, "CoAPMessage_AddOptionOpaque:");
		goto out;
	}

	res = 0;
out:
	Mem_free(enc);
	Mem_free(uri);
	return res;
}

static int MsgListSendEncrypt(struct Coala *c, struct MsgListHead *h,
			      struct Aead *aead, struct Err *err)
{
	struct MsgListEntry *e, *t;
	STAILQ_FOREACH_SAFE(e, h, list, t) {
		if (EncryptPayload(e->m, aead, err) < 0 ||
		    EncryptUri(e->m, aead, err) < 0)
			return -1;

		if (CoAPMessagePool_Add(c->mes_pool, e->m,
				        CoAPMessagePool_SkipArq |
				        CoAPMessagePool_SkipSec) < 0) {
			Err_Set(err, errno, "CoAPMessagePool_Add:");
			return -1;
		}

		CoAPMessage_Decref(e->m);

		STAILQ_REMOVE(h, e, MsgListEntry, list);
		Mem_free(e);
	}

	return 0;
}

static enum LayerStack_Ret
SecurityLayer_OnReceive_HelloPeer(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	/* Содержит ключ? */
	uint8_t *data;
	size_t data_size;
	if ((data = CoAPMessage_GetPayload(msg, &data_size, 0)) == NULL ||
	    data_size != CURVE25519_DONNA_KEY_SIZE) {
		return LayerStack_Stop;
	}

	char key[KEY_SIZE];
	KeyGen(msg, key, sizeof key);

	int ret;
	if ((ret = pthread_mutex_lock(&SessionMapMutex))) {
		Err_Set(err, ret, "pthread_mutex_lock");
		return LayerStack_Err;
	}

	/* Нет записи в хэш-таблице? */
	khiter_t it = kh_get(SessionMap_t, SessionMap, key);
	if (it == kh_end(SessionMap)) {
		/* Игнорируем сообщение */
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Stop;
	}

	/* Генерация shared key */
	uint8_t shared[CURVE25519_DONNA_KEY_SIZE];
	curve25519_donna(shared, c->private_key, data);

	/* Усиление ключа */
	struct HkdfOut okm;
	if (Hkdf(shared, sizeof shared, &okm) != 0) {
		Err_Set(err, 0, "Hkdf");
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Err;
	}

	struct Aead *aead;
	if ((aead = Aead(okm.peer_key, sizeof okm.peer_key,
			 okm.my_key, sizeof okm.my_key,
			 okm.peer_IV, sizeof okm.peer_IV,
			 okm.my_IV, sizeof okm.my_IV)) == NULL) {
		Err_Set(err, errno, "aead:");
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Err;
	}

	struct Session *s = kh_val(SessionMap, it);
	s->aead = aead;
	s->state = SessionState_Exchange;

	/* Отправка сообщений с подменой payload и опций */
	if (MsgListSendEncrypt(c, &s->head, aead, err) < 0) {
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Err;
	}

	pthread_mutex_unlock(&SessionMapMutex);
	/* Пропускаем дальше для удаление парного */
	return LayerStack_Con;
}

static int SendHello(struct Coala *c, struct CoAPMessage *msg,
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
	if ((m = CoAPMessage(type, code, id)) == NULL) {
		Err_Set(err, errno, "CoAPMessage:");
		return -1;
	}

	CoAPMessage_CopySockAddr(m, msg);
	CoAPMessage_CopyToken(m, msg);

	if (CoAPMessage_AddOptionUint(m,
				CoAPMessage_OptionCodeHandshakeType,
				htype) < 0) {
		Err_Set(err, errno, "CoAPMessage_AddOptionUint:");
		CoAPMessage_Decref(m);
		return -1;
	}

	if (CoAPMessage_SetPayload(m, c->public_key,
				   sizeof c->public_key) < 0) {
		Err_Set(err, errno, "CoAPMessage_AddOptionUint:");
		CoAPMessage_Decref(m);
		return -1;
	}

	if (Coala_Send(c, m) < 0) {
		Err_Set(err, errno, "Coala_Send:");
		CoAPMessage_Decref(m);
		return -1;
	}

	CoAPMessage_Decref(m);
	return 0;
}

static enum LayerStack_Ret
SecurityLayer_OnReceive_HelloClient(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	uint8_t *data;
	size_t data_size;
	if ((data = CoAPMessage_GetPayload(msg, &data_size, 0)) == NULL ||
	    data_size != CURVE25519_DONNA_KEY_SIZE) {
		return LayerStack_Stop;
	}

	int ret;
	if ((ret = pthread_mutex_lock(&SessionMapMutex))) {
		Err_Set(err, ret, "pthread_mutex_lock");
		return LayerStack_Err;
	}

	char key[KEY_SIZE];
	KeyGen(msg, key, sizeof key);

	SessionMapDel(key);

	/* Создание сессии */
	char *k;
	if ((k = Mem_strdup(key)) == NULL) {
		Err_Set(err, errno, "Mem_strdup:");
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Err;
	}

	khiter_t it;
	if ((it = kh_put(SessionMap_t, SessionMap, k, &ret)),
	    ret < 0) {
		Err_Set(err, errno, "kh_put:");
		Mem_free(k);
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Err;
	}

	struct Session *s;
	if ((s = Mem_calloc(1, sizeof *s)) == NULL) {
		Err_Set(err, errno, "Mem_malloc:");
		kh_del(SessionMap_t, SessionMap, it);
		Mem_free(k);
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Err;
	}

	STAILQ_INIT(&s->head);
	kh_val(SessionMap, it) = s;

	/* Генерация shared key */
	uint8_t shared[CURVE25519_DONNA_KEY_SIZE];
	curve25519_donna(shared, c->private_key, data);

	/* Усиление ключа */
	struct HkdfOut okm;
	if (Hkdf(shared, sizeof shared, &okm) < 0) {
		Err_Set(err, 0, "Hkdf");
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Err;
	}

	struct Aead *aead;
	if ((aead = Aead(okm.my_key, sizeof okm.my_key,
			 okm.peer_key, sizeof okm.peer_key,
			 okm.my_IV, sizeof okm.my_IV,
			 okm.peer_IV, sizeof okm.peer_IV)) == NULL) {
		Err_Set(err, errno, "aead:");
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Err;
	}

	s->aead = aead;
	s->state = SessionState_Exchange;

	/* Отправка публичного ключа */
	if (SendHello(c, msg, HandshakeType_Peer, err) < 0) {
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Err;
	}

	pthread_mutex_unlock(&SessionMapMutex);

	return LayerStack_Stop;
}

static int SendUnauthorized(struct Coala *c, struct CoAPMessage *msg,
			    enum CoAPMessage_OptionCode code,
			    struct Err *err)
{
	struct CoAPMessage *m;
	if ((m = CoAPMessage(CoAPMessage_TypeAck,
			     CoAPMessage_CodeUnauthorized,
			     CoAPMessage_GetId(msg))) == NULL) {
		Err_Set(err, errno, "CoAPMessage:");
		return -1;
	}

	CoAPMessage_CopySockAddr(m, msg);
	CoAPMessage_CopyToken(m, msg);

	if (CoAPMessage_AddOptionUint(m, code, 1) < 0) {
		Err_Set(err, errno, "CoAPMessage_AddOptionUint:");
		CoAPMessage_Decref(m);
		return -1;
	}

	if (Coala_Send(c, m) < 0) {
		Err_Set(err, errno, "Coala_Send:");
		CoAPMessage_Decref(m);
		return -1;
	}

	CoAPMessage_Decref(m);

	return 0;
}

static int DecryptPayload(struct CoAPMessage *m, struct Aead *aead,
			  struct Err *err)
{
	uint8_t *enc;
	size_t enc_size;

	if ((enc = CoAPMessage_GetPayload(m, &enc_size, 0)) == NULL)
		return 0;

	if (enc_size - AEAD_TAG_SIZE <= 0)
		return -2;

	uint8_t *dec;
	size_t dec_size = enc_size - AEAD_TAG_SIZE;
	if ((dec = Mem_malloc(dec_size)) == NULL) {
		Err_Set(err, errno, "Mem_malloc:");
		return -1;
	}

	if (Aead_Open(aead, enc, enc_size,
		      CoAPMessage_GetId(m),
		      NULL, 0,
		      dec, &dec_size) < 0) {
		Err_Set(err, 0, "Aead_Open");
		Mem_free(dec);
		return -2;
	}

	if (CoAPMessage_SetPayload(m, dec, dec_size) < 0) {
		Err_Set(err, errno, "CoAPMessage_SetPayload:");
		Mem_free(enc);
		return -1;
	}

	Mem_free(dec);
	return 0;
}

static int DecryptUri(struct CoAPMessage *m, struct Aead *aead,
		      struct Err *err)
{
	uint8_t *enc;
	size_t enc_size;
	if ((enc = CoAPMessage_GetOptionOpaque(m,
					CoAPMessage_OptionCodeCoapsUri,
					&enc_size)) == NULL)
		return 0;

	if (enc_size - AEAD_TAG_SIZE <= 0)
		return -2;

	uint8_t *dec;
	size_t dec_size = enc_size - AEAD_TAG_SIZE;
	if ((dec = Mem_malloc(dec_size + 1)) == NULL) {
		Err_Set(err, errno, "Mem_malloc:");
		return -1;
	}

	int ret;
	if ((ret = Aead_Open(aead, enc, enc_size,
		      CoAPMessage_GetId(m),
		      NULL, 0,
		      dec, &dec_size)) < 0) {
		Err_Set(err, 0, "Aead_Open");
		Mem_free(dec);
		return -2;
	}

	dec[dec_size] = '\0';

	if (CoAPMessage_SetUri(m, (char *)dec,
			       CoAPMessage_SetUri_OnlyPath |
			       CoAPMessage_SetUri_OnlyQuery) < 0) {
		Err_Set(err, errno, "CoAPMessage_SetUri:");
		Mem_free(enc);
		return -1;
	}

	Mem_free(dec);
	CoAPMessage_RemoveOptions(m, CoAPMessage_OptionCodeCoapsUri);

	return 0;
}

static enum LayerStack_Ret
SecurityLayer_OnReceive_Secure(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	char key[KEY_SIZE];
	KeyGen(msg, key, sizeof key);

	int ret;
	if ((ret = pthread_mutex_lock(&SessionMapMutex))) {
		Err_Set(err, ret, "pthread_mutex_lock");
		return LayerStack_Err;
	}

	khiter_t it = kh_get(SessionMap_t, SessionMap, key);
	if (it == kh_end(SessionMap)) {
		if (CoAPMessage_IsRequest(msg)) {
			if (SendUnauthorized(c, msg,
					CoAPMessage_OptionCodeSessionNotFound,
					err) < 0) {
				pthread_mutex_unlock(&SessionMapMutex);
				return LayerStack_Err;
			}
		}

		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Stop;
	}

	struct Session *s = kh_val(SessionMap, it);
	if (s->state != SessionState_Exchange) {
		/* XXX: Сессия устанавливается => игнорирование */
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Stop;
	}

	ret = DecryptPayload(msg, s->aead, err);
	if (ret == -1) {
		Err_Set(err, errno, "DecryptPayload:");
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Err;
	} else if (ret == -2) {
		if (SendUnauthorized(c, msg,
				     CoAPMessage_OptionCodeSessionExpired,
				     err) < 0) {
			pthread_mutex_unlock(&SessionMapMutex);
			return LayerStack_Err;
		}
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Stop;
	}

	ret = DecryptUri(msg, s->aead, err);
	if (ret == -1) {
		Err_Set(err, errno, "DecryptPayload:");
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Err;
	} else if (ret == -2) {
		if (SendUnauthorized(c, msg,
				     CoAPMessage_OptionCodeSessionExpired,
				     err) < 0) {
			pthread_mutex_unlock(&SessionMapMutex);
			return LayerStack_Err;
		}
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Stop;
	}

	pthread_mutex_unlock(&SessionMapMutex);
	return LayerStack_Con;
}

static bool IsSessionError(struct CoAPMessage *m)
{
	if (CoAPMessage_GetType(m) != CoAPMessage_TypeAck)
		return false;

	if (CoAPMessage_GetCode(m) != CoAPMessage_CodeUnauthorized)
		return false;

	uint32_t v;
	if (!CoAPMessage_GetOptionUint(m,
				CoAPMessage_OptionCodeSessionNotFound, &v))
		return true;

	if (!CoAPMessage_GetOptionUint(m,
				CoAPMessage_OptionCodeSessionExpired, &v))
		return true;

	return false;
}

enum LayerStack_Ret
SecurityLayer_OnReceive_SessionError(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	char key[KEY_SIZE];
	KeyGen(msg, key, sizeof key);

	int ret;
	if ((ret = pthread_mutex_lock(&SessionMapMutex))) {
		Err_Set(err, ret, "pthread_mutex_lock");
		return LayerStack_Err;
	}

	SessionMapDel(key);
	pthread_mutex_unlock(&SessionMapMutex);

	return LayerStack_Con;
}

enum LayerStack_Ret
SecurityLayer_OnReceive(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	if (IsHelloPeer(msg))
		return SecurityLayer_OnReceive_HelloPeer(c, msg, flags, err);
	else if (IsHelloClient(msg))
		return SecurityLayer_OnReceive_HelloClient(c, msg, flags, err);
	else if (CoAPMessage_IsSecure(msg))
		return SecurityLayer_OnReceive_Secure(c, msg, flags, err);
	else if (IsSessionError(msg))
		return SecurityLayer_OnReceive_SessionError(c, msg, flags, err);

	return LayerStack_Con;
}

enum LayerStack_Ret
SecurityLayer_OnSend(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	int ret;

	if (flags & CoAPMessagePool_SkipSec)
		return LayerStack_Con;

	if (!CoAPMessage_IsSecure(msg))
		return LayerStack_Con;

	/* Формирование ключа */
	char key[KEY_SIZE];
	KeyGen(msg, key, sizeof key);

	if ((ret = pthread_mutex_lock(&SessionMapMutex))) {
		Err_Set(err, ret, "pthread_mutex_lock");
		return LayerStack_Err;
	}

	/* Нет записи в хэш-таблице? */
	khiter_t it = kh_get(SessionMap_t, SessionMap, key);
	if (it == kh_end(SessionMap)) {
		/* Создание записи */
		char *k;
		if ((k = Mem_strdup(key)) == NULL) {
			Err_Set(err, errno, "Mem_strdup:");
			pthread_mutex_unlock(&SessionMapMutex);
			return LayerStack_Err;
		}

		int ret;
		if ((it = kh_put(SessionMap_t, SessionMap, k, &ret)),
		    ret < 0) {
			Err_Set(err, errno, "kh_put:");
			Mem_free(k);
			pthread_mutex_unlock(&SessionMapMutex);
			return LayerStack_Err;
		}

		struct Session *s;
		if ((s = Mem_calloc(1, sizeof *s)) == NULL) {
			Err_Set(err, errno, "Mem_malloc:");
			kh_del(SessionMap_t, SessionMap, it);
			Mem_free(k);
			pthread_mutex_unlock(&SessionMapMutex);
			return LayerStack_Err;
		}

		s->state = SessionState_Init;
		STAILQ_INIT(&s->head);
		kh_val(SessionMap, it) = s;
	}

	/* Запись сообщения в список из хэш-таблицы */
	struct Session *s = kh_val(SessionMap, it);

	struct MsgListEntry *e;
	if ((e = Mem_calloc(1, sizeof *e)) == NULL) {
		Err_Set(err, errno, "Mem_calloc:");
		pthread_mutex_unlock(&SessionMapMutex);
		return LayerStack_Err;
	}
	e->m = CoAPMessage_Incref(msg);
	STAILQ_INSERT_TAIL(&s->head, e, list);

	CoAPMessagePool_Remove(c->mes_pool, CoAPMessage_GetId(msg));

	if (s->state == SessionState_Init) {
		/* Новая сессия => отправка публичного ключа */
		if (SendHello(c, msg, HandshakeType_Client, err) < 0) {
			pthread_mutex_unlock(&SessionMapMutex);
			return LayerStack_Err;
		}
		s->state = SessionState_HelloSend;
	} else if (s->state == SessionState_Exchange) {
		/* Установленная => отправка всех незашифрованных */
		if (MsgListSendEncrypt(c, &s->head, s->aead, err) < 0) {
			pthread_mutex_unlock(&SessionMapMutex);
			return LayerStack_Err;
		}
	}

	pthread_mutex_unlock(&SessionMapMutex);
	return LayerStack_Stop;
}
