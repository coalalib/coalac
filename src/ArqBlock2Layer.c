#include <errno.h>
#include <stdlib.h>

#include <coala/CoAPMessage.h>
#include <coala/Str.h>
#include <ndm/ip_sockaddr.h>

#include "ArqBlock2Layer.h"
#include "Err.h"
#include "MsgQueue.h"
#include "Private.h"
#include "SecLayer.h"
#include "SlidingWindow.h"
#include "SlidingWindowPool.h"

#define WINDOW_SIZE	70
			/* <ip>:<port>_<token> */
#define TOKEN_SIZE	sizeof("127.127.127.127:65535_123456789abcdef0")

static int TokenGen(struct CoAPMessage *m, char *buf, size_t buf_size)
{
	char addr_s[INET_ADDRSTRLEN];
	struct ndm_ip_sockaddr_t addr;

	if (CoAPMessage_GetSockAddr(m, &addr) < 0 ||
	    ndm_ip_sockaddr_ntop(&addr, addr_s, sizeof addr_s) == NULL)
		return -1;

	uint8_t m_tok[COAP_MESSAGE_MAX_TOKEN_SIZE];
	char m_tok_s[COAP_MESSAGE_MAX_TOKEN_SIZE * 2 + 1] = {'\0'};
	size_t m_tok_size = sizeof m_tok;

	if (!CoAPMessage_GetToken(m, m_tok, &m_tok_size))
		Str_FromArr(m_tok, m_tok_size, m_tok_s, sizeof m_tok_s);

	unsigned port = ndm_ip_sockaddr_port(&addr);

	snprintf(buf, buf_size, "%s:%u_%s", addr_s, port, m_tok_s);

	return 0;
}

static int Callback(
		struct SlidingWindow *sw,
		unsigned block_num,
		void *d, size_t s,
		struct SlidingWindow_BlockFlags *bf,
		void *data)
{
	enum CoAPMessage_BlockSize szx;
	enum CoAPMessage_OptionCode code_bl, code_win =
		CoAPMessage_OptionCodeSelectiveRepeatWindowSize;
	int fd, id, *first_id;
	struct Coala *c;
	struct CoAPMessage_Block b = {0};
	struct CoAPMessage *m, *n = NULL;
	void **tup = (void **)data;

	if (bf->sent)
		return SlidingWindow_ReadBlockIterCbOk;

	c = tup[0];
	m = tup[1];
	code_bl = (intptr_t)tup[2];
	szx = (intptr_t)tup[3];
	first_id = tup[4];
	fd = (long)tup[5];

	b.num = block_num;
	b.m = !bf->last;
	b.szx = szx;

	if ((n = CoAPMessage_Clone(m, 0)) == NULL ||
	    CoAPMessage_AddOptionUint(n, code_win, WINDOW_SIZE) < 0 ||
	    CoAPMessage_AddOptionBlock(n, code_bl, &b) < 0 ||
	    CoAPMessage_SetPayload(n, d, s)) {
		CoAPMessage_Free(n);
		return SlidingWindow_ReadBlockIterCbError;
	}

	CoAPMessage_SetType(n, CoAPMessage_TypeCon);

	if (first_id && *first_id >= 0) {
		id = *first_id;
		*first_id = -1;
	} else {
		id = CoAPMessage_GenId();
	}

	CoAPMessage_SetId(n, id);

	if (Coala_Send(c, fd, n) < 0) {
		CoAPMessage_Free(n);
		return SlidingWindow_ReadBlockIterCbError;
	}

	CoAPMessage_Free(n);

	bf->sent = true;

	return SlidingWindow_ReadBlockIterCbOk;
}

enum LayerStack_Ret
ArqBlock2Layer_OnReceive(
		struct Coala *c,
		int fd,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	int id, t;

	Err_Init(err, __func__);

	t = CoAPMessage_GetType(msg);
	id = CoAPMessage_GetId(msg);

	/* Есть размер окна? */
	uint32_t win;
	if (CoAPMessage_GetOptionUint(msg,
	    CoAPMessage_OptionCodeSelectiveRepeatWindowSize,
	    &win) < 0) {
		return LayerStack_Con;
	}

	/* Извлечение блочных опций */
	bool bl1_set = true;
	struct CoAPMessage_Block bl1;
	if (CoAPMessage_GetOptionBlock(msg, CoAPMessage_OptionCodeBlock1,
				       &bl1) < 0) {
		if (errno == ENOENT)
			bl1_set = false;
		else
			return LayerStack_Stop;
	}

	bool bl2_set = true;
	struct CoAPMessage_Block bl2;
	if (CoAPMessage_GetOptionBlock(msg, CoAPMessage_OptionCodeBlock2,
				       &bl2) < 0) {
		if (errno == ENOENT)
			bl2_set = false;
		else
			return LayerStack_Stop;
	}

	/* Генерация token */
	char tok_s[TOKEN_SIZE] = {0};
	if (TokenGen(msg, tok_s, sizeof tok_s) < 0)
	{
		Err_Set(err, errno, "TokenGen:");
		return LayerStack_Err;
	}

	/* Пустое сообщение => создание нового окна */
	if (t == CoAPMessage_TypeAck &&
	    CoAPMessage_IsEmpty(msg) &&
	    !bl2_set /* фильтрация последней квитанции */) {
		/* Есть парное исходящее? */
		struct CoAPMessage *pair;

		if ((pair = MsgQueue_Get(msg)) == NULL)
			return LayerStack_Stop;

		struct SlidingWindow *sw;
		if ((sw = SlidingWindow(SlidingWindow_DirInput, 0, win)) == NULL) {
			Err_Set(err, errno, "SlidingWindow:");
			return LayerStack_Err;
		}

		if (SlidingWindowPool_Set(c->sw_pool, tok_s, sw, pair) < 0) {
			Err_Set(err, errno, "SlidingWindowPool_Set:");
			SlidingWindow_Free(sw);
			return LayerStack_Err;
		}

		MsgQueue_Remove(msg);

		return LayerStack_Stop;
	}

	if (!bl2_set && bl1_set)
		return LayerStack_Con;

	if (!(t == CoAPMessage_TypeCon ||
	      t == CoAPMessage_TypeAck))
		return LayerStack_Stop;

	/*
	 * Получение сессии
	 */
	struct CoAPMessage *m;
	struct SlidingWindow *sw;
	if ((sw = SlidingWindowPool_Get(c->sw_pool, tok_s, &m)) == NULL &&
	    errno != ENOENT) {
		Err_Set(err, errno, "SlidingWindowPool_Get:");
		return LayerStack_Err;
	}

	if (t == CoAPMessage_TypeCon) {
		size_t s;
		uint8_t *d;
		if ((d = CoAPMessage_GetPayload(msg, &s, 0)) == NULL) {
			Err_Set(err, errno, "CoAPMessage_GetPayload:");
			return LayerStack_Err;
		}

		SlidingWindow_SetBlockSize(sw, CoAPMessage_BlockSize(bl2.szx));

		struct SlidingWindow_BlockFlags bf = {0};
		bf.last = !bl2.m;
		if (SlidingWindow_WriteBlock(sw, bl2.num, d, s, true, &bf) < 0) {
			Err_Set(err, errno, "SlidingWindow_WriteBlock:");
			return LayerStack_Err;
		}

		bool comp;
		SlidingWindow_Advance(sw, &comp);

		/* Создание квитанции и отправка */
		struct CoAPMessage *a;
		a = CoAPMessage(CoAPMessage_TypeAck,
				CoAPMessage_CodeContinue,
				id, 0);
		if (a == NULL) {
			Err_Set(err, errno, "CoAPMessage:");
			return LayerStack_Err;
		}

		/* Последняя квитанция должна иметь код empty */
		if (!bl2.m)
			CoAPMessage_SetCode(a, CoAPMessage_CodeEmpty);

		CoAPMessage_CopyToken(a, msg);
		CoAPMessage_CopySockAddr(a, msg);

		/* TODO: Check return value */
		CoAPMessage_AddOptionBlock(a, CoAPMessage_OptionCodeBlock2, &bl2);
		CoAPMessage_AddOptionUint(a,
			CoAPMessage_OptionCodeSelectiveRepeatWindowSize,
			win);

		if (Coala_Send(c, fd, a) < 0) {
			Err_Set(err, errno, "Coala_Send:");
			CoAPMessage_Free(a);
			return LayerStack_Err;
		}

		CoAPMessage_Free(a);

		if (comp) {
			size_t s;
			uint8_t *d;
			if ((d = SlidingWindow_Read(sw, &s)) == NULL) {
				Err_Set(err, errno, "SlidingWindow_Read:");
				return LayerStack_Err;
			}

			if (CoAPMessage_SetPayload(msg, d, s) < 0) {
				Err_Set(err, errno, "CoAPMessage_SetPayload:");
				free(d);
				return LayerStack_Err;
			}

			free(d);

			CoAPMessage_RemoveOptions(msg,
				CoAPMessage_OptionCodeBlock2);
			CoAPMessage_RemoveOptions(msg,
				CoAPMessage_OptionCodeSelectiveRepeatWindowSize);

			void *arg = NULL;
			CoAPMessage_Cb_t cb = NULL;

			if (!CoAPMessage_TestFlag(m, SECLAYER_FLAG_CB_ONLY_ERR) &&
			    !CoAPMessage_GetCb(m, &cb, &arg) &&
			    cb)
				cb(c, fd, CoAPMessage_CbErrNone, msg, arg);

			SlidingWindowPool_Del(c->sw_pool, tok_s);
		}
	} else { /* CoAPMessage_TypeAck */
		struct SlidingWindow_BlockFlags bf;
		if (SlidingWindow_GetBlockFlags(sw, bl2.num, &bf) < 0)
			return LayerStack_Stop;

		bf.received = true;
		if (SlidingWindow_SetBlockFlags(sw, bl2.num, &bf) < 0)
			return LayerStack_Stop;

		bool comp;
		SlidingWindow_Advance(sw, &comp);

		MsgQueue_Remove(msg);

		if (comp) {
			SlidingWindowPool_Del(c->sw_pool, tok_s);
		} else {
			void *t[] = {c, m, (void *)CoAPMessage_OptionCodeBlock2,
				     (void *)bl2.szx, NULL, (void *)(long)fd};
			SlidingWindow_ReadBlockIter(sw, true, Callback, t);
		}
	}

	return LayerStack_Stop;
}

enum LayerStack_Ret
ArqBlock2Layer_OnSend(
		struct Coala *c,
		int fd,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	enum LayerStack_Ret res = LayerStack_Stop;
	struct CoAPMessage *ack = NULL;
	struct SlidingWindow *sw = NULL;

	Err_Init(err, __func__);

	if (CoAPMessage_TestFlag(msg, SECLAYER_FLAG_SKIP_BLK_SEC))
                return LayerStack_Con;

	if (!CoAPMessage_IsResponse(msg)) {
		res = LayerStack_Con;
		goto out;
	}

	/* Check size */
	enum CoAPMessage_BlockSize szx = CoAPMessage_BlockSize1024;
	uint8_t *data;
	size_t bs = CoAPMessage_BlockSize(szx), size;
	if ((data = CoAPMessage_GetPayload(msg, &size, 0)) == NULL ||
	    size <= bs) {
		res = LayerStack_Con;
		goto out;
	}

	/* Remove current message from queue */
	int id = CoAPMessage_GetId(msg);

	char tok_s[TOKEN_SIZE];
	if (TokenGen(msg, tok_s, sizeof tok_s) < 0)
	{
		Err_Set(err, errno, "TokenGen:");
		res = LayerStack_Err;
		goto out;
	}

	if (SlidingWindowPool_Get(c->sw_pool, tok_s, NULL)) {
		/* Игнорируем исходящее сообщение, если окно уже существует */
		res = LayerStack_Stop;
		goto out;
	}

	/* Create window */
	if ((sw = SlidingWindow(SlidingWindow_DirOutput, bs,
				WINDOW_SIZE)) == NULL) {
		Err_Set(err, errno, "SlidingWindow:");
		res = LayerStack_Err;
		goto out;
	}

	if (SlidingWindow_Write(sw, data, size) < 0) {
		Err_Set(err, errno, "SlidingWindow_Write:");
		res = LayerStack_Err;
		goto out_sw_free;
	}

	/* Send ACK message */
	if ((ack = CoAPMessage(CoAPMessage_TypeAck,
			       CoAPMessage_CodeEmpty,
			       CoAPMessage_GetId(msg),
			       0)) == NULL) {
		Err_Set(err, errno, "CoAPMessage:");
		res = LayerStack_Err;
		goto out_sw_free;
	}

	CoAPMessage_CopySockAddr(ack, msg);
	CoAPMessage_CopyToken(ack, msg);

	if (CoAPMessage_AddOptionUint(ack,
			CoAPMessage_OptionCodeSelectiveRepeatWindowSize,
			WINDOW_SIZE) < 0) {
		Err_Set(err, errno, "CoAPMessage_AddOptionUint:");
		res = LayerStack_Err;
		goto out_decref;
	}

	/* Совместимость с Block 1 */
	if (CoAPMessage_CopyOption(ack, msg,
				   CoAPMessage_OptionCodeBlock1) < 0 &&
	    errno != ENOENT) {
		Err_Set(err, errno, "CoAPMessage_CopyOption:");
		res = LayerStack_Err;
		goto out_decref;
	}

	if (Coala_Send(c, fd, ack) < 0) {
		Err_Set(err, errno, "Coala_Send:");
		res = LayerStack_Err;
		goto out_decref;
	}

	CoAPMessage_Free(ack);
	ack = NULL;

	/* Send messages from window */

	/*
	 * В ответе на block 1 опция должна присутствовать только в пустом
	 * сообщении.
	 */
	CoAPMessage_RemoveOptions(msg, CoAPMessage_OptionCodeBlock1);

	id = -1;
	void *tup[] = {c, msg, (void *)CoAPMessage_OptionCodeBlock2,
		       (void *)szx, &id, (void *)(long)fd};
	if (SlidingWindow_ReadBlockIter(sw, true, Callback, tup) < 0) {
		Err_Set(err, 0, "SlidingWindow_ReadBlockIter");
		res = LayerStack_Err;
		goto out_decref;
	}

	/* Save window to list */
	if (SlidingWindowPool_Set(c->sw_pool, tok_s, sw, msg) < 0) {
		Err_Set(err, errno, "SlidingWindowPool_Set:");
		res = LayerStack_Err;
		goto out_decref;
	}

	goto out;

out_decref:
	CoAPMessage_Free(ack);
out_sw_free:
	SlidingWindow_Free(sw);
out:
	return res;
}
