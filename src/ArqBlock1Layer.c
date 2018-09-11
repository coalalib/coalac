#include <coala/Coala.h>
#include <coala/CoAPMessage.h>
#include <coala/Mem.h>
#include <ndm/ip_sockaddr.h>
#include <errno.h>

#include "ArqBlock1Layer.h"
#include "CoAPMessagePool.h"
#include "Err.h"
#include "SlidingWindow.h"
#include "SlidingWindowPool.h"
#include "Str.h"

#define WINDOW_SIZE	70
#define TOKEN_SIZE	sizeof("127.127.127.127:5683_123456789abcdef0")

static void TokenGen(struct CoAPMessage *m, char *buf, size_t buf_size)
{
	char addr_s[NDM_IP_SOCKADDR_LEN];
	struct ndm_ip_sockaddr_t addr;

	CoAPMessage_GetSockAddr(m, &addr);
	ndm_ip_sockaddr_ntop(&addr, addr_s, sizeof addr_s);

	uint8_t m_tok[COAP_MESSAGE_MAX_TOKEN_SIZE];
	char m_tok_s[COAP_MESSAGE_MAX_TOKEN_SIZE * 2 + 1] = {'\0'};
	size_t m_tok_size = sizeof m_tok;

	if (!CoAPMessage_GetToken(m, m_tok, &m_tok_size))
		Str_FromArr(m_tok, m_tok_size, m_tok_s, sizeof m_tok_s);

	unsigned port = ndm_ip_sockaddr_port(&addr);

	snprintf(buf, buf_size, "%s:%u_%s", addr_s, port, m_tok_s);
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
	int id, *first_id;
	struct Coala *c;
	struct CoAPMessage_Block b = {0};
	struct CoAPMessage *m, *n = NULL;
	void **tup = (void **)data;

	if (bf->sent)
		return SlidingWindow_ReadBlockIterCbOk;

	c = tup[0];
	m = tup[1];
	code_bl = (enum CoAPMessage_OptionCode)tup[2];
	szx = (enum CoAPMessage_BlockSize)tup[3];
	first_id = tup[4];

	b.num = block_num;
	b.m = !bf->last;
	b.szx = szx;

	if ((n = CoAPMessage_Clone(m, false)) == NULL ||
	    CoAPMessage_AddOptionUint(n, code_win, WINDOW_SIZE) < 0 ||
	    CoAPMessage_AddOptionBlock(n, code_bl, &b) < 0 ||
	    CoAPMessage_SetPayload(n, d, s)) {
		CoAPMessage_Decref(n);
		return SlidingWindow_ReadBlockIterCbError;
	}

	if (first_id && *first_id >= 0) {
		id = *first_id;
		*first_id = -1;
	} else {
		id = CoAPMessage_GenId();
	}

	CoAPMessage_SetId(n, id);

	if (Coala_Send(c, n) < 0) {
		CoAPMessage_Decref(n);
		return SlidingWindow_ReadBlockIterCbError;
	}

	CoAPMessage_Decref(n);

	bf->sent = true;

	return SlidingWindow_ReadBlockIterCbOk;
}

static enum LayerStack_Ret
ArqLayer_OnReceive_Block1_Ack(
		struct Coala *c,
		struct CoAPMessage *msg,
		struct Err *err,
		const char *sw_tok,
		CoAPMessage_Handler_t handler,
		struct CoAPMessage *m,
		struct CoAPMessage_Block *b,
		struct SlidingWindow *sw)
{
	struct SlidingWindow_BlockFlags bf;

	if (SlidingWindow_GetBlockFlags(sw, b->num, &bf) < 0)
		return LayerStack_Stop;

	bf.received = true;
	SlidingWindow_SetBlockFlags(sw, b->num, &bf);

	bool comp;
	SlidingWindow_Advance(sw, &comp);

	/* Т.к. сообщение с кодом может прийти в произвольном
	 * порядке, то сохраняем его */
	int mc = CoAPMessage_GetCode(msg);
	if (mc != CoAPMessage_CodeContinue)
		SlidingWindowPool_SetCode(c->sw_pool, sw_tok, mc);

	/* Все квитанции получены? */
	if (comp) {
		CoAPMessage_RemoveOptions(msg,
			CoAPMessage_OptionCodeBlock1);

		if (!CoAPMessage_IsEmpty(msg))
			CoAPMessage_RemoveOptions(msg,
				CoAPMessage_OptionCodeSelectiveRepeatWindowSize);

		/* Правка кода на сохранённый */
		int mc = SlidingWindowPool_GetCode(c->sw_pool, sw_tok);
		if (mc != -1)
			CoAPMessage_SetCode(msg, mc);

		SlidingWindowPool_Del(c->sw_pool, sw_tok);

		/* Поиск парного сообщения в пуле исходящих сообщений
		 * и установка обработчика */
		int id = CoAPMessage_GetId(msg);
		struct CoAPMessage *pair;
		if ((pair = CoAPMessagePool_Get(c->mes_pool, id, NULL))) {
			CoAPMessage_SetHandler(pair, handler);
			CoAPMessage_Decref(pair);
		}

		return LayerStack_Con;
	}

	/* Отправка оставшихся сообщений из окна */
	void *t[] = {c, m, (void *)CoAPMessage_OptionCodeBlock1,
		     (void *)b->szx, NULL};
	if (SlidingWindow_ReadBlockIter(sw, true, Callback, t) < 0) {
		Err_Set(err, 0, "SlidingWindow_ReadBlockIter");
		return LayerStack_Err;
	}

	/* Удаление парного исходящего сообщения */
	CoAPMessagePool_Remove(c->mes_pool, CoAPMessage_GetId(msg));

	return LayerStack_Stop;
}

static enum LayerStack_Ret
ArqLayer_OnReceive_Block1_Con(
		struct Coala *c,
		struct CoAPMessage *msg,
		struct Err *err,
		const char *sw_tok,
		unsigned win,
		struct CoAPMessage_Block *b,
		struct SlidingWindow *sw)
{
	size_t s;
	uint8_t *d;

	/* Нет рабочей нагрузки? */
	if ((d = CoAPMessage_GetPayload(msg, &s, 0)) == NULL)
		return LayerStack_Stop;

	struct SlidingWindow_BlockFlags bf = {0};
	bf.last = !b->m;
	if (SlidingWindow_WriteBlock(sw, b->num, d, s, true, &bf) < 0) {
		Err_Set(err, errno, "SlidingWindow_WriteBlock:");
		return LayerStack_Err;
	}

	bool comp;
	SlidingWindow_Advance(sw, &comp);

	if (comp) {
		/* Извлечение данных из окна и подмена рабочей нагрузки */
		if ((d = SlidingWindow_Read(sw, &s)) == NULL) {
			Err_Set(err, errno, "SlidingWindow_Read:");
			return LayerStack_Err;
		}

		SlidingWindowPool_Del(c->sw_pool, sw_tok);

		if (CoAPMessage_SetPayload(msg, d, s) < 0) {
			Err_Set(err, errno, "CoAPMessage_SetPayload:");
			Mem_free(d);
			return LayerStack_Err;
		}

		Mem_free(d);

		return LayerStack_Con;
	} else {
		struct CoAPMessage *a;
		a = CoAPMessage(CoAPMessage_TypeAck,
				CoAPMessage_CodeContinue,
				CoAPMessage_GetId(msg));
		if (a == NULL) {
			Err_Set(err, errno, "CoAPMessage:");
			return LayerStack_Err;
		}

		CoAPMessage_CopyToken(a, msg);
		CoAPMessage_CopySockAddr(a, msg);

		b->m = false;

		CoAPMessage_AddOptionBlock(a, CoAPMessage_OptionCodeBlock1, b);
		CoAPMessage_AddOptionUint(a,
			CoAPMessage_OptionCodeSelectiveRepeatWindowSize,
			win);

		if (Coala_Send(c, a) < 0) {
			Err_Set(err, errno, "Coala_Send:");
			CoAPMessage_Decref(a);
			return LayerStack_Err;
		}

		CoAPMessage_Decref(a);
	}

	return LayerStack_Stop;
}

enum LayerStack_Ret
ArqBlock1Layer_OnReceive(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	Err_Init(err, __func__);

	/*
	 * Требования к входящему сообщению:
	 * 1) наличие опции с размером окна;
	 * 2) наличие опции Block1;
	 * 3) тип Ack/Con.
	 *
	 * Ack - квитации от ранее отправленного ответа.
	 * Con - входящий запрос.
	 */

	/* Проверка требований */
	uint32_t win;
	if (CoAPMessage_GetOptionUint(msg,
		CoAPMessage_OptionCodeSelectiveRepeatWindowSize, &win) < 0) {

		return LayerStack_Con;
	}

	struct CoAPMessage_Block b;
	if (CoAPMessage_GetOptionBlock(msg, CoAPMessage_OptionCodeBlock1,
				       &b) < 0) {
		return LayerStack_Con;
	}

	int t = CoAPMessage_GetType(msg);
	if (!(t == CoAPMessage_TypeAck || t == CoAPMessage_TypeCon))
		return LayerStack_Stop;

	/* Генерация token */
	char tok_s[TOKEN_SIZE] = {0};
	TokenGen(msg, tok_s, sizeof tok_s);

	/* Получение окна */
	CoAPMessage_Handler_t handler;
	struct CoAPMessage *m;
	struct SlidingWindow *sw;
	if ((sw = SlidingWindowPool_Get(c->sw_pool, tok_s, &m,
					&handler)) == NULL &&
	    errno != ENOENT) {
		Err_Set(err, errno, "SlidingWindowPool_Get:");
		return LayerStack_Err;
	}

	if (t == CoAPMessage_TypeAck) {
		/* Окно не создано? */
		if (sw == NULL)
			return LayerStack_Stop;

		return ArqLayer_OnReceive_Block1_Ack(c, msg, err, tok_s,
						     handler, m, &b, sw);
	} else { /* CoAPMessage_TypeCon */
		if (sw == NULL) {
			if ((sw = SlidingWindow(SlidingWindow_DirInput,
						CoAPMessage_BlockSize(b.szx),
						win)) == NULL) {
				Err_Set(err, errno, "SlidingWindow:");
				return LayerStack_Err;
			}

			if ((m = CoAPMessage_Clone(msg, false)) == NULL) {
				Err_Set(err, errno, "CoAPMessage_Clone:");
				SlidingWindow_Free(sw);
				return LayerStack_Err;
			}

			if (SlidingWindowPool_Set(c->sw_pool, tok_s, sw, m,
						  NULL) < 0) {
				Err_Set(err, errno, "SlidingWindowPool_Set:");
				SlidingWindow_Free(sw);
				return LayerStack_Err;
			}
		}

		return ArqLayer_OnReceive_Block1_Con(c, msg, err, tok_s,
						     win, &b, sw);
	}

	return LayerStack_Stop;
}

enum LayerStack_Ret
ArqBlock1Layer_OnSend(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	enum LayerStack_Ret res = LayerStack_Stop;

	Err_Init(err, __func__);

	if (flags & CoAPMessagePool_SkipArq)
		return LayerStack_Con;

	if (!CoAPMessage_IsRequest(msg)) {
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
	CoAPMessagePool_Remove(c->mes_pool, id);

	/* Create window */
	struct SlidingWindow *sw;
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

	/* Send messages from window */
	struct CoAPMessage *m;
	if ((m = CoAPMessage_Clone(msg, false)) == NULL) {
		Err_Set(err, errno, "CoAPMessage_Clone:");
		res = LayerStack_Err;
		goto out_sw_free;
	}

	void *tup[] = {c, m, (void *)CoAPMessage_OptionCodeBlock1,
		       (void *)szx, &id};
	if (SlidingWindow_ReadBlockIter(sw, true, Callback, tup) < 0) {
		Err_Set(err, 0, "SlidingWindow_ReadBlockIter");
		res = LayerStack_Err;
		goto out_m_decref;
	}

	/* Save window to list */
	char tok_s[TOKEN_SIZE] = {0};
	TokenGen(msg, tok_s, sizeof tok_s);

	if (SlidingWindowPool_Set(c->sw_pool, tok_s, sw, m,
				  CoAPMessage_GetHandler(msg)) < 0) {
		Err_Set(err, errno, "SlidingWindowPool_Set:");
		res = LayerStack_Err;
		goto out_m_decref;
	}

	goto out;

out_m_decref:
	CoAPMessage_Decref(m);
out_sw_free:
	SlidingWindow_Free(sw);
out:
	return res;
}
