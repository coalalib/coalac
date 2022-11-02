#include <errno.h>
#include <stdlib.h>

#include <coala/CoAPMessage.h>
#include <coala/Str.h>
#include <ndm/ip_sockaddr.h>
#include <ndm/time.h>

#include "ArqBlock1Layer.h"
#include "Err.h"
#include "MsgQueue.h"
#include "Private.h"
#include "SecLayer.h"
#include "SlidingWindow.h"
#include "SlidingWindowPool.h"
#include "constants.h"

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
	int id, fd, *first_id;
	struct Coala *c;
	struct CoAPMessage_Block b = {0};
	struct CoAPMessage *m, *n = NULL;
	void **tup = (void **)data;


	if (bf->received || ndm_time_left_monotonic_msec(&bf->expire) >= 0)
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
	
	if ((n = CoAPMessage_Clone(m, CoAPMessage_CloneFlagCb)) == NULL ||
	    CoAPMessage_AddOptionUint(n, code_win, DEFAULT_WINDOW_SIZE) < 0 ||
	    CoAPMessage_AddOptionBlock(n, code_bl, &b) < 0 ||
	    CoAPMessage_SetPayload(n, d, s)) {
		CoAPMessage_Free(n);
		return SlidingWindow_ReadBlockIterCbError;
	}

	if (first_id && *first_id >= 0) {
		id = *first_id;
		*first_id = -1;
	} else {
		id = CoAPMessage_GenId();
	}

	CoAPMessage_SetId(n, id);

	if (bf->attempts == 3){
		overflowIndicatorInc(sw);
	}
	if (bf->attempts > 0){
		retransmitsInc(sw);
	}
	if (bf->attempts > 6){
		return SlidingWindow_ReadBlockIterCbError;
	}
	bf->attempts++;
	ndm_time_get_monotonic(&bf->expire);
	ndm_time_add_msec(&bf->expire,EXPIRATION_TIME);

	if (bf->attempts == 1 && Coala_Send(c, fd, n) < 0) {
		CoAPMessage_Free(n);
		return SlidingWindow_ReadBlockIterCbError;
	}

	CoAPMessage_Free(n);

	return SlidingWindow_ReadBlockIterCbOk;
}

static enum LayerStack_Ret
ArqLayer_OnReceive_Block1_Ack(
		struct Coala *c,
		int fd,
		struct CoAPMessage *msg,
		struct Err *err,
		const char *sw_tok,
		struct CoAPMessage *m,
		struct CoAPMessage_Block *b,
		struct SlidingWindow *sw)
{
	struct SlidingWindow_BlockFlags bf;

	if (SlidingWindow_GetBlockFlags(sw, b->num, &bf) < 0){
		return LayerStack_Stop;
	}
	
	accept_block(sw,&bf);
	pid_control(sw);
	
	SlidingWindow_SetBlockFlags(sw, b->num, &bf);
	
	/* Т.к. сообщение с кодом может прийти в произвольном
	 * порядке, то сохраняем его */
	int mc = CoAPMessage_GetCode(msg);
	if (mc != CoAPMessage_CodeContinue)
		SlidingWindowPool_SetCode(c->sw_pool, sw_tok, mc);
	
	/* Все квитанции получены? */
	if (CoAPMessage_GetCode(msg) != CoAPMessage_CodeContinue) {
		CoAPMessage_RemoveOptions(msg,
			CoAPMessage_OptionCodeBlock1);

		if (!CoAPMessage_IsEmpty(msg))
			CoAPMessage_RemoveOptions(msg,
				CoAPMessage_OptionCodeSelectiveRepeatWindowSize);

		/* Правка кода на сохранённый */
		int mc = SlidingWindowPool_GetCode(c->sw_pool, sw_tok);
		if (mc != -1)
			CoAPMessage_SetCode(msg, mc);
		/* Удаляем все пакеты, связанные с данным окном из MsgQueue */
		MsgQueue_RemoveAll(msg); 
		SlidingWindowLog(sw, "U");
		SlidingWindowPool_Del(c->sw_pool, sw_tok);
		return LayerStack_Con;
	}

	/* Отправка оставшихся сообщений из окна */
	void *t[] = {c, m, (void *)CoAPMessage_OptionCodeBlock1,
		     (void *)b->szx, NULL, (void *)(long)fd};
	if (SlidingWindow_ReadBlockIter(sw, true, Callback, t) < 0) {
		Err_Set(err, 0, "SlidingWindow_ReadBlockIter");
		return LayerStack_Err;
	}

	/* Удаление парного исходящего сообщения */
	MsgQueue_Remove(msg);

	return LayerStack_Stop;
}

static enum LayerStack_Ret
ArqLayer_OnReceive_Block1_Con(
		struct Coala *c,
		int fd,
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
	
	if (SlidingWindow_WriteBlock(sw, b->num, d, s, false, &bf) < 0) {
		Err_Set(err, errno, "SlidingWindow_WriteBlock:");
		return LayerStack_Err;
	}
	if(!b->m){
		setTotalBlocks(sw,b->num);
	}
	bool comp = isComplete(sw);
	
	if (comp) {
		/* Извлечение данных из окна и подмена рабочей нагрузки */
		if ((d = SlidingWindow_Read(sw, &s)) == NULL) {
			Err_Set(err, errno, "SlidingWindow_Read:");
			return LayerStack_Err;
		}

		SlidingWindowLog(sw,"U");

		SlidingWindowPool_Del(c->sw_pool, sw_tok);

		if (CoAPMessage_SetPayload(msg, d, s) < 0) {
			Err_Set(err, errno, "CoAPMessage_SetPayload:");
			free(d);
			return LayerStack_Err;
		}

		free(d);

		return LayerStack_Con;
	} else {
		struct CoAPMessage *a;
		a = CoAPMessage(CoAPMessage_TypeAck,
				CoAPMessage_CodeContinue,
				CoAPMessage_GetId(msg),
				0);
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
		if (Coala_Send(c, fd, a) < 0) {
			Err_Set(err, errno, "Coala_Send:");
			CoAPMessage_Free(a);
			return LayerStack_Err;
		}

		CoAPMessage_Free(a);
	}

	return LayerStack_Stop;
}

enum LayerStack_Ret
ArqBlock1Layer_OnReceive(
		struct Coala *c,
		int fd,
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
	if (TokenGen(msg, tok_s, sizeof tok_s) < 0)
	{
		Err_Set(err, errno, "TokenGen:");
		return LayerStack_Err;
	}

	/* Получение окна */
	struct CoAPMessage *m = NULL;
	struct SlidingWindow *sw;
	if ((sw = SlidingWindowPool_Get(c->sw_pool, tok_s, &m)) == NULL &&
	    errno != ENOENT) {
		Err_Set(err, errno, "SlidingWindowPool_Get:");
		return LayerStack_Err;
	}

	if (t == CoAPMessage_TypeAck) {
		/* Окно не создано? */
		if (sw == NULL)
			return LayerStack_Stop;

		return ArqLayer_OnReceive_Block1_Ack(c, fd, msg, err, tok_s,
						     m, &b, sw);
	} else { /* CoAPMessage_TypeCon */
		if (sw == NULL) {
			if ((sw = SlidingWindow(SlidingWindow_DirInput,
						CoAPMessage_BlockSize(b.szx),
						win)) == NULL) {
				Err_Set(err, errno, "SlidingWindow:");
				return LayerStack_Err;
			}

			if (SlidingWindowPool_Set(c->sw_pool, tok_s, sw, msg) < 0) {
				Err_Set(err, errno, "SlidingWindowPool_Set:");
				SlidingWindow_Free(sw);
				return LayerStack_Err;
			}
		}

		return ArqLayer_OnReceive_Block1_Con(c, fd, msg, err, tok_s,
						     win, &b, sw);
	}

	return LayerStack_Stop;
}

enum LayerStack_Ret
ArqBlock1Layer_OnSend(
		struct Coala *c,
		int fd,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	enum LayerStack_Ret res = LayerStack_Stop;
	Err_Init(err, __func__);

	if (CoAPMessage_TestFlag(msg, SECLAYER_FLAG_SKIP_BLK_SEC))
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

	int id = CoAPMessage_GetId(msg);

	/* Create window */
	struct SlidingWindow *sw;
	if ((sw = SlidingWindow(SlidingWindow_DirOutput, bs,
				DEFAULT_WINDOW_SIZE)) == NULL) {
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
	void *tup[] = {c, msg, (void *)CoAPMessage_OptionCodeBlock1,
		       (void *)szx, &id, (void *)(long)fd};
	if (SlidingWindow_ReadBlockIter(sw, true, Callback, tup) < 0) {
		Err_Set(err, 0, "SlidingWindow_ReadBlockIter");
		res = LayerStack_Err;
		goto out_sw_free;
	}

	/* Save window to list */
	char tok_s[TOKEN_SIZE] = {0};
	if (TokenGen(msg, tok_s, sizeof tok_s) < 0)
	{
		Err_Set(err, errno, "TokenGen:");
		res = LayerStack_Err;
		goto out_sw_free;
	}

	if (SlidingWindowPool_Set(c->sw_pool, tok_s, sw, msg) < 0) {
		Err_Set(err, errno, "SlidingWindowPool_Set:");
		res = LayerStack_Err;
		goto out_sw_free;
	}

	goto out;

out_sw_free:
	SlidingWindow_Free(sw);
out:
	return res;
}
