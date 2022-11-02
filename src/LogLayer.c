#include <ndm/ip_sockaddr.h>
#include <ndm/log.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <coala/Buf.h>
#include <coala/Coala.h>
#include <coala/CoAPMessage.h>
#include <coala/Str.h>

#include "LogLayer.h"

#ifndef NDEBUG
static int IterOptionsCb(enum CoAPMessage_OptionCode code, uint8_t *v, size_t s,
			 bool last, void *data)
{
	char buf[40];
	struct Buf_Handle *b = data;

	if (Buf_AddFormatStr(b, "%s:",
			CoAPMessage_OptionCodeStr(code, buf, sizeof buf)) < 0)
		return CoAPMessage_IterOptionsFuncError;

	if (Str_ArrIsPrintable(v, s)) {
		if (Buf_AddCh(b, '\"') ||
		    Buf_Add(b, v, s) < 0 ||
		    Buf_AddStr(b, "\"") < 0)
			return CoAPMessage_IterOptionsFuncError;
	} else if (!s) {
		if (Buf_AddStr(b, "(empty)") < 0)
			return CoAPMessage_IterOptionsFuncError;
	} else {
		for (size_t i = 0; i < s; i++) {
			if (Buf_AddFormatStr(b, (i == s - 1) ? "%02x" : "%02x ",
					     v[i]) < 0)
				return CoAPMessage_IterOptionsFuncError;
		}
	}

	if (!last && Buf_AddStr(b, ", ") < 0)
		return CoAPMessage_IterOptionsFuncError;

	return CoAPMessage_IterOptionsFuncOk;
}

static int Log(struct CoAPMessage *m, bool send, bool options, bool payload)
{
	int errsv = 0, res = -1;
	size_t s = 0, tok_size;
	struct Buf_Handle *b = NULL;
	struct CoAPMessage_Block bl1, bl2;
	uint8_t *d, tok[COAP_MESSAGE_MAX_TOKEN_SIZE];
	uint32_t t;

	if ((b = Buf()) == NULL) {
		errsv = errno;
		goto out;
	}

	char type[50];
	if (Buf_AddFormatStr(b, "[%d] %s %s%s %s",
			     CoAPMessage_GetId(m),
			     send ? "S" : "R",
			     CoAPMessage_IsSecure(m) ? "$ " : "",
			     CoAPMessage_GetTypeStr(m),
			     CoAPMessage_GetCodeStr(m, type,
						    sizeof type)) < 0) {
		errsv = errno;
		goto out;
	}

	if (CoAPMessage_IsRequest(m)) {
		char *s;

		if ((s = CoAPMessage_GetUriPath(m))) {
			if (Buf_AddFormatStr(b, " %s", s) < 0) {
				errsv = errno;
				free(s);
				goto out;
			}
			free(s);
		}

		if ((s = CoAPMessage_GetUriQuery(m))) {
			if (Buf_AddFormatStr(b, " %s", s) < 0) {
				errsv = errno;
				free(s);
				goto out;
			}
			free(s);
		}
	}

	if (!CoAPMessage_GetOptionBlock(m, CoAPMessage_OptionCodeBlock1, &bl1) &&
	    Buf_AddFormatStr(b, ", 1:%u/%u/%u", bl1.num, bl1.m,
			     CoAPMessage_BlockSize(bl1.szx)) < 0) {
		errsv = errno;
		goto out;
	}

	if (!CoAPMessage_GetOptionBlock(m, CoAPMessage_OptionCodeBlock2, &bl2) &&
	    Buf_AddFormatStr(b, ", 2:%u/%u/%u", bl2.num, bl2.m,
			     CoAPMessage_BlockSize(bl2.szx)) < 0) {
		errsv = errno;
		goto out;
	}

	if (!CoAPMessage_GetOptionUint(m,
			CoAPMessage_OptionCodeSelectiveRepeatWindowSize, &t) &&
	    Buf_AddFormatStr(b, ", W:%u", t) < 0) {
		errsv = errno;
		goto out;
	}

	if ((d = CoAPMessage_GetPayload(m, &s, 0)) &&
	    Buf_AddFormatStr(b, ", [%ub]", (unsigned)s) < 0) {
		errsv = errno;
		goto out;
	}


	struct ndm_ip_sockaddr_t sa;
	CoAPMessage_GetSockAddr(m, &sa);

	char a[NDM_IP_SOCKADDR_LEN];
	ndm_ip_sockaddr_ntop(&sa, a, sizeof a);

	if (Buf_AddFormatStr(b, " %s %s", send ? "to" : "from", a) < 0) {
		errsv = errno;
		goto out;
	}

	unsigned port = ndm_ip_sockaddr_port(&sa);
	if (port != COALA_PORT &&
	    Buf_AddFormatStr(b, ":%u", port) < 0) {
		errsv = errno;
		goto out;
	}

	tok_size = sizeof tok;
	if (!CoAPMessage_GetToken(m, tok, &tok_size)) {
		if (Buf_AddStr(b, ", Token: ") < 0) {
			errsv = errno;
			goto out;
		}

		if (Str_ArrIsPrintable(tok, tok_size)) {
			if (Buf_AddCh(b, '\"') < 0 ||
			    Buf_Add(b, tok, tok_size) < 0 ||
			    Buf_AddCh(b, '\"') < 0) {
				errsv = errno;
				goto out;
			}
		} else {
			for (size_t i = 0; i < tok_size; i++) {
				if (Buf_AddFormatStr(b, (i == tok_size - 1) ?
						"%02x" : "%02x ", tok[i]) < 0) {
					errsv = errno;
					goto out;
				}
			}
		}
	}

	if (payload && d) {
		if (Buf_AddStr(b, ", Payload: ") < 0) {
			errsv = errno;
			goto out;
		}

		if (Str_ArrIsPrintable(d, s)) {
			if (Buf_AddCh(b, '\"') < 0 ||
			    Buf_Add(b, d, s) < 0 ||
			    Buf_AddCh(b, '\"') < 0) {
				errsv = errno;
				goto out;
			}
		} else {
			for (size_t i = 0; i < s; i++) {
				if (Buf_AddFormatStr(b, "%02x ", d[i])
						< 0) {
					errsv = errno;
					goto out;
				}
			}
		}
	}

	if (options) {
		if (Buf_AddStr(b, ", Options: [") < 0 ||
		    CoAPMessage_IterOptions(m, IterOptionsCb, b) < 0 ||
		    Buf_AddCh(b, ']') < 0) {
			errsv = errno;
			goto out;
		}
	}

	if (Buf_AddCh(b, '\0') < 0) {
		errsv = errno;
		goto out;
	}

	NDM_LOG_DEBUG("%s", (char *)Buf_GetData(b, NULL, false));
	res = 0;
out:
	Buf_Free(b);

	if (errsv)
		errno = errsv;

	return res;
}
#endif

enum LayerStack_Ret
LogLayer_OnReceive(
		struct Coala *c,
		int fd,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
#ifndef NDEBUG
	int l = ndm_log_get_debug();

	if (l == LDEBUG_1)
		Log(msg, false, true, false);
	else if (l >= LDEBUG_2)
		Log(msg, false, true, true);
#endif

	return LayerStack_Con;
}

enum LayerStack_Ret
LogLayer_OnSend(
		struct Coala *c,
		int fd,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
#ifndef NDEBUG
	int l = ndm_log_get_debug();

	if (l == LDEBUG_1)
		Log(msg, true, true, false);
	else if (l >= LDEBUG_2)
		Log(msg, true, true, true);
#endif

	return LayerStack_Con;
}
