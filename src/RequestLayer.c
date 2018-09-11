#define _GNU_SOURCE	/* GNU variant of strerror_r */

#include <coala/Coala.h>
#include <coala/Mem.h>
#include <arpa/inet.h>
#include <ndm/log.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "Err.h"
#include "RequestLayer.h"

enum LayerStack_Ret
RequestLayer_OnReceive(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	bool is_ping;
	int id, ret;
	res_handler_t h;

	Err_Init(err, __func__);

	id = CoAPMessage_GetId(msg);
	is_ping = CoAPMessage_IsPing(msg);

	if (!(CoAPMessage_IsRequest(msg) || is_ping))
		return LayerStack_Con;

	if (is_ping) {
		struct CoAPMessage *m;

		if ((m = CoAPMessage(CoAPMessage_TypeRst,
				     CoAPMessage_CodeEmpty,
				     id)) == NULL) {
			Err_Set(err, errno, "CoAPMessage:");
			return LayerStack_Err;
		}

		CoAPMessage_CopyToken(m, msg);
		CoAPMessage_CopySockAddr(m, msg);

		if (Coala_Send(c, m) < 0) {
			Err_Set(err, errno, "Coala_Send:");
			CoAPMessage_Decref(m);
			return LayerStack_Err;
		}

		CoAPMessage_Decref(m);

		return LayerStack_Stop;
	}

	char *path;
	if ((path = CoAPMessage_GetUriPath(msg, false)) == NULL) {
		if (errno != ENOENT) {
			Err_Set(err, errno, "CoAPMessage_GetUriPath:");
			return LayerStack_Err;
		}

		if ((path = Mem_strdup("/")) == NULL) {
			Err_Set(err, errno, "Mem_strdup:");
			return LayerStack_Err;
		}
	}

	struct CoAPMessage *m;
	if ((m = CoAPMessage(CoAPMessage_TypeAck,
			     CoAPMessage_CodeEmpty,
			     id)) == NULL) {
		Err_Set(err, errno, "CoAPMessage:");
		Mem_free(path);
		return LayerStack_Err;
	}

	CoAPMessage_CopyToken(m, msg);
	CoAPMessage_CopySockAddr(m, msg);

	if ((CoAPMessage_CopyOption(m, msg,
		CoAPMessage_OptionCodeUriScheme) < 0 &&
	     errno != ENOENT) ||
	    (CoAPMessage_CopyOption(m, msg,
		CoAPMessage_OptionCodeBlock1) < 0 &&
	     errno != ENOENT) ||
	    (CoAPMessage_CopyOption(m, msg,
		CoAPMessage_OptionCodeSelectiveRepeatWindowSize) < 0 &&
	     errno != ENOENT)) {
		Err_Set(err, errno, "CoAPMessage_CopyOption:");
		Mem_free(path);
		return LayerStack_Err;
	}

	if (!Coala_GetRes(c, path, CoAPMessage_GetCode(msg), &h)) {
		ret = h(c, msg, m);
		if (!ret)
			Coala_Send(c, m);
	} else if (errno == ENOENT || errno == ENOKEY) {
		char buf[50];
		int code = (errno == ENOENT) ?
			   CoAPMessage_CodeNotFound :
			   CoAPMessage_CodeMethodNotAllowed;

		CoAPMessage_SetCode(m, code);

		NDM_LOG_DEBUG("%s: resource \"%s\" with code "
			      "%s doesn't exist", __func__, path,
			      CoAPMessage_GetCodeStr(msg, buf, sizeof buf));

		if (Coala_Send(c, m) < 0) {
			Err_Set(err, errno, "Coala_Send:");
			CoAPMessage_Decref(m);
			Mem_free(path);
			return LayerStack_Err;
		}
	}

	CoAPMessage_Decref(m);
	Mem_free(path);

	return LayerStack_Stop;
}
