#include <coala/Coala.h>
#include <arpa/inet.h>
#include <ndm/log.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "Err.h"
#include "ReqLayer.h"

enum LayerStack_Ret
ReqLayer_OnReceive(struct Coala *c,
		   int fd,
		   struct CoAPMessage *msg,
		   unsigned flags,
		   struct Err *err)
{
	bool is_ping;
	int id;
	res_handler_t h;
	void *arg;

	Err_Init(err, __func__);

	id = CoAPMessage_GetId(msg);
	is_ping = CoAPMessage_IsPing(msg);

	if (!(CoAPMessage_IsRequest(msg) || is_ping))
		return LayerStack_Con;

	if (is_ping) {
		struct CoAPMessage *m;

		if ((m = CoAPMessage(CoAPMessage_TypeRst,
				     CoAPMessage_CodeEmpty,
				     id, 0)) == NULL) {
			Err_Set(err, errno, "CoAPMessage:");
			return LayerStack_Err;
		}

		CoAPMessage_CopyToken(m, msg);
		CoAPMessage_CopySockAddr(m, msg);

		if (Coala_Send(c, fd, m) < 0) {
			Err_Set(err, errno, "Coala_Send:");
			CoAPMessage_Free(m);
			return LayerStack_Err;
		}

		CoAPMessage_Free(m);

		return LayerStack_Stop;
	}

	char *path;
	if ((path = CoAPMessage_GetUriPath(msg)) == NULL) {
		if (errno != ENOENT) {
			Err_Set(err, errno, "CoAPMessage_GetUriPath:");
			return LayerStack_Err;
		}

		if ((path = strdup("/")) == NULL) {
			Err_Set(err, errno, "strdup:");
			return LayerStack_Err;
		}
	}

	struct CoAPMessage *m;
	if ((m = CoAPMessage(CoAPMessage_TypeAck,
			     CoAPMessage_CodeEmpty,
			     id, 0)) == NULL) {
		Err_Set(err, errno, "CoAPMessage:");
		free(path);
		return LayerStack_Err;
	}

	CoAPMessage_CopySockAddr(m, msg);
	CoAPMessage_CopyToken(m, msg);
	CoAPMessage_CopyProxySecurityId(m, msg);

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
		free(path);
		return LayerStack_Err;
	}

	if (!Coala_GetRes(c, path, CoAPMessage_GetCode(msg), &h, &arg)) {
		int ret = h(c, fd, msg, m, arg);

		if (!ret)
			Coala_Send(c, fd, m);
	} else if (errno == ENOENT || errno == ENOKEY) {
		int code = (errno == ENOENT) ?
			   CoAPMessage_CodeNotFound :
			   CoAPMessage_CodeMethodNotAllowed;

		CoAPMessage_SetCode(m, code);

#ifndef NDEBUG
		char buf[50];
		NDM_LOG_DEBUG("%s: resource \"%s\" with code "
			      "%s doesn't exist", __func__, path,
			      CoAPMessage_GetCodeStr(msg, buf, sizeof buf));
#endif

		if (Coala_Send(c, fd, m) < 0) {
			Err_Set(err, errno, "Coala_Send:");
			CoAPMessage_Free(m);
			free(path);
			return LayerStack_Err;
		}
	}

	CoAPMessage_Free(m);
	free(path);

	return LayerStack_Stop;
}
