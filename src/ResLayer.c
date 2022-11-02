#include <coala/Coala.h>
#include <ndm/log.h>

#include "MsgQueue.h"
#include "ResLayer.h"
#include "SecLayer.h"

enum LayerStack_Ret
ResLayer_OnReceive(struct Coala *c,
		   int fd,
		   struct CoAPMessage *msg,
		   unsigned flags,
		   struct Err *err)
{
	int type = CoAPMessage_GetType(msg);
	struct CoAPMessage *m;

	if (!(CoAPMessage_TypeIsResponse(type)))
		return LayerStack_Con;

	if ((m = MsgQueue_Get(msg)) != NULL) {
		CoAPMessage_Cb_t cb = NULL;
		void *arg = NULL;

		if (!CoAPMessage_TestFlag(m, SECLAYER_FLAG_CB_ONLY_ERR) &&
		    !CoAPMessage_GetCb(m, &cb, &arg) &&
		    cb)
			cb(c, fd, CoAPMessage_CbErrNone, msg, arg);

		if (!CoAPMessage_IsMulticast(m))
			MsgQueue_Remove(msg);
	}

	return LayerStack_Stop;
}
