#include <errno.h>

#include <coala/Coala.h>

#include "Err.h"
#include "CacheLayer.h"
#include "MsgCache.h"

int CacheLayer_Init(struct Coala *c, struct Err *err)
{
	if (MsgCache_Init() < 0) {
		Err_Set(err, errno, "MsgCache_Init:");
		return -1;
	}

	return 0;
}

void CacheLayer_Deinit(struct Coala *c)
{
	MsgCache_Deinit();
}

enum LayerStack_Ret
CacheLayer_OnReceive(struct Coala *c,
	int fd,
	struct CoAPMessage *msg,
	unsigned flags,
	struct Err *err)
{
	struct CoAPMessage *m;

	Err_Init(err, __func__);

	if (!CoAPMessage_TypeIsRequest(CoAPMessage_GetType(msg)))
		return LayerStack_Con;

	if ((m = MsgCache_Get(fd, msg)) == NULL)
		return LayerStack_Con;

	if (Coala_SendLow(c, fd, m) < 0) {
		Err_Set(err, errno, "Coala_Send:");
		return LayerStack_Err;
	}

	return LayerStack_Stop;
}
