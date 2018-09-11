#include <coala/Coala.h>
#include <ndm/log.h>

#include "CoAPMessagePool.h"
#include "ResponseLayer.h"

enum LayerStack_Ret
ResponseLayer_OnReceive(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	int id, type;
	struct CoAPMessage *m;

	id = CoAPMessage_GetId(msg);
	type = CoAPMessage_GetType(msg);

	if (!(CoAPMessage_TypeIsResponse(type)))
		return LayerStack_Con;

	m = CoAPMessagePool_Get(c->mes_pool, id, NULL);
	if (m) {
		CoAPMessage_Handler_t h = CoAPMessage_GetHandler(m);
		if (h)
			h(c, msg);

		if (!CoAPMessage_IsMulticast(m))
			CoAPMessagePool_Remove(c->mes_pool, id);

		CoAPMessage_Decref(m);
	}


	return LayerStack_Stop;
}
