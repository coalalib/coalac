#include <ndm/log.h>
#include <ndm/macro.h>
#include <stddef.h>

#include <coala/CoAPMessage.h>

#include "LayerStack.h"

#include "ArqBlock1Layer.h"
#include "ArqBlock2Layer.h"
#include "LogLayer.h"
#include "RequestLayer.h"
#include "ResponseLayer.h"
#include "SecurityLayer.h"

typedef enum LayerStack_Ret (*LayerHandler_t)(
	struct Coala *c,
	struct CoAPMessage *msg,
	unsigned flags,
	struct Err *err);

typedef int (*LayerInit_t)(struct Coala *c, struct Err *err);
typedef void (*LayerDeinit_t)(struct Coala *c);

struct LayerDsc {
	const char *name;
	LayerHandler_t handler;
	LayerInit_t init;
	LayerDeinit_t deinit;
};

struct LayerDsc ReceiveLayers[] = {
	{
		.name = "log",
		.handler = LogLayer_OnReceive
	}, {
		.name = "sec",
		.handler = SecurityLayer_OnReceive,
		.init = SecurityLayer_Init,
		.deinit = SecurityLayer_Deinit
	}, {
		.name = "log",
		.handler = LogLayer_OnReceive
	}, {
		.name = "bl1",
		.handler = ArqBlock1Layer_OnReceive
	}, {
		.name = "bl2",
		.handler = ArqBlock2Layer_OnReceive
	}, {
		.name = "req",
		.handler = RequestLayer_OnReceive
	}, {
		.name = "res",
		.handler = ResponseLayer_OnReceive
	}
};

struct LayerDsc SendLayers[] = {
	{
		.name = "bl1",
		.handler = ArqBlock1Layer_OnSend
	}, {
		.name = "bl2",
		.handler = ArqBlock2Layer_OnSend
	}, {
		.name = "log",
		.handler = LogLayer_OnSend
	}, {
		.name = "sec",
		.handler = SecurityLayer_OnSend
	}
};

static const char *LayerStack_Ret2Str(enum LayerStack_Ret r)
{
	const char *a[] = {"continue", "stop", "error"};
	return a[r];
}

int LayerStack_Init(struct Coala *c, struct Err *err)
{
	int ret;
	LayerInit_t f;

	for (size_t i = 0; i < NDM_ARRAY_SIZE(ReceiveLayers); i++) {
		if ((f = ReceiveLayers[i].init) == NULL)
			continue;

		if ((ret = f(c, err)) < 0)
			return ret;
	}

	for (size_t i = 0; i < NDM_ARRAY_SIZE(SendLayers); i++) {
		if ((f = SendLayers[i].init) == NULL)
			continue;

		if ((ret = f(c, err)) < 0)
			return ret;
	}

	return 0;
}

void LayerStack_Deinit(struct Coala *c)
{
	LayerDeinit_t f;

	for (size_t i = 0; i < NDM_ARRAY_SIZE(ReceiveLayers); i++) {
		if ((f = ReceiveLayers[i].deinit) == NULL)
			continue;
		f(c);
	}

	for (size_t i = 0; i < NDM_ARRAY_SIZE(SendLayers); i++) {
		if ((f = SendLayers[i].deinit) == NULL)
			continue;
		f(c);
	}
}

enum LayerStack_Ret
LayerStack_OnReceive(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	int ret;

	if (c == NULL || msg == NULL)
		return LayerStack_Err;

	for (size_t i = 0; i < NDM_ARRAY_SIZE(ReceiveLayers); i++) {
		const char *n = ReceiveLayers[i].name;
		LayerHandler_t h = ReceiveLayers[i].handler;

		if (n == NULL || h == NULL)
			continue;

		NDM_LOG_DEBUG_3("[%d] RL#%zu \"%s\": enter",
				CoAPMessage_GetId(msg),
				i,
				ReceiveLayers[i].name);

		ret = h(c, msg, flags, err);

		NDM_LOG_DEBUG_3("[%d] RL#%zu \"%s\": %s",
				CoAPMessage_GetId(msg),
				i,
				ReceiveLayers[i].name,
				LayerStack_Ret2Str(ret));

		if (ret != LayerStack_Con)
			break;
	}

	return ret;
}

enum LayerStack_Ret
LayerStack_OnSend(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	int ret;

	if (c == NULL || msg == NULL)
		return LayerStack_Err;

	for (size_t i = 0; i < NDM_ARRAY_SIZE(SendLayers); i++) {
		const char *n = SendLayers[i].name;
		LayerHandler_t h = SendLayers[i].handler;

		if (n == NULL || h == NULL)
			continue;

		NDM_LOG_DEBUG_3("[%d] SL#%zu \"%s\": enter",
				CoAPMessage_GetId(msg),
				i,
				SendLayers[i].name);

		ret = h(c, msg, flags, err);

		NDM_LOG_DEBUG_3("[%d] SL#%zu \"%s\": %s",
				CoAPMessage_GetId(msg),
				i,
				SendLayers[i].name,
				LayerStack_Ret2Str(ret));

		if (ret != LayerStack_Con)
			break;
	}

	return ret;
}
