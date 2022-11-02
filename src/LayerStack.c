#include <ndm/log.h>
#include <ndm/macro.h>
#include <stddef.h>

#include <coala/CoAPMessage.h>

#include "LayerStack.h"

#include "ArqBlock1Layer.h"
#include "ArqBlock2Layer.h"
#include "CacheLayer.h"
#include "LogLayer.h"
#include "ReqLayer.h"
#include "ResLayer.h"
#include "SecLayer.h"

typedef enum LayerStack_Ret (*LayerHandler_t)(
	struct Coala *c,
	int fd,
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
		.name = "cac",
		.handler = CacheLayer_OnReceive,
		.init = CacheLayer_Init,
		.deinit = CacheLayer_Deinit
	}, {
		.name = "sec",
		.handler = SecLayer_OnReceive,
		.init = SecLayer_Init,
		.deinit = SecLayer_Deinit
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
		.handler = ReqLayer_OnReceive
	}, {
		.name = "res",
		.handler = ResLayer_OnReceive
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
		.handler = SecLayer_OnSend
	}
};

#ifndef NDEBUG
static const char *LayerStack_Ret2Str(enum LayerStack_Ret r)
{
	const char *a[] = {"continue", "stop", "error"};
	return a[r];
}
#endif

int LayerStack_Init(struct Coala *c, struct Err *err)
{
	int ret;
	LayerInit_t f;

	for (size_t i = 0; i < NDM_ARRAY_SIZE(ReceiveLayers); i++) {
		if ((f = ReceiveLayers[i].init) == NULL)
			continue;

		if ((ret = f(c, err)) < 0)
		{
			LayerStack_Deinit(c);
			return ret;
		}
	}

	for (size_t i = 0; i < NDM_ARRAY_SIZE(SendLayers); i++) {
		if ((f = SendLayers[i].init) == NULL)
			continue;

		if ((ret = f(c, err)) < 0)
		{
			LayerStack_Deinit(c);
			return ret;
		}
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
		int fd,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	int ret = LayerStack_Err;

	if (c == NULL || msg == NULL)
		return LayerStack_Err;

	for (size_t i = 0; i < NDM_ARRAY_SIZE(ReceiveLayers); i++) {
		const char *n = ReceiveLayers[i].name;
		LayerHandler_t h = ReceiveLayers[i].handler;

		if (n == NULL || h == NULL)
			continue;

#ifndef NDEBUG
		NDM_LOG_DEBUG_3("[%d] RL#%zu \"%s\": enter",
				CoAPMessage_GetId(msg),
				i,
				ReceiveLayers[i].name);
#endif

		ret = h(c, fd, msg, flags, err);

#ifndef NDEBUG
		NDM_LOG_DEBUG_3("[%d] RL#%zu \"%s\": %s",
				CoAPMessage_GetId(msg),
				i,
				ReceiveLayers[i].name,
				LayerStack_Ret2Str(ret));
#endif

		if (ret != LayerStack_Con)
			break;
	}

	return ret;
}

enum LayerStack_Ret
LayerStack_OnSend(
		struct Coala *c,
		int fd,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err)
{
	int ret = LayerStack_Err;

	if (c == NULL || msg == NULL)
		return LayerStack_Err;

	for (size_t i = 0; i < NDM_ARRAY_SIZE(SendLayers); i++) {
		const char *n = SendLayers[i].name;
		LayerHandler_t h = SendLayers[i].handler;

		if (n == NULL || h == NULL)
			continue;

#ifndef NDEBUG
		NDM_LOG_DEBUG_3("[%d] SL#%zu \"%s\": enter",
				CoAPMessage_GetId(msg),
				i,
				SendLayers[i].name);
#endif

		ret = h(c, fd, msg, flags, err);

#ifndef NDEBUG
		NDM_LOG_DEBUG_3("[%d] SL#%zu \"%s\": %s",
				CoAPMessage_GetId(msg),
				i,
				SendLayers[i].name,
				LayerStack_Ret2Str(ret));
#endif

		if (ret != LayerStack_Con)
			break;
	}

	return ret;
}
