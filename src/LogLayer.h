#ifndef _LOG_LAYER_H_
#define _LOG_LAYER_H_

#include "LayerStack.h"

extern enum LayerStack_Ret
LogLayer_OnReceive(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err);

extern enum LayerStack_Ret
LogLayer_OnSend(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err);

#endif
