#ifndef _REQUEST_LAYER_H_
#define _REQUEST_LAYER_H_

#include "LayerStack.h"

enum LayerStack_Ret
RequestLayer_OnReceive(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err);

#endif
