#ifndef _RESPONSE_LAYER_H_
#define _RESPONSE_LAYER_H_

#include "LayerStack.h"

extern enum LayerStack_Ret
ResLayer_OnReceive(struct Coala *c,
		   int fd,
		   struct CoAPMessage *msg,
		   unsigned flags,
		   struct Err *err);

#endif
