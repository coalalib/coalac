#ifndef _REQUEST_LAYER_H_
#define _REQUEST_LAYER_H_

#include "LayerStack.h"

enum LayerStack_Ret
ReqLayer_OnReceive(struct Coala *c,
		   int fd,
		   struct CoAPMessage *msg,
		   unsigned flags,
		   struct Err *err);

#endif
