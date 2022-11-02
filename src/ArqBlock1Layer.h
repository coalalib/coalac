#ifndef _ARQ_BLOCK1_LAYER_H_
#define _ARQ_BLOCK1_LAYER_H_

#include "LayerStack.h"

extern enum LayerStack_Ret
ArqBlock1Layer_OnReceive(
		struct Coala *c,
		int fd,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err);

extern enum LayerStack_Ret
ArqBlock1Layer_OnSend(
		struct Coala *c,
		int fd,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err);

#endif
