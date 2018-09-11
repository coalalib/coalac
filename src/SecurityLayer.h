#ifndef _SECURITY_LAYER2_H_
#define _SECURITY_LAYER2_H_

#include "LayerStack.h"

extern int SecurityLayer_Init(struct Coala *c, struct Err *err);
extern void SecurityLayer_Deinit(struct Coala *c);

extern enum LayerStack_Ret
SecurityLayer_OnReceive(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err);

extern enum LayerStack_Ret
SecurityLayer_OnSend(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err);

#endif
