#ifndef _CACHELAYER_H_
#define _CACHELAYER_H_

#include "LayerStack.h"

extern int CacheLayer_Init(struct Coala *c, struct Err *err);
extern void CacheLayer_Deinit(struct Coala *c);

extern enum LayerStack_Ret
CacheLayer_OnReceive(struct Coala *c,
		     int fd,
		     struct CoAPMessage *msg,
		     unsigned flags,
		     struct Err *err);

#endif
