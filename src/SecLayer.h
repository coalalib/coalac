#ifndef _SECLAYER_H_
#define _SECLAYER_H_

#include <stdint.h>	/* uint32_t */

#include "LayerStack.h"

#define SECLAYER_FLAG_SKIP_BLK_SEC	0
#define SECLAYER_FLAG_CB_ONLY_ERR	1

struct SecLayer_Stats {
	uint32_t current;
	uint32_t total;
};

extern int SecLayer_Init(struct Coala *c, struct Err *err);
extern void SecLayer_Deinit(struct Coala *c);

extern enum LayerStack_Ret
SecLayer_OnReceive(struct Coala *c,
		   int fd,
		   struct CoAPMessage *msg,
		   unsigned flags,
		   struct Err *err);

extern enum LayerStack_Ret
SecLayer_OnSend(struct Coala *c,
		int fd,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err);

extern void SecLayer_Cleaner(void);
extern int SecLayer_Stats(struct SecLayer_Stats *st);

#endif
