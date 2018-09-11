#ifndef _COAP_MP_H
#define _COAP_MP_H

#include <coala/CoAPMessage.h>

struct CoAPMessagePool;

extern struct CoAPMessagePool *CoAPMessagePool(void);
extern void CoAPMessagePool_Free(struct CoAPMessagePool *mp);
extern struct CoAPMessage *CoAPMessagePool_Next(struct CoAPMessagePool *mp,
					        unsigned *flags);
extern struct CoAPMessage *CoAPMessagePool_Get(struct CoAPMessagePool *mp,
					       unsigned short id,
					       unsigned *flags);
#define CoAPMessagePool_SkipArq	(1 << 0)
#define CoAPMessagePool_SkipSec (1 << 1)
extern int CoAPMessagePool_Add(struct CoAPMessagePool *mp,
			       struct CoAPMessage *m,
			       unsigned flags);
extern int CoAPMessagePool_Remove(struct CoAPMessagePool *mp, unsigned short id);
extern int CoAPMessagePool_Clear(struct CoAPMessagePool *mp);

#endif
