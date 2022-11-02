#ifndef _SLIDING_WINDOW_POOL_
#define _SLIDING_WINDOW_POOL_

#include <stdint.h>	/* uint32_t */

#include <coala/CoAPMessage.h>

#include "SlidingWindow.h"

struct SlidingWindowPool_Stats {
	uint32_t current;
	uint32_t total;
	uint32_t orphan;
};

extern struct SlidingWindowPool *SlidingWindowPool(void);
extern void SlidingWindowPool_Free(struct SlidingWindowPool *p);
extern void SlidingWindowPool_Cleaner(struct SlidingWindowPool *p);
extern int SlidingWindowPool_Stats(struct SlidingWindowPool *p,
				   struct SlidingWindowPool_Stats *st);

extern int SlidingWindowPool_Set(
	struct SlidingWindowPool *p,
	const char *tok,
	struct SlidingWindow *sw,
	struct CoAPMessage *m);

extern struct SlidingWindow *SlidingWindowPool_Get(
	struct SlidingWindowPool *p,
	const char *tok,
	struct CoAPMessage **m);

extern int SlidingWindowPool_Del(
	struct SlidingWindowPool *p,
	const char *tok);

extern int SlidingWindowPool_GetCode(
	struct SlidingWindowPool *p,
	const char *tok);

extern int SlidingWindowPool_SetCode(
	struct SlidingWindowPool *p,
	const char *tok,
	int code);

#endif
