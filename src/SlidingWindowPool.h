#ifndef _SLIDING_WINDOW_POOL_
#define _SLIDING_WINDOW_POOL_

#include <coala/CoAPMessage.h>

#include "SlidingWindow.h"

extern struct SlidingWindowPool *SlidingWindowPool(void);
extern void SlidingWindowPool_Free(struct SlidingWindowPool *p);

extern int SlidingWindowPool_Set(
	struct SlidingWindowPool *p,
	const char *tok,
	struct SlidingWindow *sw,
	struct CoAPMessage *m,
	CoAPMessage_Handler_t handler);

extern struct SlidingWindow *SlidingWindowPool_Get(
	struct SlidingWindowPool *p,
	const char *tok,
	struct CoAPMessage **m,
	CoAPMessage_Handler_t *handler);

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
