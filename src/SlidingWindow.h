#ifndef _SLIDING_WINDOW_
#define _SLIDING_WINDOW_

#include <stdbool.h>
#include <stddef.h>

enum SlidingWindow_Dir {
	SlidingWindow_DirInput,
	SlidingWindow_DirOutput
};

struct SlidingWindow;

struct SlidingWindow_BlockFlags {
	bool sent	: 1;
	bool received	: 1;
	bool last	: 1;
};

extern struct SlidingWindow *SlidingWindow(enum SlidingWindow_Dir d,
					   size_t block_size,
					   size_t win_size);
extern void SlidingWindow_Free(struct SlidingWindow *sw);

extern bool SlidingWindow_IsRx(struct SlidingWindow *sw);

extern size_t SlidingWindow_GetSize(struct SlidingWindow *sw);

extern int SlidingWindow_SetBlockSize(struct SlidingWindow *sw,
				      size_t block_size);

extern int SlidingWindow_Write(struct SlidingWindow *sw, void *d,
				   size_t s);
extern void *SlidingWindow_Read(struct SlidingWindow *sw, size_t *s);

extern void *SlidingWindow_ReadBlock(struct SlidingWindow *sw,
				     unsigned block_num,
				     size_t *size, bool check_window,
				     struct SlidingWindow_BlockFlags *bf);
extern int SlidingWindow_WriteBlock(struct SlidingWindow *sw,
				    unsigned block_num,
				    void *data, size_t size,
				    bool check_window,
				    struct SlidingWindow_BlockFlags *bf);
extern int SlidingWindow_GetOffset(struct SlidingWindow *sw);
extern int SlidingWindow_Advance(struct SlidingWindow *sw, bool *complete);

enum {
	SlidingWindow_ReadBlockIterCbError = -1,
	SlidingWindow_ReadBlockIterCbStop  = 0,
	SlidingWindow_ReadBlockIterCbOk    = 1
};

typedef int (*SlidingWindow_ReadBlockIterCb)(struct SlidingWindow *sw,
					     unsigned block_num,
					     void *d, size_t s,
					     struct SlidingWindow_BlockFlags *bf,
					     void *data);
extern int SlidingWindow_ReadBlockIter(struct SlidingWindow *sw,
				       bool only_window,
				       SlidingWindow_ReadBlockIterCb cb,
				       void *data);

extern int SlidingWindow_GetBlockFlags(struct SlidingWindow *sw,
				       unsigned block_num,
				       struct SlidingWindow_BlockFlags *flags);
extern int SlidingWindow_SetBlockFlags(struct SlidingWindow *sw,
				       unsigned block_num,
				       struct SlidingWindow_BlockFlags *flags);

#endif
