#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <coala/khash.h>
#include <coala/Str.h>

#include "SlidingWindow.h"

/*
 * Use as param for Read/WriteBlock?
 */
struct Block {
	void *data;
	size_t size;
	struct SlidingWindow_BlockFlags flags;
};

KHASH_MAP_INIT_INT(BlockMap, struct Block *);

struct SlidingWindow {
	size_t block_size;
	size_t win_size;
	size_t off;
	khash_t(BlockMap) *map;
	bool input;			/* enum? */
	bool complete;			/* output -> acked all
					   input -> received all */
};

bool SlidingWindow_IsRx(struct SlidingWindow *sw)
{
	return (sw) ? sw->input : false;
}

struct SlidingWindow *SlidingWindow(enum SlidingWindow_Dir d,
				    size_t block_size,
				    size_t win_size)
{
	struct SlidingWindow *sw = NULL;

	if (!win_size) {
		errno = EINVAL;
		goto out;
	}

	if ((sw = calloc(1, sizeof(*sw))) == NULL ||
	    (sw->map = kh_init(BlockMap)) == NULL) {
		errno = ENOMEM;
		goto out_free;
	}

	sw->input = (d == SlidingWindow_DirInput);
	sw->block_size = block_size;
	sw->win_size = win_size;

	goto out;

out_free:
	free(sw);
	sw = NULL;
out:
	return sw;
}

int SlidingWindow_SetBlockSize(struct SlidingWindow *sw, size_t block_size)
{
	if (sw == NULL || !block_size) {
		errno = EINVAL;
		return -1;
	}

	if (sw->block_size) {
		errno = EALREADY;
		return -1;
	}

	sw->block_size = block_size;

	return 0;
}

void SlidingWindow_Free(struct SlidingWindow *sw)
{
	if (sw == NULL)
		return;

	for (khiter_t it = kh_begin(sw->map); it != kh_end(sw->map); it++) {
		struct Block *b;

		if (!kh_exist(sw->map, it))
			continue;

		b = kh_val(sw->map, it);
		free(b->data);
		free(b);
	}

	kh_destroy(BlockMap, sw->map);
	free(sw);
}

int SlidingWindow_Write(struct SlidingWindow *sw, void *d, size_t s)
{
	int errsv = 0, res = -1;

	if (sw == NULL || d == NULL || !s) {
		errsv = EINVAL;
		goto out;
	} else if (kh_size(sw->map) != 0) {
		errsv = ENOTEMPTY;
		goto out;
	} else if (!sw->block_size) {
		errsv = EBADE;
		goto out;
	}

	for (size_t i = 0, j = 0; i < s; i += sw->block_size, j++) {
		bool last;
		int ret;
		khiter_t it;
		size_t p_size;
		struct Block *b = NULL;
		void *p = NULL;

		last = s - i <= sw->block_size;
		p_size = last ? s - i : sw->block_size;

		if ((b = calloc(1, sizeof(*b))) == NULL ||
		    (p = malloc(p_size)) == NULL ||
		     ((it = kh_put(BlockMap, sw->map, j, &ret)), ret < 0)) {
			free(b);
			free(p);
			errsv = ENOMEM;
			goto out;
		}

		memcpy(p, (char *)d + i, p_size);
		b->size = p_size;
		b->data = p;
		b->flags.last = last;

		kh_val(sw->map, it) = b;
	}

	res = 0;
out:
	if (errsv)
		errno = errsv;

	return res;
}

void *SlidingWindow_Read(struct SlidingWindow *sw, size_t *s)
{
	int errsv = 0;
	size_t full_size = 0;
	void *m = NULL;

	if (sw == NULL) {
		errsv = EINVAL;
		goto out;
	} else if (!sw->complete) {
		errno = ENODATA;
		goto out;
	}

	for (khiter_t it = kh_begin(sw->map); it != kh_end(sw->map); it++) {
		struct Block *b;
		void *t;

		if (!kh_exist(sw->map, it))
			continue;

		b = kh_val(sw->map, it);

		if ((t = realloc(m, full_size + b->size)) == NULL) {
			errsv = errno;
			free(m);
			m = NULL;
			goto out;
		}

		memcpy((char *)t + full_size, b->data, b->size);

		full_size += b->size;
		m = t;
	}

	if (s)
		*s = full_size;

out:
	if (errsv)
		errno = errsv;

	return m;
}

static inline bool InWindow(unsigned block_num, unsigned off,
			    unsigned win_size)
{
	return block_num >= off && block_num < off + win_size;
}


void *SlidingWindow_ReadBlock(struct SlidingWindow *sw, unsigned block_num,
			      size_t *size, bool check_window,
			      struct SlidingWindow_BlockFlags *bf)
{
	khiter_t it;
	struct Block *b;

	if (sw == NULL) {
		errno = EINVAL;
		return NULL;
	} else if (check_window &&
		   !InWindow(block_num, sw->off, sw->win_size)) {
		errno = ERANGE;
		return NULL;
	} else if ((it = kh_get(BlockMap, sw->map, block_num)) ==
		   kh_end(sw->map)) {
		errno = ENOENT;
		return NULL;
	}

	/* Or copy? */
	b = kh_val(sw->map, it);

	if (size)
		*size = b->size;

	if (bf)
		*bf = b->flags;

	return b->data;
}

int SlidingWindow_WriteBlock(struct SlidingWindow *sw, unsigned block_num,
			     void *data, size_t size, bool check_window,
			     struct SlidingWindow_BlockFlags *bf)
{
	int ret;
	khiter_t it;
	struct Block *b;
	void *d;

	if (sw == NULL || data == NULL || !size) {
		errno = EINVAL;
		return -1;
	} else if (check_window &&
		   !InWindow(block_num, sw->off, sw->win_size)) {
		errno = ERANGE;
		return -1;
	} else if (!sw->block_size) {
		errno = EBADE;
		return -1;
	} else if (size > sw->block_size) {
		errno = E2BIG;
		return -1;
	}

	it = kh_put(BlockMap, sw->map, block_num, &ret);
	if (ret < 0) {
		errno = ENOMEM;
		return -1;
	} else if (!ret) {
		errno = EEXIST;
		return -1;
	}

	if ((b = calloc(1, sizeof(*b))) == NULL ||
	     (d = malloc(size)) == NULL) {
		free(b);
		return -1;
	}

	memcpy(d, data, size);
	b->data = d;
	b->size = size;

	if (bf)
		b->flags = *bf;

	kh_val(sw->map, it) = b;

	return 0;
}

int SlidingWindow_ReadBlockIter(struct SlidingWindow *sw, bool only_window,
				SlidingWindow_ReadBlockIterCb cb, void *data)
{
	khiter_t it;

	if (sw == NULL || cb == NULL) {
		errno = EINVAL;
		return -1;
	}

	it = (only_window) ? kh_get(BlockMap, sw->map, sw->off) :
			     kh_begin(sw->map);

	for ( ; it != kh_end(sw->map); it++) {
		int k, ret;
		struct Block *b;

		if (!kh_exist(sw->map, it))
			continue;

		k = kh_key(sw->map, it);

		if (only_window && !InWindow(k, sw->off, sw->win_size))
			break;

		b = kh_val(sw->map, it);

		ret = cb(sw, k, b->data, b->size, &b->flags, data);
		if (ret <= SlidingWindow_ReadBlockIterCbStop)
			return ret;
	}

	return SlidingWindow_ReadBlockIterCbOk;
}

int SlidingWindow_SetBlockFlags(struct SlidingWindow *sw, unsigned block_num,
				struct SlidingWindow_BlockFlags *flags)
{
	khiter_t it;
	struct Block *b;

	if (sw == NULL || flags == NULL) {
		errno = EINVAL;
		return -1;
	}

	if ((it = kh_get(BlockMap, sw->map, block_num)) == kh_end(sw->map)) {
		errno = ENOENT;
		return -1;
	}

	b = kh_val(sw->map, it);
	b->flags = *flags;

	return 0;
}

int SlidingWindow_GetBlockFlags(struct SlidingWindow *sw, unsigned block_num,
				struct SlidingWindow_BlockFlags *flags)
{
	khiter_t it;
	struct Block *b;

	if (sw == NULL || flags == NULL) {
		errno = EINVAL;
		return -1;
	}

	if ((it = kh_get(BlockMap, sw->map, block_num)) == kh_end(sw->map)) {
		errno = ENOENT;
		return -1;
	}

	b = kh_val(sw->map, it);
	*flags = b->flags;

	return 0;
}

size_t SlidingWindow_GetSize(struct SlidingWindow *sw)
{
	size_t s = 0;

	if (sw == NULL) {
		errno = EINVAL;
		goto out;
	} else if (!sw->complete) {
		errno = ENODATA;
		goto out;
	}

	for (khiter_t it = kh_begin(sw->map); it != kh_end(sw->map); it++) {
		struct Block *b;

		if (!kh_exist(sw->map, it))
			continue;

		b = kh_val(sw->map, it);
		s += b->size;
	}

out:
	return s;
}

int SlidingWindow_Advance(struct SlidingWindow *sw, bool *complete)
{
	bool last = false;
	unsigned i, beg, end;

	if (sw == NULL) {
		errno = EINVAL;
		return -1;
	}

	beg = sw->off;
	end = beg + sw->win_size;

	for (i = beg; i < end; i++) {
		khiter_t it;
		struct Block *b;

		it = kh_get(BlockMap, sw->map, i);
		if (it == kh_end(sw->map))
			break;

		b = kh_val(sw->map, it);
		if (!sw->input && !b->flags.received)
			break;

		if (b->flags.last)
			last = true;

		/*
		 * TODO: Проверка наличия других блоков после
		 * последнего.
		 */

		sw->off++;
	}

	if (complete)
		*complete = last;

	sw->complete = last;

	return 0;
}

int SlidingWindow_GetOffset(struct SlidingWindow *sw)
{
	if (sw == NULL) {
		errno = EINVAL;
		return -1;
	}

	return sw->off;
}
