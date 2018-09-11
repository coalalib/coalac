#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>

#include "SlidingWindow.h"

static void Test_Init(void **state)
{
	struct SlidingWindow *sw;

	sw = SlidingWindow(SlidingWindow_DirInput, 4, 0);
	assert_null(sw);
	assert_int_equal(EINVAL, errno);

	sw = SlidingWindow(SlidingWindow_DirInput, 4, 3);
	assert_non_null(sw);
	SlidingWindow_Free(sw);
}

static void Test_ReadWrite(void **state)
{
	char *t;
	int ret;
	size_t s;
	struct SlidingWindow *sw;

	/* Без начального указания размера блока */
	sw = SlidingWindow(SlidingWindow_DirInput, 0, 3);
	assert_non_null(sw);

	ret = SlidingWindow_Write(sw, "123456789", 9);
	assert_int_equal(-1, ret);
	assert_int_equal(EBADE, errno);

	ret = SlidingWindow_SetBlockSize(sw, 4);
	assert_int_equal(0, ret);

	ret = SlidingWindow_SetBlockSize(sw, 5);
	assert_int_equal(-1, ret);
	assert_int_equal(EALREADY, errno);

	ret = SlidingWindow_Write(sw, "123456789", 9);
	assert_int_equal(0, ret);

	SlidingWindow_Free(sw);

	/* С указанием начального размера блока */
	sw = SlidingWindow(SlidingWindow_DirInput, 4, 3);
	assert_non_null(sw);

	ret = SlidingWindow_Write(sw, "123456789", 9);
	assert_int_equal(0, ret);

	ret = SlidingWindow_Advance(sw, NULL);
	assert_int_equal(0, ret);

	t = SlidingWindow_Read(sw, &s);
	assert_non_null(t);
	assert_int_equal(9, s);
	assert_memory_equal("123456789", t, 9);

	free(t);

	SlidingWindow_Free(sw);
}

static int cb(struct SlidingWindow *sw, unsigned b, void *d, size_t s,
	      struct SlidingWindow_BlockFlags *bf, void *data)
{
	printf("b: %u", b);
	if (bf->last)
		printf(", last");
	putchar('\n');

	return SlidingWindow_ReadBlockIterCbOk;
}

static void Test_ReadWriteBlock(void **state)
{
	bool comp;
	const int block_size = 2, win_size = 3;
	int ret;
	size_t s;
	struct SlidingWindow_BlockFlags f = {.last = true};
	struct SlidingWindow *sw;
	void *v;

	/* Без указания начального размера блока */
	sw = SlidingWindow(SlidingWindow_DirInput, 0, win_size);
	assert_non_null(sw);

	ret = SlidingWindow_WriteBlock(sw, 0, "12", 2, true, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EBADE, errno);

	ret = SlidingWindow_SetBlockSize(sw, block_size);
	assert_int_equal(0, ret);

	ret = SlidingWindow_WriteBlock(sw, 0, "34", 2, true, NULL);
	assert_int_equal(0, ret);

	SlidingWindow_Free(sw);

	/* С указанием начального размера блока */
	sw = SlidingWindow(SlidingWindow_DirInput, block_size, win_size);
	assert_non_null(sw);

	v = SlidingWindow_ReadBlock(sw, 0, NULL, false, NULL);
	assert_null(v);
	assert_int_equal(ENOENT, errno);

	ret = SlidingWindow_WriteBlock(sw, 0, "123", 3, true, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(E2BIG, errno);

	ret = SlidingWindow_WriteBlock(sw, win_size + 1, "12", 2, true, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(ERANGE, errno);

	ret = SlidingWindow_WriteBlock(sw, 0, "12", 2, true, NULL);
	assert_int_equal(0, ret);

	ret = SlidingWindow_WriteBlock(sw, 1, "34", 2, true, NULL);
	assert_int_equal(0, ret);

	ret = SlidingWindow_WriteBlock(sw, 2, "56", 2, true, NULL);
	assert_int_equal(0, ret);

	ret = SlidingWindow_Advance(sw, &comp);
	assert_int_equal(0, ret);
	assert_int_equal(false, comp);

	ret = SlidingWindow_GetOffset(sw);
	assert_int_equal(3, ret);

	ret = SlidingWindow_WriteBlock(sw, 3, "78", 2, true, NULL);
	assert_int_equal(0, ret);

	ret = SlidingWindow_WriteBlock(sw, 4, "9", 1, true, &f);
	assert_int_equal(0, ret);

	ret = SlidingWindow_Advance(sw, &comp);
	assert_int_equal(0, ret);
	assert_int_equal(true, comp);

	ret = SlidingWindow_ReadBlockIter(sw, false, cb, NULL);
	assert_int_equal(SlidingWindow_ReadBlockIterCbOk, ret);

	ret = SlidingWindow_GetOffset(sw);
	assert_int_equal(5, ret);

	v = SlidingWindow_Read(sw, &s);
	assert_non_null(v);
	assert_int_equal(9, s);
	assert_memory_equal("123456789", v, s);

	free(v);

	SlidingWindow_Free(sw);
}

static int cb2(struct SlidingWindow *sw, unsigned b, void *d, size_t s,
	       struct SlidingWindow_BlockFlags *bf, void *data)
{
	int n = (intptr_t)data;

	printf("w: %d, b: %u", n, b);
	if (bf->last)
		printf(", last");
	putchar('\n');

	bf->sent = true;
	bf->received = true;

	return SlidingWindow_ReadBlockIterCbOk;
}

void Test_ReadBlockIter(void **state)
{
	bool complete;
	int ret;
	struct SlidingWindow *sw;

	sw = SlidingWindow(SlidingWindow_DirOutput, 2, 3);
	assert_non_null(sw);

	ret = SlidingWindow_Write(sw, "1234567890", 10);
	assert_int_equal(0, ret);

	ret = SlidingWindow_ReadBlockIter(sw, true, cb2, (void *)1);
	assert_int_equal(SlidingWindow_ReadBlockIterCbOk, ret);

	ret = SlidingWindow_Advance(sw, &complete);
	assert_int_equal(0, ret);
	assert_int_equal(false, complete);

	ret = SlidingWindow_ReadBlockIter(sw, true, cb2, (void *)2);
	assert_int_equal(SlidingWindow_ReadBlockIterCbOk, ret);

	ret = SlidingWindow_Advance(sw, &complete);
	assert_int_equal(0, ret);
	assert_int_equal(true, complete);

	SlidingWindow_Free(sw);
}

void Test_GetSetBlockFlags(void **state)
{
	int ret;
	struct SlidingWindow *sw;
	struct SlidingWindow_BlockFlags f1 = {.sent = true}, f2;

	sw = SlidingWindow(SlidingWindow_DirOutput, 1, 2);
	assert_non_null(sw);

	ret = SlidingWindow_GetBlockFlags(NULL, 0, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = SlidingWindow_GetBlockFlags(sw, 0, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = SlidingWindow_SetBlockFlags(NULL, 0, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = SlidingWindow_SetBlockFlags(sw, 0, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = SlidingWindow_GetBlockFlags(sw, 0, &f1);
	assert_int_equal(-1, ret);
	assert_int_equal(ENOENT, errno);

	ret = SlidingWindow_SetBlockFlags(sw, 0, &f1);
	assert_int_equal(-1, ret);
	assert_int_equal(ENOENT, errno);

	ret = SlidingWindow_WriteBlock(sw, 0, "a", 1, true, &f1);
	assert_int_equal(0, ret);

	ret = SlidingWindow_GetBlockFlags(sw, 0, &f2);
	assert_int_equal(0, ret);
	assert_memory_equal(&f1, &f2, sizeof f1);

	f1.last = true;
	ret = SlidingWindow_SetBlockFlags(sw, 0, &f1);
	assert_int_equal(0, ret);

	ret = SlidingWindow_GetBlockFlags(sw, 0, &f2);
	assert_int_equal(0, ret);
	assert_memory_equal(&f1, &f2, sizeof f1);

	SlidingWindow_Free(sw);
}

int main(int argc, char *argv[])
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(Test_Init),
		cmocka_unit_test(Test_ReadWrite),
		cmocka_unit_test(Test_ReadWriteBlock),
		cmocka_unit_test(Test_GetSetBlockFlags),
		cmocka_unit_test(Test_ReadBlockIter)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}

