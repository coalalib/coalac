#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>

#include "SlidingWindowPool.h"

static void Test_1(void **state)
{
	int ret;
	struct SlidingWindow *sw1, *sw2, *sw3;
	struct SlidingWindowPool *p;

	p = SlidingWindowPool();
	assert_non_null(p);

	sw1 = SlidingWindow(SlidingWindow_DirInput, 2, 3);
	assert_non_null(sw1);

	sw2 = SlidingWindow(SlidingWindow_DirOutput, 3, 4);
	assert_non_null(sw2);

	sw3 = SlidingWindowPool_Get(p, "tok1", NULL, NULL);
	assert_null(sw3);
	assert_int_equal(ENOENT, errno);

	ret = SlidingWindowPool_Set(p, "tok1", sw1, NULL, NULL);
	assert_int_equal(0, ret);

	ret = SlidingWindowPool_Set(p, "tok1", sw2, NULL, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EEXIST, errno);

	ret = SlidingWindowPool_Set(p, "tok2", sw2, NULL, NULL);
	assert_int_equal(0, ret);

	sw3 = SlidingWindowPool_Get(p, "tok1", NULL, NULL);
	assert_non_null(sw3);

	ret = SlidingWindowPool_Del(p, "tok1");
	assert_int_equal(0, ret);

	sw3 = SlidingWindowPool_Get(p, "tok1", NULL, NULL);
	assert_null(sw3);
	assert_int_equal(ENOENT, errno);

	sw3 = SlidingWindowPool_Get(p, "tok2", NULL, NULL);
	assert_non_null(sw3);

	SlidingWindowPool_Free(p);
}

int main(int argc, char *argv[])
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(Test_1)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}

