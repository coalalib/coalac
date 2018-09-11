#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <cmocka.h>

#include <coala/Buf.h>

static void test_Buf_Add(void **state)
{
	int ret;
	size_t s;
	struct Buf_Handle *b;
	void *d;

	b = Buf();
	assert_non_null(b);

	ret = Buf_Add(b, "abc", 3);
	assert_int_equal(0, ret);

	ret = Buf_Add(b, "def", 3);
	assert_int_equal(0, ret);

	ret = Buf_Add(b, "\0", 1);
	assert_int_equal(0, ret);

	d = Buf_GetData(b, &s, false);
	assert_non_null(d);
	assert_int_equal(s, sizeof("abcdef"));
	assert_string_equal(d, "abcdef");

	Buf_Free(b);
}

static void test_Buf_AddStr(void **state)
{
	int ret;
	size_t s;
	struct Buf_Handle *b;
	void *d;

	b = Buf();
	assert_non_null(b);

	ret = Buf_AddStr(b, "my_");
	assert_int_equal(0, ret);

	ret = Buf_AddStr(b, "super_");
	assert_int_equal(0, ret);

	ret = Buf_AddStr(b, "string");
	assert_int_equal(0, ret);

	d = Buf_GetData(b, &s, false);
	assert_non_null(d);
	assert_int_equal(s, strlen("my_") + strlen("super_") + strlen("string"));

	ret = memcmp(d, "my_super_string", s);
	assert_int_equal(0, ret);

	Buf_Free(b);
}

static void test_Buf_AddFormatStr(void **state)
{
	int ret;
	struct Buf_Handle *b;
	size_t s;
	void *d;

	b = Buf();
	assert_non_null(b);

	ret = Buf_AddFormatStr(b, "my_%s_%d", "test", 1);
	assert_int_equal(0, ret);

	d = Buf_GetData(b, &s, false);
	assert_non_null(d);
	assert_int_equal(s, strlen("my_test_1"));

	ret = memcmp(d, "my_test_1", s);
	assert_int_equal(0, ret);

	Buf_Free(b);
}

static void test_Buf_AddCh(void **state)
{
	const char *data = "NDM";
	int ret;
	size_t s;
	struct Buf_Handle *b;
	void *d;

	b = Buf();
	assert_non_null(b);

	for (unsigned i = 0; i < strlen(data) + 1; i++) {
		ret = Buf_AddCh(b, data[i]);
		assert_int_equal(0, ret);
	}

	d = Buf_GetData(b, &s, false);
	assert_non_null(d);
	assert_string_equal(d, data);
	assert_int_equal(strlen(data) + 1, s);

	Buf_Free(b);
}

static void test_Buf_GetData(void **state)
{
	int ret;
	size_t s;
	struct Buf_Handle *b;
	void *d1, *d2;

	b = Buf();
	assert_non_null(b);

	d1 = Buf_GetData(b, NULL, false);
	assert_null(d1);
	assert_int_equal(ENODATA, errno);

	ret = Buf_AddCh(b, '\0');
	assert_int_equal(0, ret);

	d1 = Buf_GetData(b, &s, false);
	assert_non_null(d1);
	assert_int_equal(1, s);

	d2 = Buf_GetData(b, &s, true);
	assert_non_null(d2);
	assert_true(d1 != d2);
	assert_int_equal(1, s);

	free(d2);

	Buf_Free(b);
}

int main(int argc, char *argv[])
{
	struct CMUnitTest tests[] = {
		cmocka_unit_test(test_Buf_Add),
		cmocka_unit_test(test_Buf_AddStr),
		cmocka_unit_test(test_Buf_AddCh),
		cmocka_unit_test(test_Buf_AddFormatStr),
		cmocka_unit_test(test_Buf_GetData)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
