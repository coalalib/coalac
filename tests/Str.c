#include <ndm/macro.h>
#include <ctype.h>
#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "Str.h"

static const struct {
	char c;
	unsigned char h;
} Data[] = {
	{'0', 0}, {'1', 1}, {'2', 2},
	{'3', 3}, {'4', 4}, {'5', 5},
	{'6', 6}, {'7', 7}, {'8', 8},
	{'9', 9},
	{'a', 0xa}, {'b', 0xb}, {'c', 0xc},
	{'d', 0xd}, {'e', 0xe}, {'f', 0xf}
};

static void test_Str_Char2Hex(void **state)
{
	for (unsigned i = 0; i < NDM_ARRAY_SIZE(Data); i++) {
		char c;
		unsigned char h, r;

		c = Data[i].c;
		h = Data[i].h;

		r = Str_Char2Hex(c);
		assert_int_equal(h, r);

		if (isalpha(c)) {
			r = Str_Char2Hex(toupper(c));
			assert_int_equal(h, r);
		}
	}
}

static void test_Str_Hex2Char(void **state)
{
	for (unsigned i = 0; i < NDM_ARRAY_SIZE(Data); i++) {
		char r = Str_Hex2Char(Data[i].h);
		assert_int_equal(Data[i].c, r);
	}
}

static void test_Str_strnchr(void **state)
{
	char *s;
	const char *t = "abcdef";

	s = Str_strnchr(t, 0, 'f');
	assert_null(s);

	s = Str_strnchr(t, strlen(t) - 1, 'f');
	assert_null(s);

	s = Str_strnchr(t, strlen(t), 'f');
	assert_non_null(s);
	assert_true(*s == 'f');

	s = Str_strnchr(t, strlen(t) + 1, 'z');
	assert_null(s);

	s = Str_strnchr(t, strlen(t) + 2, 'e');
	assert_non_null(s);
	assert_true(*s == 'e');
}

static void test_Str_FromArr(void **state)
{
	uint8_t a[] = {0xab, 0xbc, 0xd, 0xe, 0xf};
	char buf[sizeof(a) * 2 + 1], *s;

	/* Invalid params */
	s = Str_FromArr(NULL, 0, NULL, 0);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = Str_FromArr(a, 0, NULL, 0);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = Str_FromArr(a, sizeof a, NULL, 0);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = Str_FromArr(a, sizeof a, buf, 0);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = Str_FromArr(a, NDM_ARRAY_SIZE(a), buf, sizeof buf - 1);
	assert_null(s);
	assert_int_equal(ENOSPC, errno);

	/* Good */
	s = Str_FromArr(a, NDM_ARRAY_SIZE(a), buf, sizeof buf);
	assert_non_null(s);
	assert_string_equal("abbc0d0e0f", s);
}

static void test_Str_SizeFormat(void **state)
{
	char buf[50];

	Str_SizeFormat(0, buf, sizeof buf);
	assert_string_equal("0 B", buf);

	Str_SizeFormat(1023, buf, sizeof buf);
	assert_string_equal("1023 B", buf);

	Str_SizeFormat(1024, buf, sizeof buf);
	assert_string_equal("1.00 KiB", buf);

	Str_SizeFormat(1024 * 1024, buf, sizeof buf);
	assert_string_equal("1.00 MiB", buf);

	Str_SizeFormat(1024 * 1024 * 1024, buf, sizeof buf);
	assert_string_equal("1.00 GiB", buf);

	Str_SizeFormat(1024ULL * 1024 * 1024 * 1024, buf, sizeof buf);
	assert_string_equal("1.00 TiB", buf);
}

static void test_Str_SpeedFormat(void **state)
{
	char buf[50];

	Str_SpeedFormat(0, buf, sizeof buf);
	assert_string_equal("0 B/s", buf);

	Str_SpeedFormat(1023, buf, sizeof buf);
	assert_string_equal("1023 B/s", buf);

	Str_SpeedFormat(1024, buf, sizeof buf);
	assert_string_equal("1.00 KiB/s", buf);

	Str_SpeedFormat(1024 * 1024, buf, sizeof buf);
	assert_string_equal("1.00 MiB/s", buf);

	Str_SpeedFormat(1024 * 1024 * 1024, buf, sizeof buf);
	assert_string_equal("1.00 GiB/s", buf);

	Str_SpeedFormat(1024ULL * 1024 * 1024 * 1024, buf, sizeof buf);
	assert_string_equal("1.00 TiB/s", buf);
}

static void test_Str_Low_Up(void **state)
{
	char buf[] = "abcdef";

	Str_Low(NULL);
	Str_Up(NULL);

	Str_Up(buf);
	assert_string_equal("ABCDEF", buf);

	Str_Low(buf);
	assert_string_equal("abcdef", buf);
}

int main(int argc, char *argv[])
{
	struct CMUnitTest tests[] = {
		cmocka_unit_test(test_Str_Char2Hex),
		cmocka_unit_test(test_Str_Hex2Char),
		cmocka_unit_test(test_Str_strnchr),
		cmocka_unit_test(test_Str_FromArr),
		cmocka_unit_test(test_Str_SizeFormat),
		cmocka_unit_test(test_Str_SpeedFormat),
		cmocka_unit_test(test_Str_Low_Up)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
