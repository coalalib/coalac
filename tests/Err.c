#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "Err.h"

#define LONG_STRING_50	"WuqESrAYG4UuXqGkICNcKZHAcA6h8OL2om4vveUv77Bc9uy2nk"
#define LONG_STRING_97	"o3Yah0tD0NUjkCxVLN99CsHaB9i6rgrTDWy7OJMSASyN7EtqVF" \
			"bD7Ww8O5fE75x121zmC46SnaAZkDpPzMHMcSF6WetEApEBr"
#define LONG_STRING_100 "o3Yah0tD0NUjkCxVLN99CsHaB9i6rgrTDWy7OJMSASyN7EtqVF" \
			"bD7Ww8O5fE75x121zmC46SnaAZkDpPzMHMcSF6WetEApEBrMDE"

static void test_1(void **state)
{
	struct Err e;

	Err_Init(&e, NULL);
	assert_true(e.src[0] == '\0');

	Err_Init(&e, "source");
	assert_string_equal("source", e.src);

	Err_Init(&e, LONG_STRING_50);
	assert_true(e.src[sizeof e.src - 1] == '\0');
	assert_memory_equal(LONG_STRING_50, e.src, sizeof e.src - 1);
	assert_int_equal(-1, e.code);

	Err_Set(&e, 0, "test");
	assert_string_equal("test", e.dsc);
	assert_int_equal(0, e.code);

	Err_Set(&e, -1, "test_%d_%s", 1, "a");
	assert_string_equal("test_1_a", e.dsc);

	errno = EINVAL;
	Err_Set(&e, -1, "bugaga:", 1, "a");
	assert_string_equal("bugaga: Invalid argument", e.dsc);

	Err_Set(&e, -1, LONG_STRING_100);
	assert_true(e.dsc[sizeof e.dsc - 1] == '\0');
	assert_memory_equal(LONG_STRING_100, e.dsc, sizeof e.dsc - 1);

	errno = EINVAL;
	Err_Set(&e, -1, "%s:", LONG_STRING_100);
	assert_true(e.dsc[sizeof e.dsc - 1] == '\0');
	assert_memory_equal(LONG_STRING_100, e.dsc, sizeof e.dsc - 1);

	errno = EINVAL;
	Err_Set(&e, -1, "%s:", LONG_STRING_97);
	assert_true(e.dsc[sizeof e.dsc - 1] == '\0');
	assert_memory_equal(LONG_STRING_97 ": ", e.dsc, sizeof e.dsc - 1);
}

int main(int argc, char *argv[])
{
	struct CMUnitTest tests[] = {
		cmocka_unit_test(test_1)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
