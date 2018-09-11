#include <coala/HexString.h>
#include <coala/Sin.h>
#include <ndm/macro.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <setjmp.h>
#include <stdlib.h>
#include <cmocka.h>

static void test_ip(void **state)
{
	char buf[SIN_IP_SIZE];
	const char *test_ip = "123.123.123.123";
	int ret;
	struct sockaddr_in sin = {
		.sin_family = AF_INET
	};

	ret = Sin_SetIp(&sin, test_ip);
	assert_int_equal(0, ret);

	ret = Sin_GetIp(&sin, buf, sizeof buf);
	assert_int_equal(0, ret);
	assert_string_equal(test_ip, buf);
}

static void test_port(void **state)
{
	char buf[SIN_PORT_SIZE];
	const char *test_port = "65535";
	int ret;
	struct sockaddr_in sin = {
		.sin_family = AF_INET
	};

	ret = Sin_SetPort(&sin, test_port);
	assert_int_equal(0, ret);

	ret = Sin_GetPort(&sin, buf, sizeof buf);
	assert_int_equal(0, ret);
	assert_string_equal(test_port, buf);
}

static void test_ipport(void **state)
{
	char buf[SIN_IPPORT_SIZE];
	const char *test_ipport = "123.123.123.123:65535";
	int ret;
	struct sockaddr_in sin = {
		.sin_family = AF_INET
	};

	ret = Sin_SetIpPort(&sin, test_ipport);
	assert_int_equal(0, ret);

	ret = Sin_GetIpPort(&sin, buf, sizeof buf);
	assert_int_equal(0, ret);
	assert_string_equal(test_ipport, buf);
}

static void Test_Init(void **state)
{
	struct HexString *hs;

	hs = HexString();
	assert_non_null(hs);

	HexString_Free(hs);
}

static void Test_GetSetBin(void **state)
{
	uint8_t data[] = {0x12, 0x34, 0xab, 0xcd}, *d;
	int ret;
	size_t s;
	struct HexString *hs;

	hs = HexString();
	assert_non_null(hs);

	d = HexString_GetBin(NULL, &s);
	assert_null(d);
	assert_int_equal(EINVAL, errno);

	d = HexString_GetBin(hs, NULL);
	assert_null(d);
	assert_int_equal(EINVAL, errno);

	d = HexString_GetBin(hs, &s);
	assert_null(d);
	assert_int_equal(ENODATA, errno);

	ret = HexString_SetBin(NULL, data, NDM_ARRAY_SIZE(data));
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = HexString_SetBin(hs, NULL, NDM_ARRAY_SIZE(data));
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = HexString_SetBin(hs, data, 0);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = HexString_SetBin(hs, data, NDM_ARRAY_SIZE(data));
	assert_int_equal(0, ret);

	d = HexString_GetBin(hs, &s);
	assert_non_null(d);
	assert_int_equal(NDM_ARRAY_SIZE(data), s);

	assert_memory_equal(data, d, s);
	free(d);

	char *t = HexString_Get(hs);
	assert_non_null(t);
	assert_string_equal("1234abcd", t);
	free(t);

	ret = HexString_SetBin(hs, (uint8_t *)"\xff", 1);
	assert_int_equal(0, ret);

	d = HexString_GetBin(hs, &s);
	assert_non_null(d);
	assert_int_equal(1, s);
	assert_memory_equal((uint8_t *)"\xff", d, 1);
	free(d);

	HexString_Free(hs);
}

static void Test_GetSet(void **state)
{
	char *s;
	int ret;
	struct HexString *hs;

	hs = HexString();
	assert_non_null(hs);

	s = HexString_Get(NULL);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = HexString_Get(hs);
	assert_null(s);
	assert_int_equal(ENODATA, errno);

	ret = HexString_Set(NULL, "12");
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = HexString_Set(hs, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = HexString_Set(hs, "1");
	assert_int_equal(-1, ret);
	assert_int_equal(EBADE, errno);

	ret = HexString_Set(hs, "az");
	assert_int_equal(-1, ret);
	assert_int_equal(EBADE, errno);

	ret = HexString_Set(hs, "1234abcd");
	assert_int_equal(0, ret);

	s = HexString_Get(hs);
	assert_non_null(s);

	assert_string_equal("1234abcd", s);
	free(s);

	size_t d_size;
	uint8_t *d = HexString_GetBin(hs, &d_size);
	assert_non_null(d);
	assert_int_equal(strlen("1234abcd") / 2, d_size);
	assert_memory_equal("\x12\x34\xab\xcd", d, d_size);

	free(d);

	HexString_Free(hs);
}

int main(int argc, char *argv[])
{
	struct CMUnitTest tests[] = {
		cmocka_unit_test(Test_Init),
		cmocka_unit_test(Test_GetSetBin),
		cmocka_unit_test(Test_GetSet),
		cmocka_unit_test(test_ip),
		cmocka_unit_test(test_port),
		cmocka_unit_test(test_ipport)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
