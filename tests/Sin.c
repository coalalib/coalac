#include <coala/Sin.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
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

int main(int argc, char *argv[])
{
	struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ip),
		cmocka_unit_test(test_port),
		cmocka_unit_test(test_ipport)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
