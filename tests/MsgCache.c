#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <coala/CoAPMessage.h>
#include <ndm/time.h>
#include <cmocka.h>

#include "MsgCache.h"

int64_t __wrap_ndm_time_left_monotonic_msec(const struct timespec *t)
{
	return mock_type(int);
}

static void test_1(void **state)
{
	int ret;

	ret = MsgCache_Init();
	assert_int_equal(0, ret);

	MsgCache_Deinit();
}

static void test_2(void **state)
{
	struct MsgCache_Stats st;
	struct CoAPMessage *m1, *m2;
	int ret;

	ret = MsgCache_Add(0, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	m2 = MsgCache_Get(0, NULL);
	assert_null(m2);
	assert_int_equal(EINVAL, errno);

	ret = MsgCache_Stats(NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = MsgCache_Init();
	assert_int_equal(0, ret);

	m1 = CoAPMessage(CoAPMessage_TypeAck, CoAPMessage_CodeChanged, -1,
			 CoAPMessage_FlagGenToken);
	assert_non_null(m1);

	ret = MsgCache_Add(0, m1);
	assert_int_equal(-1, ret);
	assert_int_equal(ENODATA, errno);

	ret = CoAPMessage_SetUri(m1, "coap://127.0.0.1/info", 0);
	assert_int_equal(0, ret);

	ret = MsgCache_Add(0, m1);
	assert_int_equal(0, ret);

	m2 = MsgCache_Get(0, m1);
	assert_non_null(m2);

	ret = MsgCache_Add(0, m1);
	assert_int_equal(-1, ret);
	assert_int_equal(EEXIST, errno);

	ret = MsgCache_Stats(&st);
	assert_int_equal(0, ret);
	assert_int_equal(1, st.current);
	assert_int_equal(1, st.match);
	assert_int_equal(1, st.total);

	will_return(__wrap_ndm_time_left_monotonic_msec, 1);
	MsgCache_Cleaner();

	m2 = MsgCache_Get(0, m1);
	assert_non_null(m2);

	ret = MsgCache_Stats(&st);
	assert_int_equal(0, ret);
	assert_int_equal(1, st.current);
	assert_int_equal(2, st.match);
	assert_int_equal(1, st.total);

	will_return(__wrap_ndm_time_left_monotonic_msec, -1);
	MsgCache_Cleaner();

	m2 = MsgCache_Get(0, m1);
	assert_null(m2);
	assert_int_equal(ENOENT, errno);

	ret = MsgCache_Stats(&st);
	assert_int_equal(0, ret);
	assert_int_equal(0, st.current);
	assert_int_equal(2, st.match);
	assert_int_equal(1, st.total);

	CoAPMessage_Free(m1);

	MsgCache_Deinit();
}

static void test_3(void **state)
{
	char k[MSGCACHE_KEY_SIZE];
	int ret;
	struct CoAPMessage *m;
	uint8_t t[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

	ret = KeyGen(NULL, k);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	m = CoAPMessage(CoAPMessage_TypeAck, CoAPMessage_CodeChanged, 65535, 0);
	assert_non_null(m);

	ret = KeyGen(m, k);
	assert_int_equal(-1, ret);
	assert_int_equal(ENODATA, errno);

	ret = CoAPMessage_SetUri(m, "coap://128.128.128.128:12345", 0);
	assert_int_equal(0, ret);

	ret = KeyGen(m, k);
	assert_int_equal(0, ret);
	assert_string_equal("128.128.128.128:12345_65535_", k);

	ret = CoAPMessage_SetToken(m, t, sizeof t);
	assert_int_equal(0, ret);

	ret = KeyGen(m, k);
	assert_int_equal(0, ret);
	assert_string_equal("128.128.128.128:12345_65535_1122334455667788", k);

	CoAPMessage_Free(m);
}

int main(int argc, char *argv[])
{
	struct CMUnitTest tests[] = {
		cmocka_unit_test(test_1),
		cmocka_unit_test(test_2),
		cmocka_unit_test(test_3)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
