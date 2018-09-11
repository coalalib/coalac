#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdlib.h>
#include <cmocka.h>

#include <coala/Uri.h>

static void _test_uri_parse(const char *uri, int ret, bool secure,
			    uint16_t port, char *host, char *path, char *query)
{
	int r;
	struct Uri u;

	printf("uri: %s\n", uri);

	r = Uri_Parse(&u, uri);
	assert_int_equal(ret, r);

	if (!r) {
		assert_int_equal(secure, u.secure);
		assert_int_equal(port, u.port);

		assert_non_null(u.host);
		assert_string_equal(host, u.host);

		if (path == NULL) {
			assert_null(u.path);
		} else {
			assert_non_null(u.path);
			assert_string_equal(path, u.path);
		}

		if (query == NULL) {
			assert_null(u.query);
		} else {
			assert_non_null(u.query);
			assert_string_equal(query, u.query);
		}

		Uri_ParseFree(&u);
	}
}

#define PORT 5683

static void test_uri_parse(void **state)
{
	_test_uri_parse(NULL, -1, false, 0, NULL, NULL, NULL);
	_test_uri_parse("", -1, false, 0, NULL, NULL, NULL);
	_test_uri_parse("coap://", -1, false, 0, NULL, NULL, NULL);
	_test_uri_parse("coap://:1234", -1, false, 0, NULL, NULL, NULL);
	_test_uri_parse("coap://?abc", -1, false, 0, NULL, NULL, NULL);
	_test_uri_parse("coap://:1234?abc", -1, false, 0, NULL, NULL, NULL);

	/* Secure */
	_test_uri_parse("coaps://1.2.3.4",
			0, true, PORT, "1.2.3.4", NULL, NULL);

	/* Fragment */
	_test_uri_parse("coap://1.2.3.4#abc",
			0, false, PORT, "1.2.3.4", NULL, NULL);
	_test_uri_parse("coap://1.2.3.4/#abc",
			0, false, PORT, "1.2.3.4", NULL, NULL);

	/* Query */
	_test_uri_parse("coap://1.2.3.4?abc",
			0, false, PORT, "1.2.3.4", NULL, "?abc");
	_test_uri_parse("coap://1.2.3.4/?abc",
			0, false, PORT, "1.2.3.4", NULL, "?abc");
	_test_uri_parse("coap://1.2.3.4?abc#frag",
			0, false, PORT, "1.2.3.4", NULL, "?abc");
	_test_uri_parse("coap://1.2.3.4/?abc#frag",
			0, false, PORT, "1.2.3.4", NULL, "?abc");

	/* Path */
	_test_uri_parse("coap://1.2.3.4/abc/def",
			0, false, PORT, "1.2.3.4", "/abc/def", NULL);
	_test_uri_parse("coap://1.2.3.4/abc/def/",
			0, false, PORT, "1.2.3.4", "/abc/def", NULL);
	_test_uri_parse("coap://1.2.3.4/abc/def#frag",
			0, false, PORT, "1.2.3.4", "/abc/def", NULL);
	_test_uri_parse("coap://1.2.3.4/abc/def/#frag",
			0, false, PORT, "1.2.3.4", "/abc/def", NULL);

	/* Query & Path */
	_test_uri_parse("coap://1.2.3.4/abc/def?qu",
			0, false, PORT, "1.2.3.4", "/abc/def", "?qu");
	_test_uri_parse("coap://1.2.3.4/abc/def/?qu",
			0, false, PORT, "1.2.3.4", "/abc/def", "?qu");

	/* Port */
	_test_uri_parse("coap://1.2.3.4:1234",
			0, false, 1234, "1.2.3.4", NULL, NULL);
	_test_uri_parse("coap://1.2.3.4:1234/",
			0, false, 1234, "1.2.3.4", NULL, NULL);
	_test_uri_parse("coap://1.2.3.4:1234#frag",
			0, false, 1234, "1.2.3.4", NULL, NULL);
	_test_uri_parse("coap://1.2.3.4:1234/#frag",
			0, false, 1234, "1.2.3.4", NULL, NULL);

	/* Port & Query */
	_test_uri_parse("coap://1.2.3.4:1234?q1&q2",
			0, false, 1234, "1.2.3.4", NULL, "?q1&q2");
	_test_uri_parse("coap://1.2.3.4:1234/?q1&q2",
			0, false, 1234, "1.2.3.4", NULL, "?q1&q2");

	/* Port & Path */
	_test_uri_parse("coap://1.2.3.4:1234/abc/def",
			0, false, 1234, "1.2.3.4", "/abc/def", NULL);
	_test_uri_parse("coap://1.2.3.4:1234/abc/def/",
			0, false, 1234, "1.2.3.4", "/abc/def", NULL);

	/* Port, Path & Query */
	_test_uri_parse("coap://1.2.3.4:1234/abc/def?q1&q2",
			0, false, 1234, "1.2.3.4", "/abc/def", "?q1&q2");
	_test_uri_parse("coap://1.2.3.4:1234/abc/def/?q1&q2",
			0, false, 1234, "1.2.3.4", "/abc/def", "?q1&q2");

}

static void test_uri_parse_path(void **state)
{
	const char *a[] = {"a", "b", "c", "d e", "f", "g"};
	int ret;
	struct Uri_ParsePathEntry *e;
	struct Uri_ParsePathHead h = STAILQ_HEAD_INITIALIZER(h);
	size_t n;

	ret = Uri_ParsePath(&h, "/a/b/c/d%20e/f/g");
	assert_int_equal(0, ret);

	n = 0;
	STAILQ_FOREACH(e, &h, list) {
		assert_non_null(e->s);
		assert_string_equal(a[n], e->s);
		n++;
	}
	assert_int_equal(6, n);

	Uri_ParsePathFree(&h);
}

static void test_uri_parse_query_keyvalue(void **state)
{
	int ret;
	struct Uri_ParseQueryEntry *e;
	struct Uri_ParseQueryHead h = STAILQ_HEAD_INITIALIZER(h);
	size_t n;
	struct {
		const char *k;
		const char *v;
	} a[] = {
		{"login", "admin"},
		{"some_param", NULL},
		{"pass", "super pass"}
	};

	ret = Uri_ParseQuery(&h, "?login=admin&some_param&pass=super%20pass",
			     true);
	assert_int_equal(0, ret);

	n = 0;
	STAILQ_FOREACH(e, &h, list) {
		assert_non_null(e->key);
		assert_string_equal(a[n].k, e->key);

		if (a[n].v == NULL) {
			assert_null(e->value);
		} else {
			assert_non_null(e->value);
			assert_string_equal(a[n].v, e->value);
		}
		n++;
	}
	assert_int_equal(3, n);

	Uri_ParseQueryFree(&h);
}

static void test_uri_parse_query_wo_keyvalue(void **state)
{
	const char *a[] = {"login=admin", "some_param", "pass=super pass"};
	int ret;
	struct Uri_ParseQueryEntry *e;
	struct Uri_ParseQueryHead h = STAILQ_HEAD_INITIALIZER(h);
	size_t n;

	ret = Uri_ParseQuery(&h, "?login=admin&some_param&pass=super%20pass",
			     false);
	assert_int_equal(0, ret);

	n = 0;
	STAILQ_FOREACH(e, &h, list) {
		assert_non_null(e->key);
		assert_null(e->value);
		assert_string_equal(a[n], e->key);
		n++;
	}
	assert_int_equal(3, n);

	Uri_ParseQueryFree(&h);
}

static const char *uri_data_decoded =
	"!*'();:@&=+$,/&#[]"
	"-_.~"
	" "
	"ABCDEFGHIJKLMNOPQRSTUWXYZ"
	"abcdefghijklmnopqrstuwxyz"
	"01234567890";

static const char *uri_data_encoded =
	"%21%2A%27%28%29%3B%3A%40%26%3D%2B%24%2C%2F%26%23%5B%5D"
	"-_.~"
	"+"
	"ABCDEFGHIJKLMNOPQRSTUWXYZ"
	"abcdefghijklmnopqrstuwxyz"
	"01234567890";


static void test_uri_encode_str(void **state)
{
	char *r;

	r = Uri_EncodeStr(uri_data_decoded);
	assert_non_null(r);
	assert_string_equal(uri_data_encoded, r);

	free(r);
}

static void test_uri_decode_str(void **state)
{
	char *r;

	r = Uri_DecodeStr(uri_data_encoded);
	assert_non_null(r);
	assert_string_equal(uri_data_decoded, r);

	free(r);
}

static void _test_uri_gen(bool secure,
			  const char *host, uint16_t port,
			  const char *path, const char *query,
			  char *exp_res, int exp_errno)
{
	char *s;
	struct Uri u;

	u.secure = secure;
	u.port = port;
	u.host = (char *)host;
	u.path = (char *)path;
	u.query = (char *)query;

	s = Uri_Gen(&u);
	if (exp_res) {
		assert_non_null(s);
		assert_string_equal(exp_res, s);
	} else {
		assert_null(s);
		assert_int_equal(exp_errno, errno);
	}

	free(s);
}

static void test_uri_gen(void **state)
{
	char *s = Uri_Gen(NULL);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	_test_uri_gen(false, NULL, 0, NULL, NULL,
		      NULL, EINVAL);
	_test_uri_gen(false, "", 0, NULL, NULL,
		      NULL, EINVAL);
	_test_uri_gen(false, "coap.me", 0, "", NULL,
		      NULL, EINVAL);
	_test_uri_gen(false, "coap.me", 0, "a/b", NULL,
		      NULL, EINVAL);
	_test_uri_gen(false, "coap.me", 0, NULL, "",
		      NULL, EINVAL);
	_test_uri_gen(false, "coap.me", 0, NULL, "a=b",
		      NULL, EINVAL);
	_test_uri_gen(true, "coap.me", 0, NULL, NULL,
		      "coaps://coap.me:0", 0);
	_test_uri_gen(false, "coap.me", 5683, NULL, NULL,
		      "coap://coap.me", 0);
	_test_uri_gen(false, "coap.me", 0, "/abc/bcd/", NULL,
		      "coap://coap.me:0/abc/bcd/", 0);
	_test_uri_gen(false, "coap.me", 0, NULL, "?one=1&two=2&three",
		      "coap://coap.me:0?one=1&two=2&three", 0);
	_test_uri_gen(true, "coap.me", 5683, "/abc/bcd", "?one=1&two=2&three",
		      "coaps://coap.me/abc/bcd?one=1&two=2&three", 0);
}

static void test_uri_encode_path(void **state)
{
	char *s;

	s = Uri_EncodePath(NULL);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = Uri_EncodePath("");
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = Uri_EncodePath("a/b");
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = Uri_EncodePath("/a/b");
	assert_non_null(s);
	assert_string_equal("/a/b", s);
	free(s);

	s = Uri_EncodePath("/a/b/");
	assert_non_null(s);
	assert_string_equal("/a/b", s);
	free(s);

	s = Uri_EncodePath("/a/b d/");
	assert_non_null(s);
	assert_string_equal("/a/b+d", s);
	free(s);
}

static void test_uri_encode_query(void **state)
{
	char *s;

	s = Uri_EncodeQuery(NULL, false);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = Uri_EncodeQuery("", false);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = Uri_EncodeQuery("a=b", false);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = Uri_EncodeQuery("?a=b&c=d&e", false);
	assert_non_null(s);
	assert_string_equal("?a%3Db&c%3Dd&e", s);
	free(s);

	s = Uri_EncodeQuery("?a=b&c=d&e&", false);
	assert_non_null(s);
	assert_string_equal("?a%3Db&c%3Dd&e", s);
	free(s);

	s = Uri_EncodeQuery("?a=b&c=d&e", true);
	assert_non_null(s);
	assert_string_equal("?a=b&c=d&e", s);
	free(s);

	s = Uri_EncodeQuery("?a=b&c=d&e&", true);
	assert_non_null(s);
	assert_string_equal("?a=b&c=d&e", s);
	free(s);

	s = Uri_EncodeQuery("?a=b d", true);
	assert_non_null(s);
	assert_string_equal("?a=b+d", s);
	free(s);
}

int main(int argc, char *argv[])
{
	struct CMUnitTest tests[] = {
		cmocka_unit_test(test_uri_parse),
		cmocka_unit_test(test_uri_parse_path),
		cmocka_unit_test(test_uri_parse_query_keyvalue),
		cmocka_unit_test(test_uri_parse_query_wo_keyvalue),
		cmocka_unit_test(test_uri_encode_str),
		cmocka_unit_test(test_uri_decode_str),
		cmocka_unit_test(test_uri_gen),
		cmocka_unit_test(test_uri_encode_path),
		cmocka_unit_test(test_uri_encode_query)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
