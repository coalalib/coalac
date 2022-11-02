#include <arpa/inet.h>
#include <coap2/coap.h>
#include <ndm/macro.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

#include <coala/CoAPMessage.h>
#include <ndm/ip_sockaddr.h>

static void test_id(void **state)
{
	int ret1, ret2;
	unsigned id = 0xffff;
	struct CoAPMessage *m1, *m2;

	/* Fixed ID */
	m1 = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, id, 0);
	assert_non_null(m1);

	ret1 = CoAPMessage_GetId(m1);
	assert_true(ret1 != -1);
	assert_int_equal(id, ret1);

	CoAPMessage_Free(m1);

	/* Generate ID */
	m1 = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	m2 = CoAPMessage(CoAPMessage_TypeNon, CoAPMessage_CodePost, -1, 0);
	assert_non_null(m1);
	assert_non_null(m2);

	ret1 = CoAPMessage_GetId(m1);
	ret2 = CoAPMessage_GetId(m2);
	assert_true(ret1 != -1);
	assert_true(ret2 != -1);

	assert_true(ret1 != ret2);

	CoAPMessage_Free(m1);
	CoAPMessage_Free(m2);
}

static void test_payload(void **state)
{
	const char pl1[] = "payload_1", pl2[] = "payload_2";
	int ret;
	size_t s;
	struct CoAPMessage *m;
	uint8_t *d;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeNotFound, 0, 0);
	assert_non_null(m);

	d = CoAPMessage_GetPayload(m, NULL, 0);
	assert_null(d);
	assert_int_equal(ENODATA, errno);

	/* pl1 */
	ret = CoAPMessage_SetPayload(m, (uint8_t *)pl1, sizeof pl1);
	assert_int_equal(0, ret);

	d = CoAPMessage_GetPayload(m, &s, 0);
	assert_non_null(d);
	assert_int_equal(s, sizeof pl1);
	assert_string_equal(pl1, d);

	/* pl2 */
	ret = CoAPMessage_SetPayload(m, (uint8_t *)pl2, sizeof pl2);
	assert_int_equal(0, ret);

	d = CoAPMessage_GetPayload(m, &s, 0);
	assert_non_null(d);
	assert_int_equal(s, sizeof pl2);
	assert_string_equal(pl2, d);

	/* Remove payload */
	ret = CoAPMessage_SetPayload(m, NULL, 0);
	assert_int_equal(0, ret);

	d = CoAPMessage_GetPayload(m, &s, 0);
	assert_null(d);
	assert_int_equal(ENODATA, errno);

	CoAPMessage_Free(m);
}

static void test_token(void **state)
{
	char buf[COAP_MESSAGE_MAX_TOKEN_SIZE];
	const char token[] = "12345", long_token[] = "123456789";
	int ret;
	size_t size;
	struct CoAPMessage *m1;

	m1 = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, 0, 0);
	assert_non_null(m1);

	/* Try to obtain token in message without it */
	size = sizeof buf;
	ret = CoAPMessage_GetToken(m1, (uint8_t *)buf, &size);
	assert_int_equal(-1, ret);
	assert_int_equal(ENODATA, errno);

	/* Simple token */
	ret = CoAPMessage_SetToken(m1, (uint8_t *)token, sizeof token);
	assert_int_equal(0, ret);

	size = sizeof buf;
	ret = CoAPMessage_GetToken(m1, (uint8_t *)buf, &size);
	assert_int_equal(0, ret);
	assert_int_equal(sizeof token, size);
	assert_string_equal(token, buf);

	/* Too long token */
	ret = CoAPMessage_SetToken(m1, (uint8_t *)long_token, sizeof long_token);
	assert_int_equal(-1, ret);

	/* Reset token */
	ret = CoAPMessage_SetToken(m1, NULL, 0);
	assert_int_equal(0, ret);

	size = sizeof buf;
	ret = CoAPMessage_GetToken(m1, (uint8_t *)buf, &size);
	assert_int_equal(-1, ret);
	assert_int_equal(ENODATA, errno);

	ret = CoAPMessage_GenToken(NULL, sizeof buf);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_GenToken((uint8_t *)buf, 0);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	/* Token generator */
	ret = CoAPMessage_GenToken((uint8_t *)buf,
				   COAP_MESSAGE_MAX_TOKEN_SIZE + 1);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	size = sizeof buf;
	ret = CoAPMessage_GenToken((uint8_t *)buf, sizeof buf);
	assert_int_equal(0, ret);

	CoAPMessage_Free(m1);

	struct CoAPMessage *m2;

	m2 = CoAPMessage(CoAPMessage_TypeCon,
			 CoAPMessage_CodeGet,
			 0,
			 CoAPMessage_FlagGenToken);
	assert_non_null(m2);

	size = sizeof buf;
	ret = CoAPMessage_GetToken(m2, (uint8_t *)buf, &size);
	assert_int_equal(0, ret);

	CoAPMessage_Free(m2);
}

#define TOKEN_BIT	(1 << 0)
#define OPTIONS_BIT	(1 << 1)
#define PAYLOAD_BIT	(1 << 2)
#define MASK		(TOKEN_BIT | OPTIONS_BIT | PAYLOAD_BIT)

static void __test_tobytes_frombytes(unsigned mask)
{
	coap_pdu_t *p;
	int ret;
	size_t s1, s2;
	struct CoAPMessage *m;
	uint8_t *d1, *d2;
	unsigned id = 0xf1f2;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, id, 0);
	assert_non_null(m);

	p = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_GET, id,
			  COAP_DEFAULT_MTU);
	assert_non_null(p);

	if (mask & TOKEN_BIT) {
		const char tok[] = "1234";

		ret = CoAPMessage_SetToken(m, (uint8_t *)tok, sizeof tok);
		assert_int_equal(0, ret);

		ret = coap_add_token(p, sizeof tok, (uint8_t *)tok);
		assert_int_equal(1, ret);
	}

	if (mask & OPTIONS_BIT) {
		const char val[] = "babavab";
		unsigned char t[4];
		unsigned opt_num;

		/* Simple options */
		opt_num = 1;

		ret = CoAPMessage_AddOptionString(m, opt_num, "a");
		assert_int_equal(0, ret);

		ret = coap_add_option(p, opt_num, 1, (uint8_t *)"a");
		assert_true(ret > 0);

		ret = CoAPMessage_AddOptionString(m, opt_num, "b");
		assert_int_equal(0, ret);

		ret = coap_add_option(p, opt_num, 1, (uint8_t *)"b");
		assert_true(ret > 0);

		ret = CoAPMessage_AddOptionString(m, opt_num, "c");
		assert_int_equal(0, ret);

		ret = coap_add_option(p, opt_num, 1, (uint8_t *)"c");
		assert_true(ret > 0);

		opt_num++;

		unsigned test_uints[] = {
			0,
			1,
			255,
			256,
			65535,
			65536,
			16777215,
			16777216
		};

		for (unsigned i = 0; i < NDM_ARRAY_SIZE(test_uints); i++) {
			unsigned v = test_uints[i];

			ret = CoAPMessage_AddOptionUint(m, opt_num, v);
			assert_int_equal(0, ret);

			ret = coap_add_option(p, opt_num,
					      coap_encode_var_safe(t, sizeof v, v), t);
			assert_true(ret > 0);

			opt_num++;
		}

		/* Options with extra byte */
		opt_num += 13;

		ret = CoAPMessage_AddOptionString(m, opt_num, val);
		assert_int_equal(0, ret);

		ret = coap_add_option(p, opt_num, strlen(val), (uint8_t *)val);
		assert_true(ret > 0);

		opt_num++;

		ret = CoAPMessage_AddOptionString(m, opt_num, val);
		assert_int_equal(0, ret);

		ret = coap_add_option(p, opt_num, strlen(val), (uint8_t *)val);
		assert_true(ret > 0);

		/* Options with extra short */
		opt_num += 269;

		unsigned test_val_sizes[] = {
			0,
			1,
			13,
			14,
			269,
			270,
			/* 65535 + 269 libcoap limits the message max size */
		};

		for (unsigned i = 0; i < NDM_ARRAY_SIZE(test_val_sizes); i++) {
			unsigned s = test_val_sizes[i];
			void *v;

			v = calloc(1, s);
			assert_non_null(v);

			ret = CoAPMessage_AddOptionOpaque(m, opt_num, v, s);
			assert_int_equal(0, ret);

			ret = coap_add_option(p, opt_num, s, v);
			assert_true(ret > 0);

			free(v);

			opt_num++;
		}
	}

	if (mask & PAYLOAD_BIT) {
		const char pay[] = "payload";

		ret = CoAPMessage_SetPayload(m, (uint8_t *)pay, sizeof pay);
		assert_int_equal(0, ret);

		ret = coap_add_data(p, sizeof pay, (uint8_t *)pay);
		assert_int_equal(1, ret);
	}

	/* Comparing with libcoap */
	d1 = CoAPMessage_ToBytes(m, &s1);
	assert_non_null(d1);

	coap_pdu_encode_header(p, COAP_PROTO_UDP);

	uint8_t *p_tok = p->token - p->hdr_size;
	size_t p_len = p->used_size + p->hdr_size;

	/*
	for (unsigned i = 0; i < p_len; i++) {
		printf("%02hhx ", ((uint8_t *)(p_tok))[i]);
		if (i % 16 == 15)
			putchar('\n');
	}

	putchar('\n');

	for (unsigned i = 0; i < s1; i++) {
		printf("%02hhx ", d1[i]);
		if (i % 16 == 15)
			putchar('\n');
	}
	*/

	assert_int_equal(p_len, s1);
	assert_memory_equal(p_tok, d1, s1);

	CoAPMessage_Free(m);
	coap_delete_pdu(p);

	/* bytes -> CoAPMessage -> bytes */
	m = CoAPMessage_FromBytes(d1, s1);
	assert_non_null(m);

	d2 = CoAPMessage_ToBytes(m, &s2);
	assert_non_null(d2);

	assert_int_equal(s1, s2);
	assert_memory_equal(d1, d2, s1);

	CoAPMessage_Free(m);
	free(d1);
	free(d2);
}

static void test_tobytes_frombytes(void **state)
{
	unsigned i;

	for (i = 0; i <= MASK; i++) {
		printf("mask: ");

		if (!i) {
			printf("empty");
		} else  {
			if (i & TOKEN_BIT)
				printf("token ");

			if (i & OPTIONS_BIT)
				printf("options ");

			if (i & PAYLOAD_BIT)
				printf("payload ");
		}

		putchar('\n');

		__test_tobytes_frombytes(i);
	}
}

static void test_coap_message_option(void **state)
{
	struct {
		uint8_t code;
		uint8_t *val;
		uint8_t len;
	} input[] = {
		{0, NULL, 0},
		{0xff, (uint8_t *)"12345", 5}
	};
	struct CoAPMessage_Option *o, *d;

	for (unsigned i = 0; i < NDM_ARRAY_SIZE(input); i++) {
		o = CoAPMessage_Option(input[i].code, input[i].val, input[i].len);
		assert_non_null(o);

		assert_int_equal(input[i].code, o->code);
		assert_int_equal(input[i].len, o->value_len);
		assert_memory_equal(input[i].val, o->value, o->value_len);

		d = CoAPMessage_OptionDup(o);
		assert_non_null(d);

		assert_int_equal(input[i].code, d->code);
		assert_int_equal(input[i].len, d->value_len);
		assert_memory_equal(input[i].val, d->value, d->value_len);

		CoAPMessage_OptionFree(o);
		CoAPMessage_OptionFree(d);
	}
}

static void test_coap_message_get_options(void **state)
{
	int ret;
	size_t n = 0;
	struct CoAPMessage *m;
	struct CoAPMessage_Option *o;
	struct CoAPMessage_OptionHead h = TAILQ_HEAD_INITIALIZER(h);
	const char *arr[] = {"welcome", "to", "sun", "trope"};

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m);

	for (unsigned i = 0; i < NDM_ARRAY_SIZE(arr); i++) {
		ret = CoAPMessage_AddOptionString(m, 1, arr[i]);
		assert_int_equal(0, ret);
	}

	ret = CoAPMessage_GetOptions(m, 1, &h);
	assert_int_equal(0, ret);

	TAILQ_FOREACH(o, &h, list) {
		const char *s;
		size_t l;

		assert_true(n < NDM_ARRAY_SIZE(arr));
		s = arr[n];
		l = strlen(s);

		assert_int_equal(l, o->value_len);
		assert_memory_equal(s, o->value, l);

		n++;
	}

	assert_int_equal(NDM_ARRAY_SIZE(arr), n);

	CoAPMessage_GetOptionsFree(&h);
	CoAPMessage_Free(m);
}

static void test_coap_message_get_option_uint(void **state)
{
	int ret;
	struct CoAPMessage *m;
	uint32_t arr[] = {0, 1, 255, 65535, 65536}, val;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m);

	for (unsigned i = 0; i < NDM_ARRAY_SIZE(arr); i++) {
		ret = CoAPMessage_AddOptionUint(m, i, arr[i]);
		assert_int_equal(0, ret);
	}

	for (unsigned i = 0; i < NDM_ARRAY_SIZE(arr); i++) {
		ret = CoAPMessage_GetOptionUint(m, i, &val);
		assert_int_equal(0, ret);
		assert_int_equal(arr[i], val);
	}

	ret = CoAPMessage_GetOptionUint(m, NDM_ARRAY_SIZE(arr), &val);
	assert_int_equal(-1, ret);
	assert_int_equal(ENOENT, errno);

	CoAPMessage_Free(m);
}

static void test_coap_message_get_option_opaque(void **state)
{
	int ret;
	size_t s;
	struct CoAPMessage *m;
	uint8_t *d;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m);

	ret = CoAPMessage_AddOptionOpaque(m, 0, NULL, 0);
	assert_int_equal(0, ret);

	ret = CoAPMessage_AddOptionOpaque(m, 1, (uint8_t *)"1", 1);
	assert_int_equal(0, ret);

	d = CoAPMessage_GetOptionOpaque(m, 0, &s);
	assert_null(d);
	assert_int_equal(ENODATA, errno);

	d = CoAPMessage_GetOptionOpaque(m, 1, &s);
	assert_non_null(d);
	assert_int_equal(1, s);
	assert_memory_equal("1", d, 1);

	CoAPMessage_Free(m);
}

static void test_coap_message_get_option_string(void **state)
{
	const char *arr[] = {"welcome", "to", "sun", "trope"};
	int ret;
	struct CoAPMessage *m;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m);

	for (unsigned i = 0; i < NDM_ARRAY_SIZE(arr); i++) {
		ret = CoAPMessage_AddOptionString(m, i, arr[i]);
		assert_int_equal(0, ret);
	}

	for (unsigned i = 0; i < NDM_ARRAY_SIZE(arr); i++) {
		char *s;
		size_t l;

		s = CoAPMessage_GetOptionString(m, i, &l);
		assert_non_null(s);
		assert_int_equal(strlen(arr[i]), l);
		assert_true(s[l] == '\0');
		assert_string_equal(arr[i], s);

		free(s);
	}

	CoAPMessage_Free(m);
}

static void test_coap_message_get_set_code(void **state)
{
	int ret;
	struct CoAPMessage *m;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m);

	ret = CoAPMessage_GetCode(m);
	assert_int_equal(CoAPMessage_CodeGet, ret);

	ret = CoAPMessage_SetCode(m, CoAPMessage_CodePost);
	assert_int_equal(0, ret);

	ret = CoAPMessage_GetCode(m);
	assert_int_equal(CoAPMessage_CodePost, ret);

	CoAPMessage_Free(m);
}

static void test_coap_message_get_set_id(void **state)
{
	int ret;
	struct CoAPMessage *m;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, 0, 0);
	assert_non_null(m);

	ret = CoAPMessage_GetId(m);
	assert_int_equal(0, ret);

	ret = CoAPMessage_SetId(m, 0xffff);
	assert_int_equal(0, ret);

	ret = CoAPMessage_GetId(m);
	assert_int_equal(0xffff, ret);

	CoAPMessage_Free(m);
}

static void test_coap_message_get_set_type(void **state)
{
	int ret;
	struct CoAPMessage *m;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m);

	ret = CoAPMessage_GetType(m);
	assert_int_equal(CoAPMessage_TypeCon, ret);

	ret = CoAPMessage_SetType(m, CoAPMessage_TypeNon);
	assert_int_equal(0, ret);

	ret = CoAPMessage_GetType(m);
	assert_int_equal(CoAPMessage_TypeNon, ret);

	CoAPMessage_Free(m);
}

static void test_coap_message_get_set_path(void **state)
{
	char *s;
	int ret;
	struct CoAPMessage *m;

	m = CoAPMessage(CoAPMessage_TypeNon, CoAPMessage_CodePost, -1, 0);
	assert_non_null(m);

	s = CoAPMessage_GetUriPath(NULL);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = CoAPMessage_GetUriPath(m);
	assert_null(s);
	assert_int_equal(ENOENT, errno);

	ret = CoAPMessage_SetUriPath(NULL, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUriPath(m, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUriPath(m, "");
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUriPath(m, "a/b");
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUriPath(m, "/");
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUriPath(m, "/first/second");
	assert_int_equal(0, ret);

	s = CoAPMessage_GetUriPath(m);
	assert_non_null(s);
	assert_string_equal("/first/second", s);
	free(s);

	ret = CoAPMessage_SetUriPath(m, "/first%20second");
	assert_int_equal(0, ret);

	s = CoAPMessage_GetUriPath(m);
	assert_non_null(s);
	assert_string_equal("/first+second", s);
	free(s);

	CoAPMessage_Free(m);
}

static void test_coap_message_get_set_query(void **state)
{
	char *s;
	int ret;
	struct CoAPMessage *m;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m);

	s = CoAPMessage_GetUriQuery(NULL);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	s = CoAPMessage_GetUriQuery(m);
	assert_null(s);
	assert_int_equal(ENOENT, errno);

	ret = CoAPMessage_SetUriQuery(NULL, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUriQuery(m, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUriQuery(m, "");
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUriQuery(m, "?");
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUriQuery(m, "?a=b&c=d&e");
	assert_int_equal(0, ret);

	s = CoAPMessage_GetUriQuery(m);
	assert_non_null(s);
	assert_string_equal("?a=b&c=d&e", s);
	free(s);

	ret = CoAPMessage_SetUriQuery(m, "?a=b&c=firm ware&e");
	assert_int_equal(0, ret);

	s = CoAPMessage_GetUriQuery(m);
	assert_non_null(s);
	assert_string_equal("?a=b&c=firm+ware&e", s);
	free(s);

	CoAPMessage_Free(m);
}

static void test_coap_message_get_set_uri(void **state)
{
	char *s;
	int ret;
	struct CoAPMessage *m;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m);

	s = CoAPMessage_GetUri(NULL);
	assert_null(s);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUri(NULL, NULL, 0);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUri(m, NULL, 0);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUri(m, "", 0);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetUri(m, "some_invalid_string", 0);
	assert_int_equal(-1, ret);
	assert_int_equal(EBADE, errno);

	ret = CoAPMessage_SetUri(m, "coap://coap.me/welcome", 0);
	assert_int_equal(0, ret);

	s = CoAPMessage_GetUri(m);
	assert_non_null(s);
	assert_string_equal("coap://coap.me/welcome", s);
	free(s);


	ret = CoAPMessage_SetUri(m, "coaps://1.2.3.4/a/b/c/d", 0);
	assert_int_equal(0, ret);

	s = CoAPMessage_GetUri(m);
	assert_non_null(s);
	assert_string_equal("coaps://1.2.3.4/a/b/c/d", s);
	free(s);

	/*
	ret = CoAPMessage_SetUri(m, "coap://[2001:db8:85a3:8d3:1319:8a2e:370:7348]", 0);
	assert_int_equal(0, ret);

	s = CoAPMessage_GetUri(m);
	assert_non_null(s);
	assert_string_equal("coap://[2001:db8:85a3:8d3:1319:8a2e:370:7348]", s);
	free(s);
	*/

	ret = CoAPMessage_SetUri(m, "coaps://coap.me/a/b b/c?fi=1&se=2 2&th", 0);
	assert_int_equal(0, ret);

	s = CoAPMessage_GetUri(m);
	assert_non_null(s);
	assert_string_equal("coaps://coap.me/a/b+b/c?fi=1&se=2+2&th", s);
	free(s);

	ret = CoAPMessage_SetUri(m, "coaps://%s:%d/info",
				 CoAPMessage_SetUriFlagFormat,
				 "1.2.3.4", 1234);
	assert_int_equal(0, ret);

	s = CoAPMessage_GetUri(m);
	assert_non_null(s);
	assert_string_equal("coaps://1.2.3.4:1234/info", s);
	free(s);

	CoAPMessage_Free(m);
}

static void test_coap_message_get_set_secure(void **state)
{
	bool on;
	int ret;
	struct CoAPMessage *m;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m);

	/* Invalid params */
	ret = CoAPMessage_GetSecure(NULL, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_GetSecure(m, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetSecure(NULL, false);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	/* Initial state  */
	ret = CoAPMessage_GetSecure(m, &on);
	assert_int_equal(0, ret);
	assert_int_equal(false, on);

	ret = CoAPMessage_IsSecure(m);
	assert_int_equal(false, ret);

	/* Turn off */
	ret = CoAPMessage_SetSecure(m, false);
	assert_int_equal(0, ret);

	ret = CoAPMessage_GetSecure(m, &on);
	assert_int_equal(0, ret);
	assert_int_equal(false, on);

	ret = CoAPMessage_IsSecure(m);
	assert_int_equal(false, ret);

	/* Turn on */
	ret = CoAPMessage_SetSecure(m, true);
	assert_int_equal(0, ret);

	ret = CoAPMessage_GetSecure(m, &on);
	assert_int_equal(0, ret);
	assert_int_equal(true, on);

	ret = CoAPMessage_IsSecure(m);
	assert_int_equal(true, ret);

	CoAPMessage_Free(m);
}

static void test_coap_message_get_set_proxy_security_id(void **state)
{
	int ret;
	struct CoAPMessage *m;
	uint32_t v = 0;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m);

	/* Invalid params */
	ret = CoAPMessage_GetProxySecurityId(NULL, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_GetProxySecurityId(m, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetProxySecurityId(NULL, 0);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	/* Initial state  */
	ret = CoAPMessage_GetProxySecurityId(m, &v);
	assert_int_equal(-1, ret);
	assert_int_equal(ENOENT, errno);

	/* Set 1 */
	ret = CoAPMessage_SetProxySecurityId(m, 0x12345678);
	assert_int_equal(0, ret);

	/* Get 1 */
	ret = CoAPMessage_GetProxySecurityId(m, &v);
	assert_int_equal(0, ret);
	assert_int_equal(0x12345678, v);

	/* Set 2 */
	ret = CoAPMessage_SetProxySecurityId(m, 0xa1a2a3a4);
	assert_int_equal(0, ret);

	/* Get 2 */
	ret = CoAPMessage_GetProxySecurityId(m, &v);
	assert_int_equal(0, ret);
	assert_int_equal(0xa1a2a3a4, v);

	CoAPMessage_Free(m);
}

static void test_coap_message_get_set_option_block(void **state)
{
	enum CoAPMessage_OptionCode code = CoAPMessage_OptionCodeBlock1;
	int ret;
	struct CoAPMessage *m;
	struct CoAPMessage_Block b1, b2;

	m = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m);

	/* Invalid params */
	ret = CoAPMessage_AddOptionBlock(NULL, code, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_AddOptionBlock(m, code, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_GetOptionBlock(NULL, code, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_GetOptionBlock(m, code, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	/* Initial state */
	ret = CoAPMessage_GetOptionBlock(m, code, &b1);
	assert_int_equal(-1, ret);
	assert_int_equal(ENOENT, errno);

	/* Setup */
	memset(&b1, 0, sizeof b1);
	ret = CoAPMessage_AddOptionBlock(m, code, &b1);
	assert_int_equal(0, ret);

	ret = CoAPMessage_GetOptionBlock(m, code, &b2);
	assert_int_equal(0, ret);
	assert_memory_equal(&b1, &b2, sizeof b1);

	b1.num = 100;
	b1.m = 1;
	b1.szx = CoAPMessage_BlockSize1024;
	ret = CoAPMessage_AddOptionBlock(m, code, &b1);
	assert_int_equal(0, ret);

	ret = CoAPMessage_GetOptionBlock(m, code, &b2);
	assert_int_equal(0, ret);
	assert_memory_equal(&b1, &b2, sizeof b1);

	CoAPMessage_Free(m);
}

static void test_coap_message_get_set_copy_sa(void **state)
{
	int ret;
	struct CoAPMessage *m1, *m2;
	struct sockaddr_in in;
	struct ndm_ip_sockaddr_t sa1 = NDM_IP_SOCKADDR_ANY, sa2 = {};

	m1 = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m1);

	m2 = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeGet, -1, 0);
	assert_non_null(m2);

	in.sin_family = AF_INET;
	in.sin_port = 1234;
	in.sin_addr.s_addr = htonl(INADDR_ANY);

	ndm_ip_sockaddr_assign(&sa1, &in);

	/* Invalid params */
	ret = CoAPMessage_GetSockAddr(NULL, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_GetSockAddr(m1, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetSockAddr(NULL, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetSockAddr(m1, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_SetSockAddr(m1, &sa2);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_CopySockAddr(NULL, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_CopySockAddr(m1, NULL);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_CopySockAddr(NULL, m1);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	/* Init */
	ret = CoAPMessage_GetSockAddr(m1, &sa2);
	assert_int_equal(-1, ret);
	assert_int_equal(ENODATA, errno);

	/* Setup */
	ret = CoAPMessage_SetSockAddr(m1, &sa1);
	assert_int_equal(0, ret);

	ret = CoAPMessage_GetSockAddr(m1, &sa2);
	assert_int_equal(0, ret);

	ret = ndm_ip_sockaddr_is_equal(&sa1, &sa2);
	assert_true(ret);

	/* Copy */
	ret = CoAPMessage_CopySockAddr(m2, m1);
	assert_int_equal(0, ret);

	memset(&sa1, 0, sizeof sa1);
	memset(&sa2, 0, sizeof sa2);

	ret = CoAPMessage_GetSockAddr(m1, &sa1);
	assert_int_equal(0, ret);

	ret = CoAPMessage_GetSockAddr(m2, &sa2);
	assert_int_equal(0, ret);

	ret = ndm_ip_sockaddr_is_equal(&sa1, &sa2);
	assert_true(ret);

	CoAPMessage_Free(m1);
	CoAPMessage_Free(m2);
}

static void test_coap_message_clone(void **state)
{
	const char *arr[] = {"first", "second", "third"};
	int ret;
	struct CoAPMessage *m, *cp;

	m = CoAPMessage(CoAPMessage_TypeNon, CoAPMessage_CodePost, -1, 0);
	assert_non_null(m);

	ret = CoAPMessage_SetUri(m, "coap://1.2.3.4/info", 0);
	assert_int_equal(0, ret);

	for (unsigned i = 0; i < NDM_ARRAY_SIZE(arr); i++) {
		ret = CoAPMessage_AddOptionString(m, 1, arr[i]);
		assert_int_equal(0, ret);
	}

	ret = CoAPMessage_SetPayload(m, (uint8_t *)"data", 4);
	assert_int_equal(0, ret);

	ret = CoAPMessage_SetToken(m, (uint8_t *)"1234", 4);
	assert_int_equal(0, ret);

	cp = CoAPMessage_Clone(NULL, 0);
	assert_null(cp);
	assert_int_equal(EINVAL, errno);

	/* With payload */
	cp = CoAPMessage_Clone(m, CoAPMessage_CloneFlagPayload);
	assert_non_null(cp);

	ret = CoAPMessage_Equals(m, cp, 0);
	assert_int_equal(1, ret);

	CoAPMessage_Free(cp);

	/* Without payload */
	cp = CoAPMessage_Clone(m, 0);
	assert_non_null(cp);

	ret = CoAPMessage_Equals(m, cp, 0);
	assert_int_equal(0, ret);

	ret = CoAPMessage_SetPayload(m, NULL, 0);
	assert_int_equal(0, ret);

	ret = CoAPMessage_Equals(m, cp, 0);
	assert_int_equal(1, ret);

	CoAPMessage_Free(cp);
	CoAPMessage_Free(m);
}

static void test_coap_message_codestr(void **state)
{
	char buf[50], *ret;

	/* Invalid params */
	ret = CoAPMessage_CodeStr(0, NULL, 0, 0);
	assert_null(ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_CodeStr(0, buf, 0, 0);
	assert_null(ret);
	assert_int_equal(EINVAL, errno);

	/* Format 1 */
	ret = CoAPMessage_CodeStr(CoAPMessage_CodeEmpty,
				  buf, sizeof buf,
				  CoAPMessage_CodeStr_Fmt1);
	assert_string_equal("0.00", ret);

	/* Format 2 */
	ret = CoAPMessage_CodeStr(CoAPMessage_CodeEmpty,
				  buf, sizeof buf,
				  CoAPMessage_CodeStr_Fmt2);
	assert_string_equal("Empty", ret);

	ret = CoAPMessage_CodeStr(COAP_MESSAGE_CODE(5),
				  buf, sizeof buf,
				  CoAPMessage_CodeStr_Fmt2);
	assert_string_equal("0.05", ret);

	ret = CoAPMessage_CodeStr(CoAPMessage_CodePost,
				  buf, sizeof 4,
				  CoAPMessage_CodeStr_Fmt2);
	assert_string_equal("Pos", ret);

	/* Format 3 */
	ret = CoAPMessage_CodeStr(CoAPMessage_CodeEmpty,
				  buf, sizeof buf,
				  CoAPMessage_CodeStr_Fmt3);
	assert_string_equal("0.00 (Empty)", ret);

	ret = CoAPMessage_CodeStr(COAP_MESSAGE_CODE(5),
				  buf, sizeof buf,
				  CoAPMessage_CodeStr_Fmt3);
	assert_string_equal("0.05", ret);

	ret = CoAPMessage_CodeStr(CoAPMessage_CodeEmpty,
                                  buf, 7,
                                  CoAPMessage_CodeStr_Fmt3);
	assert_string_equal("0.00 (", ret);
}

void test_coap_message_copy_option(void **state)
{
	int ret;
	struct CoAPMessage *m1, *m2;

	m1 = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeEmpty, -1, 0);
	assert_non_null(m1);

	m2 = CoAPMessage(CoAPMessage_TypeCon, CoAPMessage_CodeEmpty, -1, 0);
	assert_non_null(m2);

	/* Invalid params */
	ret = CoAPMessage_CopyOption(NULL, NULL, 0);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_CopyOption(m1, NULL, 0);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	ret = CoAPMessage_CopyOption(m2, NULL, 0);
	assert_int_equal(-1, ret);
	assert_int_equal(EINVAL, errno);

	/* Normal */
	ret = CoAPMessage_CopyOption(m1, m2, 0);
	assert_int_equal(-1, ret);
	assert_int_equal(ENOENT, errno);

	ret = CoAPMessage_AddOptionUint(m1, CoAPMessage_OptionCodeUriPort, 123);
	assert_int_equal(0, ret);

	ret = CoAPMessage_CopyOption(m2, m1, CoAPMessage_OptionCodeUriPort);
	assert_int_equal(0, ret);

	uint32_t v;
	ret = CoAPMessage_GetOptionUint(m2, CoAPMessage_OptionCodeUriPort, &v);
	assert_int_equal(0, ret);
	assert_int_equal(123, v);

	ret = CoAPMessage_AddOptionEmpty(m1, CoAPMessage_OptionCodeUriScheme);
	assert_int_equal(0, ret);

	ret = CoAPMessage_CopyOption(m2, m1, CoAPMessage_OptionCodeUriScheme);
	assert_int_equal(0, ret);

	uint8_t *d;
	d = CoAPMessage_GetOptionOpaque(m2, CoAPMessage_OptionCodeUriScheme,
					NULL);
	assert_null(d);
	assert_int_equal(ENODATA, errno);

	CoAPMessage_Free(m1);
	CoAPMessage_Free(m2);
}

int main(int argc, char *argv[])
{
	struct CMUnitTest tests[] = {
		cmocka_unit_test(test_id),
		cmocka_unit_test(test_payload),
		cmocka_unit_test(test_token),
		cmocka_unit_test(test_tobytes_frombytes),
		cmocka_unit_test(test_coap_message_option),
		cmocka_unit_test(test_coap_message_get_options),
		cmocka_unit_test(test_coap_message_get_option_uint),
		cmocka_unit_test(test_coap_message_get_option_opaque),
		cmocka_unit_test(test_coap_message_get_option_string),
		cmocka_unit_test(test_coap_message_get_set_code),
		cmocka_unit_test(test_coap_message_get_set_id),
		cmocka_unit_test(test_coap_message_get_set_type),
		cmocka_unit_test(test_coap_message_get_set_path),
		cmocka_unit_test(test_coap_message_get_set_query),
		cmocka_unit_test(test_coap_message_get_set_uri),
		cmocka_unit_test(test_coap_message_get_set_secure),
		cmocka_unit_test(test_coap_message_get_set_proxy_security_id),
		cmocka_unit_test(test_coap_message_get_set_option_block),
		cmocka_unit_test(test_coap_message_get_set_copy_sa),
		cmocka_unit_test(test_coap_message_clone),
		cmocka_unit_test(test_coap_message_codestr),
		cmocka_unit_test(test_coap_message_copy_option)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
