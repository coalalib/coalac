#include <ndm/log.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <coala/Coala.h>

#define CID	"eb8db192-4ff8-fe"
#define TYPE	"router"
#define NAME	"Coala-C"

static int info_handler(struct Coala *c, struct CoAPMessage *req,
			struct CoAPMessage *res)
{
	char buf[60];

	CoAPMessage_SetCode(res, CoAPMessage_CodeContent);
	CoAPMessage_AddOptionUint(res, CoAPMessage_OptionCodeContentFormat,
				  CoAPMessage_ContentFormatTextPlain);

	snprintf(buf, sizeof buf,
		 "{\"cid\":\"%s\",\"type\":\"%s\",\"name\":\"%s\"}",
		 CID, TYPE, NAME);

	CoAPMessage_SetPayload(res, (uint8_t *)buf, strlen(buf));

	return 0;
}

static int compas_handler(struct Coala *c, struct CoAPMessage *req,
			  struct CoAPMessage *res)
{
	char buf[40];
	static unsigned short counter;

	CoAPMessage_SetCode(res, CoAPMessage_CodeContent);
	CoAPMessage_AddOptionUint(res, CoAPMessage_OptionCodeContentFormat,
				  CoAPMessage_ContentFormatTextPlain);

	snprintf(buf, sizeof buf, "{\"cid\":\"%s\", \"value\":%hu}", CID,
		 counter);
	CoAPMessage_SetPayload(res, (uint8_t *)buf, strlen(buf));

	if (++counter == 360)
		counter = 0;

	return 0;
}

static int time_handler(struct Coala *c, struct CoAPMessage *req,
			struct CoAPMessage *res)
{
	char buf[50], t_buf[sizeof "12:34:56 0"];
	time_t t;
	struct tm tm;

	CoAPMessage_SetCode(res, CoAPMessage_CodeContent);
	CoAPMessage_AddOptionUint(res, CoAPMessage_OptionCodeContentFormat,
				  CoAPMessage_ContentFormatTextPlain);

	if (time(&t) == (time_t)-1 ||
	    localtime_r(&t, &tm) == NULL ||
	    !strftime(t_buf, sizeof t_buf, "%H:%M:%S 0", &tm)) {
		/* TODO: Send error */
		return -1;
	}

	snprintf(buf, sizeof buf, "{\"cid\":\"%s\", \"time\":\"%s\"}",
		 CID, t_buf);
	CoAPMessage_SetPayload(res, (uint8_t *)buf, strlen(buf));

	return 0;
}

static int random_handler(struct Coala *c, struct CoAPMessage *req,
			  struct CoAPMessage *res)
{
	char buf[20];

	CoAPMessage_SetCode(res, CoAPMessage_CodeContent);
	CoAPMessage_AddOptionUint(res, CoAPMessage_OptionCodeContentFormat,
				  CoAPMessage_ContentFormatTextPlain);

	snprintf(buf, sizeof buf, "%ld", random());
	CoAPMessage_SetPayload(res, (uint8_t *)buf, strlen(buf));

	return 0;
}

static int long_handler(struct Coala *c, struct CoAPMessage *req,
			struct CoAPMessage *res)
{
	char buf[] = "Lorem Ipsum is simply dummy text of the printing and "
		     "typesetting industry. Lorem Ipsum has been the "
		     "industry's standard dummy text ever since the 1500s, "
		     "when an unknown printer took a galley of type and "
		     "scrambled it to make a type specimen book. It has "
		     "survived not only five centuries, but also the leap "
		     "into electronic typesetting, remaining essentially "
		     "unchanged. It was popularised in the 1960s with the "
		     "release of Letraset sheets containing Lorem Ipsum "
		     "passages, and more recently with desktop publishing "
		     "software like Aldus PageMaker including versions of "
		     "Lorem Ipsum.";

	CoAPMessage_SetCode(res, CoAPMessage_CodeContent);
	CoAPMessage_AddOptionUint(res, CoAPMessage_OptionCodeContentFormat,
				  CoAPMessage_ContentFormatTextPlain);
	CoAPMessage_SetPayload(res, (uint8_t *)buf, strlen(buf));

	return 0;
}

static int post_handler(struct Coala *c, struct CoAPMessage *req,
			struct CoAPMessage *res)
{
	char buf[] = "test";

	CoAPMessage_SetCode(res, CoAPMessage_CodeChanged);
	CoAPMessage_AddOptionUint(res, CoAPMessage_OptionCodeContentFormat,
				  CoAPMessage_ContentFormatTextPlain);
	CoAPMessage_SetPayload(res, (uint8_t *)buf, strlen(buf));

	return 0;
}

static void help_print(FILE *fp, const char *pname)
{
	fprintf(fp, "Usage: %s [-v num]\n", pname);
}

int main(int argc, char *argv[])
{
	char *pname;
	int o, res = EXIT_FAILURE;
	struct Coala *c;
	uint8_t verbose = LDEBUG_2;

	pname = basename(argv[0]);
	srandom(time(NULL));

	while ((o = getopt(argc, argv, "hv:")) != -1) {
		switch (o) {
		case 'h':
			help_print(stderr, pname);
			return EXIT_SUCCESS;
		case 'v':
			if (!ndm_int_parse_uchar(optarg, &verbose) ||
			    verbose > 3) {
				fprintf(stderr, "Verbosity level must be in range [0:3]\n");
				return EXIT_FAILURE;
			}
			break;
		default:
			help_print(stderr, pname);
			return EXIT_FAILURE;
		}

	}

	if (!ndm_log_init(pname, NULL, true, false))
		goto out;

	ndm_log_set_debug(verbose);

	c = Coala(COALA_PORT_DEFAULT, htonl(INADDR_ANY));
	if (c == NULL) {
		fprintf(stderr, "c is NULL\n");
		goto out;
	}

	uint8_t key[] = {0x1e, 0xde, 0x42, 0xf0, 0x22, 0x52, 0xf3, 0x66,
                         0x9a, 0x52, 0x12, 0xdb, 0xea, 0xb9, 0xca, 0xaf,
                         0x01, 0xaa, 0x90, 0x5a, 0x61, 0xf2, 0xf0, 0x4a,
                         0x91, 0x6f, 0x03, 0x93, 0x4b, 0xa8, 0xeb, 0x0d};
        Coala_SetPrivateKey(c, key, sizeof key);

	Coala_AddRes(c, "/compas", BIT(CoAPMessage_CodeGet), compas_handler);
	Coala_AddRes(c, "/info", BIT(CoAPMessage_CodeGet), info_handler);
	Coala_AddRes(c, "/time", BIT(CoAPMessage_CodeGet), time_handler);
	Coala_AddRes(c, "/random", BIT(CoAPMessage_CodeGet), random_handler);
	Coala_AddRes(c, "/long", BIT(CoAPMessage_CodeGet), long_handler);
	Coala_AddRes(c, "/post", BIT(CoAPMessage_CodePost), post_handler);

	getchar();

	Coala_Free(c);
	res = EXIT_SUCCESS;
out:
	return res;
}
