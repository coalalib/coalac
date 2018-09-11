#include <coala/Buf.h>
#include <coala/Coala.h>
#include <ndm/log.h>
#include <ndm/int.h>
#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void help_print(FILE *fp, const char *pname)
{
	fprintf(fp,
		"Usage: %s [-f file] [-h] [-i id] [-m method] [-N] [-p port] "
		"[-T string] [-v num ] URI\n",
		pname);
}

static int handler(struct Coala *c, struct CoAPMessage *m)
{
	CoAPMessage_Print(m, stdout);

	return 0;
}

int main(int argc, char *argv[])
{
	bool id_set = false, tok_set = false;
	char *fname_in = NULL, *pname;
	const char *uri;
	enum CoAPMessage_Code code = CoAPMessage_CodeGet;
	enum CoAPMessage_Type type = CoAPMessage_TypeCon;
	struct Coala *c;
	int o;
	size_t l;
	struct CoAPMessage *m;
	uint8_t tok[COAP_MESSAGE_MAX_TOKEN_SIZE], verbose = LDEBUG_2;
	uint16_t id, port = 0;

	pname = basename(argv[0]);
	srandom(time(NULL));

	while ((o = getopt(argc, argv, "f:hi:m:Np:T:v:")) != -1) {
		switch (o) {
		case 'h':
			help_print(stdout, pname);
			return EXIT_SUCCESS;

		case 'f':
			fname_in = optarg;
			break;

		case 'i':
			if (!ndm_int_parse_ushort(optarg, &id)) {
				fprintf(stderr, "Invalid id.\n");
				return EXIT_FAILURE;
			}

			id_set = true;
			break;

		case 'm':
			if (!strcasecmp(optarg, "get")) {
				;
			} else if (!strcasecmp(optarg, "post")) {
				code = CoAPMessage_CodePost;
			} else if (!strcasecmp(optarg, "put")) {
				code = CoAPMessage_CodePut;
			} else if (!strcasecmp(optarg, "delete")) {
				code = CoAPMessage_CodeDelete;
			} else {
				fprintf(stderr, "Invalid method.\n");
				return EXIT_FAILURE;
			}
			break;

		case 'N':
			type = CoAPMessage_TypeNon;
			break;

		case 'p':
			if (!ndm_int_parse_ushort(optarg, &port)) {
				fprintf(stderr, "Invalid port.\n");
				return EXIT_FAILURE;
			}
			break;

		case 'T':
			l = strlen(optarg);

			if (l > sizeof tok) {
				fprintf(stderr, "Too long token.\n");
				return EXIT_FAILURE;
			}

			memcpy(tok, optarg, l);
			tok_set = true;
			break;

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

	if (argc - optind != 1) {
		help_print(stderr, pname);
		return EXIT_FAILURE;
	}

	uri = argv[optind];

	uint8_t *pay = NULL;
	size_t pay_size = 0;
	if (fname_in) {
		int c;
		FILE *fp;
		struct Buf_Handle *b = Buf();

		if (!strcmp(fname_in, "-")) {
			fp = stdin;
		} else if ((fp = fopen(fname_in, "r")) == NULL) {
			fprintf(stderr, "Can't open file \"%s\": %s.\n",
				fname_in, strerror(errno));
			return EXIT_FAILURE;
		}

		while ((c = fgetc(fp)) != EOF)
			Buf_AddCh(b, c);

		pay = Buf_GetData(b, &pay_size, true);

		Buf_Free(b);
		fclose(fp);
	}

	if (!ndm_log_init(pname, NULL, true, false))
		return EXIT_FAILURE;

	ndm_log_set_debug(verbose);

	if ((c = Coala(1234, htonl(INADDR_ANY))) == NULL) {
		return EXIT_FAILURE;
	} else if ((m = CoAPMessage(type, code, id_set ? id : -1)) == NULL ||
		   CoAPMessage_SetUri(m, uri, 0) < 0) {
		Coala_Free(c);
		return EXIT_FAILURE;
	} else if (pay && CoAPMessage_SetPayload(m, pay, pay_size) < 0) {
		free(pay);
		Coala_Free(c);
		return EXIT_FAILURE;
	}

	uint8_t key[] = {0x6e, 0xde, 0x42, 0xf0, 0x22, 0x52, 0xf3, 0x66,
			 0x9a, 0x52, 0x12, 0xdb, 0xea, 0xb9, 0xca, 0xaf,
			 0x01, 0xaa, 0x90, 0x5a, 0x61, 0xf2, 0xf0, 0x4a,
			 0x91, 0x6f, 0x03, 0x93, 0x4b, 0xa8, 0xeb, 0x0d};
	Coala_SetPrivateKey(c, key, sizeof key);

	free(pay);

	if (tok_set)
		CoAPMessage_SetToken(m, tok, l);

	CoAPMessage_SetHandler(m, handler);

	Coala_Send(c, m);

	getchar();

	CoAPMessage_Decref(m);
	Coala_Free(c);

	return EXIT_SUCCESS;
}
