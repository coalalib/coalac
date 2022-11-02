#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <coala/Buf.h>
#include <coala/Coala.h>
#include <ndm/log.h>
#include <ndm/int.h>

#define POLL_TIMEOUT	333

static void help_print(FILE *fp, const char *pname)
{
	fprintf(fp,
		"Usage: %s [-c cookie] [-f file] [-h] [-i id] [-m method] [-N] [-p port] "
		"[-T string] [-v num ] URI\n",
		pname);
}

static void cb(struct Coala *c, int fd, enum CoAPMessage_CbErr err,
	       struct CoAPMessage *m, void *arg)
{
	if (err)
		printf("error: %d\n", err);
	else
		CoAPMessage_Print(m, stdout);
}

static int sock_init(uint16_t port)
{
	int fd;
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons(port)
	};

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		int errsv = errno;
		close(fd);
		errno = errsv;
		return -1;
	}

	return fd;
}

int main(int argc, char *argv[])
{
	bool id_set = false, tok_set = false;
	char *cookie = NULL, *fname_in = NULL, *pname;
	const char *uri;
	enum CoAPMessage_Code code = CoAPMessage_CodeGet;
	enum CoAPMessage_Type type = CoAPMessage_TypeCon;
	int res = EXIT_FAILURE;
	struct Coala *c;
	int fd, o;
	size_t l = 0;
	struct CoAPMessage *m = NULL;
	uint8_t tok[COAP_MESSAGE_MAX_TOKEN_SIZE], verbose = LDEBUG_2;
	uint16_t id, port = 0;

	pname = basename(argv[0]);
	srandom(time(NULL));

	while ((o = getopt(argc, argv, "c:f:hi:m:Np:T:v:")) != -1) {
		switch (o) {
		case 'c':
			cookie = optarg;
			break;

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

	if ((fd = sock_init(port)) < 0)
		return EXIT_FAILURE;

	if ((c = Coala(NULL, 0, Coala_FlagWellKnownResource)) == NULL)
		return EXIT_FAILURE;

	if ((m = CoAPMessage(type, code, id_set ? id : -1, 0)) == NULL ||
	    CoAPMessage_SetUri(m, uri, 0) < 0) {
		CoAPMessage_Free(m);
		Coala_Free(c);
		return EXIT_FAILURE;
	}

	if (cookie &&
	    CoAPMessage_AddOptionString(m, CoAPMessage_OptionCodeCookie,
					cookie) < 0) {
		CoAPMessage_Free(m);
		Coala_Free(c);
		return EXIT_FAILURE;
	}

	if (pay && CoAPMessage_SetPayload(m, pay, pay_size) < 0) {
		free(pay);
		CoAPMessage_Free(m);
		Coala_Free(c);
		return EXIT_FAILURE;
	}

	free(pay);

	if (tok_set)
		CoAPMessage_SetToken(m, tok, l);

	CoAPMessage_SetCb(m, cb, NULL);
	Coala_Send(c, fd, m);
	CoAPMessage_Free(m);

	struct pollfd pfds[] = {
		{
			.fd = STDIN_FILENO,
			.events = POLLIN
		}, {
			.fd = fd,
			.events = POLLIN
		}
	};

	while (1) {
		int ret = poll(pfds, NDM_ARRAY_SIZE(pfds), POLL_TIMEOUT);

		if (ret < 0)
			goto out;

		if (!ret) {
			Coala_Tick(c);
			continue;
		}

		if (pfds[0].revents & POLLIN)
			break;

		if (pfds[1].revents & POLLIN)
			Coala_Recv(c, fd);
	}

	res = EXIT_SUCCESS;
out:
	Coala_Free(c);
	return res;
}
