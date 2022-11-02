#include <arpa/inet.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <coala/Coala.h>
#include <ndm/log.h>

#define CID		"eb8db192-4ff8-fe"
#define NAME		"Coala-C"
#define TYPE		"router"

#define POLL_TIMEOUT	333

static int info_handler(struct Coala *c, int fd, struct CoAPMessage *req,
			struct CoAPMessage *res, void *arg)
{
	char buf[60];

	CoAPMessage_SetCode(res, CoAPMessage_CodeContent);
	CoAPMessage_AddOptionUint(res, CoAPMessage_OptionCodeContentFormat,
				  CoAPMessage_ContentFormatTextPlain);

	snprintf(buf, sizeof buf,
		 "{\"cid\":\"%s\",\"type\":\"%s\",\"name\":\"%s\"}",
		 CID, TYPE, NAME);

	CoAPMessage_SetPayloadString(res, buf);

	return 0;
}

static int compas_handler(struct Coala *c, int fd, struct CoAPMessage *req,
			  struct CoAPMessage *res, void *arg)
{
	char buf[40];
	static unsigned short counter;

	CoAPMessage_SetCode(res, CoAPMessage_CodeContent);
	CoAPMessage_AddOptionUint(res, CoAPMessage_OptionCodeContentFormat,
				  CoAPMessage_ContentFormatTextPlain);

	snprintf(buf, sizeof buf, "{\"cid\":\"%s\", \"value\":%hu}", CID,
		 counter);
	CoAPMessage_SetPayloadString(res, buf);

	if (++counter == 360)
		counter = 0;

	return 0;
}

static int time_handler(struct Coala *c, int fd, struct CoAPMessage *req,
			struct CoAPMessage *res, void *arg)
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
	CoAPMessage_SetPayloadString(res, buf);

	return 0;
}

static int random_handler(struct Coala *c, int fd, struct CoAPMessage *req,
			  struct CoAPMessage *res, void *arg)
{
	char buf[20];

	CoAPMessage_SetCode(res, CoAPMessage_CodeContent);
	CoAPMessage_AddOptionUint(res, CoAPMessage_OptionCodeContentFormat,
				  CoAPMessage_ContentFormatTextPlain);

	snprintf(buf, sizeof buf, "%ld", random());
	CoAPMessage_SetPayloadString(res, buf);

	return 0;
}

static int long_handler(struct Coala *c, int fd, struct CoAPMessage *req,
			struct CoAPMessage *res, void *arg)
{
	char buf[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
		     "Nam sit amet faucibus massa. Nulla facilisi. Nunc "
		     "condimentum tincidunt urna, eget dignissim felis "
		     "condimentum eu. Praesent ut hendrerit neque. Nam non "
		     "neque id lorem tincidunt pellentesque sit amet vel erat. "
		     "Nulla facilisi. Donec mattis malesuada risus, eget "
		     "ultricies sapien molestie vel. Maecenas quis tincidunt "
		     "nisl. Morbi et laoreet erat. Duis rutrum lacus et metus "
		     "scelerisque condimentum. Donec eget quam vulputate "
		     "mauris facilisis vulputate. Cras aliquam, nulla id "
		     "rutrum vestibulum, velit ipsum porttitor lacus, ac "
		     "condimentum justo massa at lorem. Aliquam eu libero sit "
		     "amet nibh iaculis varius quis ac mauris."
		     "Praesent volutpat viverra vulputate. Mauris placerat "
		     "justo gravida, euismod nibh fermentum, consequat purus. "
		     "Phasellus est metus, fermentum faucibus tristique sed, "
		     "semper ut leo. Etiam non odio et nisl sodales porta. "
		     "Maecenas tincidunt venenatis quam. Curabitur malesuada "
		     "libero tempus lectus ultrices efficitur. Nunc sit amet "
		     "ullamcorper ipsum, quis rhoncus ante. Donec euismod "
		     "convallis fermentum. Integer vel sapien est. Proin eget "
		     "efficitur erat. Pellentesque sed metus vitae eros "
		     "ultricies blandit eu ornare augue. Curabitur hendrerit "
		     "euismod elit sed.";

	CoAPMessage_SetCode(res, CoAPMessage_CodeContent);
	CoAPMessage_AddOptionUint(res, CoAPMessage_OptionCodeContentFormat,
				  CoAPMessage_ContentFormatTextPlain);
	CoAPMessage_SetPayloadString(res, buf);

	return 0;
}

static int post_handler(struct Coala *c, int fd, struct CoAPMessage *req,
			struct CoAPMessage *res, void *arg)
{
	char buf[] = "test";

	CoAPMessage_SetCode(res, CoAPMessage_CodeChanged);
	CoAPMessage_AddOptionUint(res, CoAPMessage_OptionCodeContentFormat,
				  CoAPMessage_ContentFormatTextPlain);
	CoAPMessage_SetPayloadString(res, buf);

	return 0;
}

static int mirror_handler(struct Coala *c, int fd, struct CoAPMessage *req,
			  struct CoAPMessage *rsp, void *arg)
{
	const int cf_opt = CoAPMessage_OptionCodeContentFormat;
	size_t l;
	uint32_t v;
	unsigned char *d;

	CoAPMessage_SetCode(rsp, CoAPMessage_CodeContent);

	if (!CoAPMessage_GetOptionUint(req, cf_opt, &v))
		CoAPMessage_AddOptionUint(rsp, cf_opt, v);

	if ((d = CoAPMessage_GetPayload(req, &l, 0)))
		CoAPMessage_SetPayload(rsp, d, l);

	return 0;
}

static void help_print(FILE *fp, const char *pname)
{
	fprintf(fp, "Usage: %s [-v num]\n", pname);
}

static int sock_init(void)
{
	int fd, on = 1;
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons(COALA_PORT)
	};

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) < 0 ||
	    bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		int errsv = errno;
		close(fd);
		errno = errsv;
		return -1;
	}

	return fd;
}

int main(int argc, char *argv[])
{
	char *pname;
	int fd, o, res = EXIT_FAILURE;
	struct Coala *c = NULL;
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

	if ((fd = sock_init()) < 0)
		goto out;

	if ((c = Coala(NULL, 0, Coala_FlagWellKnownResource)) == NULL) {
		fprintf(stderr, "c is NULL\n");
		goto out;
	}

	Coala_AddRes(c, "/compas", BIT(CoAPMessage_CodeGet), compas_handler, NULL);
	Coala_AddRes(c, "/info", BIT(CoAPMessage_CodeGet), info_handler, NULL);
	Coala_AddRes(c, "/long", BIT(CoAPMessage_CodeGet), long_handler, NULL);
	Coala_AddRes(c, "/mirror", BIT(CoAPMessage_CodePost), mirror_handler, NULL);
	Coala_AddRes(c, "/random", BIT(CoAPMessage_CodeGet), random_handler, NULL);
	Coala_AddRes(c, "/time", BIT(CoAPMessage_CodeGet), time_handler, NULL);
	Coala_AddRes(c, "/post", BIT(CoAPMessage_CodePost), post_handler, NULL);

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
