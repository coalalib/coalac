#ifndef _COALA_H_
#define _COALA_H_


#define COALA_PORT_DEFAULT 5683

#include <coala/CoAPMessage.h>

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

struct CoAPMessagePool;
struct Coala_Priv;
struct sockaddr_in;

#define COALA_ADDR_STRSIZE	INET_ADDRSTRLEN
#define COALA_PORT_STRSIZE 	6

#define COALA_ADDR_STRLEN	(COALA_ADDR_STRSIZE - 1) /* exclude zero */
#define COALA_PORT_STRLEN	(COALA_PORT_STRSIZE - 1)

#define COALA_MCAST_ADDR	"224.0.0.187"

struct Coala {
	struct CoAPMessagePool *mes_pool;	/* TODO: Move to private */
	struct SlidingWindowPool *sw_pool;
	struct Coala_Priv *priv;
	uint8_t private_key[32];
	uint8_t public_key[32];
};

/* Creation & destroying */
extern struct Coala *Coala(int port, in_addr_t addr);
extern void Coala_Free(struct Coala *c);

extern int Coala_SetPrivateKey(struct Coala *c, const uint8_t *k, size_t s);

/* Sending */
extern int Coala_Send(struct Coala *c, struct CoAPMessage *msg);

/* Resource handlers */
typedef int (*res_handler_t)(struct Coala *c,
			     struct CoAPMessage *request,
			     struct CoAPMessage *response);

extern int Coala_AddRes(struct Coala *c, const char *path,
			unsigned mask, res_handler_t h);
extern int Coala_RemRes(struct Coala *c, const char *path);
extern int Coala_GetRes(struct Coala *c, const char *path,
			enum CoAPMessage_Code code, res_handler_t *h);

#endif
