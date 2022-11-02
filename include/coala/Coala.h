#ifndef _COALA_H_
#define _COALA_H_

#include <coala/CoAPMessage.h>

#include <stddef.h>
#include <stdint.h>

struct Coala_Priv;

#define COALA_KEY_SIZE		32
#define COALA_MCAST_ADDR	"224.0.0.187"
#define COALA_PORT		5683

#ifndef BIT
	#define BIT(x)  (1ul << (x))
#endif

struct Coala;

struct Coala_Stats {
	/* MsgCache */
	uint32_t msgcache_current;
	uint32_t msgcache_match;
	uint32_t msgcache_total;
	uint32_t msgcache_over;
	/* SecLayer */
	uint32_t seclayer_current;
	uint32_t seclayer_total;
	/* SlidingWindowPool */
	uint32_t swp_current;
	uint32_t swp_total;
	uint32_t swp_orphan;
};

/* Creation & destroying */
#define Coala_FlagWellKnownResource	BIT(0)
extern struct Coala *Coala(const uint8_t *key, size_t key_size, unsigned flags);
extern void Coala_Free(struct Coala *c);

/* Sending & receiving */
extern int Coala_Send(struct Coala *c, int fd, struct CoAPMessage *msg);
extern int Coala_SendLow(struct Coala *c, int fd, struct CoAPMessage *msg);
extern int Coala_Recv(struct Coala *c, int fd);

extern void Coala_Tick(struct Coala *c);
extern int Coala_Stats(struct Coala *c, struct Coala_Stats *st);

/* Resource handlers */
typedef int (*res_handler_t)(struct Coala *c,
			     int fd,
			     struct CoAPMessage *req,
			     struct CoAPMessage *rsp,
			     void *arg);

extern int Coala_AddRes(struct Coala *c, const char *path,
			unsigned mask, res_handler_t h, void *arg);
extern int Coala_RemRes(struct Coala *c, const char *path);
extern int Coala_GetRes(struct Coala *c, const char *path,
			enum CoAPMessage_Code code, res_handler_t *h,
			void **arg);

#endif
