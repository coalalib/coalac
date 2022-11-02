#ifndef _MSGCACHE_H_
#define _MSGCACHE_H_

#include <stdint.h>	/* uint32_t */

#define MSGCACHE_KEY_SIZE \
	/* ip:port_id_token */ \
	sizeof("127.127.127.127:65535_65535_123456789abcdef0")

struct CoAPMessage;

struct MsgCache_Stats {
	uint32_t current;
	uint32_t match;
	uint32_t total;
	uint32_t over;
};

extern int MsgCache_Init(void);
extern void MsgCache_Deinit(void);

extern int MsgCache_Add(int fd, struct CoAPMessage *m);
extern struct CoAPMessage *MsgCache_Get(int fd, struct CoAPMessage *m);

extern void MsgCache_Cleaner(void);
extern int MsgCache_Stats(struct MsgCache_Stats *st);

#ifdef UNIT_TEST
extern int KeyGen(struct CoAPMessage *m, char buf[MSGCACHE_KEY_SIZE]);
#endif

#endif
