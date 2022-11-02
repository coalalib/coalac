#ifndef _MSGQUEUE_H_
#define _MSGQUEUE_H_

struct CoAPMessage;

extern int MsgQueue_Add(int fd, struct CoAPMessage *m);
extern struct CoAPMessage *MsgQueue_Get(struct CoAPMessage *m);
extern int MsgQueue_Remove(struct CoAPMessage *m);
extern int MsgQueue_RemoveAll(struct CoAPMessage *m);

extern void MsgQueue_Free(void);
extern void MsgQueue_Tick(struct Coala *c);

#endif
