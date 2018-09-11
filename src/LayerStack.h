#ifndef _LAYERS_STACK_H_
#define _LAYERS_STACK_H_

struct sockaddr_in;
struct Coala;
struct CoAPMessage;
struct Err;

enum LayerStack_Ret {
	LayerStack_Con,
	LayerStack_Stop,
	LayerStack_Err
};

extern enum LayerStack_Ret
LayerStack_OnReceive(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err);

extern enum LayerStack_Ret
LayerStack_OnSend(
		struct Coala *c,
		struct CoAPMessage *msg,
		unsigned flags,
		struct Err *err);

extern int LayerStack_Init(struct Coala *c, struct Err *err);
extern void LayerStack_Deinit(struct Coala *c);

#endif
