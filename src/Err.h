#ifndef _ERR_H_
#define _ERR_H_

struct Err {
	int code;
	char src[50];
	char dsc[100];
};

extern void Err_Init(struct Err *e, const char *src);
extern void Err_Set(struct Err *e, int code, const char *fmt, ...);

#endif
