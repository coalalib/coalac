#ifndef _BUF_H_
#define _BUF_H_

#include <stdbool.h>
#include <stdio.h>	/* FILE */

struct Buf_Handle;

extern struct Buf_Handle *Buf(void);
extern void Buf_Free(struct Buf_Handle *h);
extern void Buf_Clear(struct Buf_Handle *h);

extern int Buf_Add(struct Buf_Handle *h, const void *data, size_t size);
extern int Buf_AddCh(struct Buf_Handle *h, char c);
extern int Buf_AddStr(struct Buf_Handle *h, const char *s);
extern int Buf_AddFormatStr(struct Buf_Handle *h, const char *fmt, ...);

extern void *Buf_GetData(struct Buf_Handle *h, size_t *size, bool alloc);

extern int Buf_Print(struct Buf_Handle *h, FILE *fp);
#endif
