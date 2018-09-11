#ifndef _HEXSTRING_H_
#define _HEXSTRING_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct HexString;

extern struct HexString *HexString(void);
extern void HexString_Free(struct HexString *hs);

extern int HexString_Set(struct HexString *hs, const char *s);
extern char *HexString_Get(struct HexString *hs);

extern int HexString_SetBin(struct HexString *hs, const uint8_t *b, size_t s);
extern uint8_t *HexString_GetBin(struct HexString *hs, size_t *s);

#endif
