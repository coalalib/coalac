#ifndef _STR_H_
#define _STR_H_

#include <stdbool.h>	/* bool */
#include <stddef.h>	/* size_t */
#include <stdint.h>	/* uint8_t */

extern unsigned char Str_Char2Hex(char c);
extern char Str_Hex2Char(unsigned char i);
extern char *Str_strnchr(const char *s, size_t n, int c);
extern bool Str_ArrIsPrintable(uint8_t *s, size_t n);
extern char *Str_FromArr(uint8_t *arr, size_t arr_size,
			 char *buf, size_t buf_size);

extern char *Str_SizeFormat(size_t size, char *buf, size_t buf_size);
extern char *Str_SpeedFormat(double speed, char *buf, size_t buf_size);

extern void Str_Low(char *s);
extern void Str_Up(char *s);

#endif
