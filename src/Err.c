#define _GNU_SOURCE	/* GNU variant of strerror_r */

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "Err.h"

void Err_Init(struct Err *e, const char *src)
{
	if (e == NULL)
		return;

	e->code = -1;
	e->dsc[0] = '\0';
	e->src[0] = '\0';

	if (src) {
		strncpy(e->src, src, sizeof e->src - 1);
		e->src[sizeof e->src - 1] = '\0';
	}
}

void Err_Set(struct Err *e, int code, const char *fmt, ...)
{
	int errsv = errno;
	size_t l;
	va_list ap;

	if (e == NULL || fmt == NULL || *fmt == '\0')
		return;

	e->code = code;

	va_start(ap, fmt);
	vsnprintf(e->dsc, sizeof e->dsc, fmt, ap);
	va_end(ap);

	l = strlen(e->dsc);
	if (e->dsc[l - 1] == ':') {
		char buf[100];
		snprintf(e->dsc + l, sizeof e->dsc - l, " %s",
			 strerror_r(errsv, buf, sizeof buf));
	}
}
