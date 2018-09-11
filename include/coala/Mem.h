#ifndef _MEM_H_
#define _MEM_H_

#include <stddef.h> /* size_t */

extern void *Mem_calloc(size_t n, size_t size);
extern void *Mem_malloc(size_t size);
extern void *Mem_realloc(void *p, size_t size);
extern void Mem_free(void *p);

extern char *Mem_strdup(const char *s);
extern char *Mem_strndup(const char *s, size_t n);

typedef void *(*Mem_CallocFunc)(size_t n, size_t size);
typedef void *(*Mem_MallocFunc)(size_t size);
typedef void *(*Mem_ReallocFunc)(void *p, size_t size);
typedef void (*Mem_FreeFunc)(void *p);

typedef char *(*Mem_StrdupFunc)(const char *s);
typedef char *(*Mem_StrndupFunc)(const char *s, size_t n);

extern void Mem_Setup(Mem_CallocFunc calloc_fn, Mem_MallocFunc malloc_fn,
		      Mem_ReallocFunc realloc_fn, Mem_FreeFunc free_fn,
		      Mem_StrdupFunc strdup_fn, Mem_StrndupFunc strndup_fn);

#endif
