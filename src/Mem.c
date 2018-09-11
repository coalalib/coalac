#include <stdlib.h>
#include <string.h>

#include <coala/Mem.h>

static Mem_CallocFunc do_calloc = calloc;
static Mem_MallocFunc do_malloc = malloc;
static Mem_ReallocFunc do_realloc = realloc;
static Mem_FreeFunc do_free = free;

static Mem_StrdupFunc do_strdup = strdup;
static Mem_StrndupFunc do_strndup = strndup;

void *Mem_malloc(size_t size)
{
	return (*do_malloc)(size);
}

void *Mem_calloc(size_t n, size_t size)
{
	return (*do_calloc)(n, size);
}

void *Mem_realloc(void *p, size_t size)
{
	return (*do_realloc)(p, size);
}

void Mem_free(void *p)
{
	return (*do_free)(p);
}

char *Mem_strdup(const char *s)
{
	return (*do_strdup)(s);
}

char *Mem_strndup(const char *s, size_t n)
{
	return (*do_strndup)(s, n);
}

void Mem_Setup(Mem_CallocFunc calloc_fn, Mem_MallocFunc malloc_fn,
	       Mem_ReallocFunc realloc_fn, Mem_FreeFunc free_fn,
	       Mem_StrdupFunc strdup_fn, Mem_StrndupFunc strndup_fn)
{
	do_calloc = calloc_fn;
	do_malloc = malloc_fn;
	do_realloc = realloc_fn;
	do_free = free_fn;
	do_strdup = strdup_fn;
	do_strndup = strndup_fn;
}
