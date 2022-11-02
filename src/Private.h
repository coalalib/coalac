#ifndef _PRIVATE_H_
#define _PRIVATE_H_

#include <openssl/evp.h>

#include <coala/queue.h>
#include <coala/Coala.h>

struct ResEntry;
struct SlidingWindowPool;

SLIST_HEAD(ResHead, ResEntry);

struct Coala {
	struct SlidingWindowPool *sw_pool;
	EVP_PKEY *key;
	struct ResHead resources_head;
};

#endif
