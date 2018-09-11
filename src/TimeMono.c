#include <time.h>

#include "TimeMono.h"

uint32_t TimeMono_Sec(void)
{
	int ret;
	struct timespec tp;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
	if (ret < 0)
		return 0;

	return tp.tv_sec;
}

uint64_t TimeMono_Ms(void)
{
	int ret;
	struct timespec tp;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
	if (ret < 0)
		return 0;

	return tp.tv_sec * 1000ULL + tp.tv_nsec / 1000000;
}

uint64_t TimeMono_Us(void)
{
	int ret;
	struct timespec tp;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
	if (ret < 0)
		return 0;

	return tp.tv_sec * 1000000ULL + tp.tv_nsec / 1000;
}
