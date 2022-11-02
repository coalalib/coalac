#include "Log_utils.h"

int ByteCountBinaryBits(size_t b, char* rez) {
	b *= 8;
	const size_t unit = 1024;
	if (b < unit) {
	    sprintf(rez,"%ld B", b);
        return 0;
	}
    size_t div = unit;
    size_t exp = 0;
	for (size_t n = b / unit; n >= unit; n /= unit) {
		div *= unit;
		++exp;
	}
	sprintf(rez,"%.1f %cBits", ((double)b / (double)div),"KMGTPE"[exp]);
    return 0;
}

int ByteCountBinary(size_t b, char* rez){
	const size_t unit = 1024;
	if (b < unit) {
	    sprintf(rez,"%ld B", b);
        return 0;
	}
    size_t div = unit;
    size_t exp = 0;
	for (size_t n = b / unit; n >= unit; n /= unit) {
		div *= unit;
		++exp;
	}
	sprintf(rez,"%.1f %ciB", ((double)b / (double)div),"KMGTPE"[exp]);
    return 0;
}
