#include <ndm/macro.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <coala/Str.h>

enum Unit {
	Unit_B,
	Unit_KiB,
	Unit_MiB,
	Unit_GiB,
	Unit_TiB
};

unsigned char Str_Char2Hex(char c)
{
        if (isdigit(c))
                return c - '0';

        return tolower(c) - 'a' + 0xa;
}

char Str_Hex2Char(unsigned char i)
{
        if (i < 0xa)
                return i + '0';

        return i - 0xa + 'a';
}

char *Str_strnchr(const char *s, size_t n, int c)
{
        while (*s && n--) {
                if (*s == c)
                        return (char *)s;
                s++;
        }

        return NULL;
}

char *Str_FromArr(uint8_t *arr, size_t arr_size,
		  char *buf, size_t buf_size)
{
	char *s;

	if (arr == NULL || !arr_size ||
	    buf == NULL || !buf_size) {
		errno = EINVAL;
		return NULL;
	}

	if ((arr_size << 1) + 1 > buf_size) {
		errno = ENOSPC;
		return NULL;
	}

	s = buf;
	for (size_t i = 0; i < arr_size; i++) {
		sprintf(s, "%02x", arr[i]);
		s += 2;
	}

	return buf;
}

bool Str_ArrIsPrintable(uint8_t *s, size_t n)
{
	if (s == NULL || !n)
		return false;

	/*
	 * TODO: Option to check trailing zero.
	 */
	for (size_t i = 0; i < n; i++) {
		if (isprint(s[i]))
			continue;

		return false;
	}

	return true;
}

static double Str_SizeSimp(double size, enum Unit *unit)
{
	size_t i;
	unsigned char a[] = {
		[Unit_B]   = 0,
		[Unit_KiB] = 10,
		[Unit_MiB] = 20,
		[Unit_GiB] = 30,
		[Unit_TiB] = 40
	};

	if (unit == NULL)
		return 0;

	for (i = 1; i < NDM_ARRAY_SIZE(a); i++) {
		if (size < (1ULL << a[i]))
			break;
	}

	i--;
	*unit = i;

	return size / (1ULL << a[i]);
}

char *Str_SizeFormat(size_t size, char *buf, size_t buf_size)
{
	const char *a[] = {
		[Unit_B] = "B",
		[Unit_KiB] = "KiB",
		[Unit_MiB] = "MiB",
		[Unit_GiB] = "GiB",
		[Unit_TiB] = "TiB"
	};
	enum Unit u;
	double v;

	if (buf == NULL || !buf_size)
		return NULL;

	v = Str_SizeSimp(size, &u);
	snprintf(buf, buf_size, (u == Unit_B) ? "%.0f %s" : "%.02f %s",
		 v, a[u]);

	return buf;
}

char *Str_SpeedFormat(double speed, char *buf, size_t buf_size)
{
	const char *a[] = {
		[Unit_B] = "B/s",
		[Unit_KiB] = "KiB/s",
		[Unit_MiB] = "MiB/s",
		[Unit_GiB] = "GiB/s",
		[Unit_TiB] = "TiB/s"
	};
	enum Unit u;
	double v;

	if (buf == NULL || !buf_size)
		return NULL;

	v = Str_SizeSimp(speed, &u);
	snprintf(buf, buf_size, (u == Unit_B) ? "%.0f %s" : "%.02f %s",
		 v, a[u]);

	return buf;
}

void Str_Low(char *s)
{
	if (s == NULL)
		return;

	while (*s) {
		*s = tolower(*s);
		s++;
	}
}

void Str_Up(char *s)
{
	if (s == NULL)
		return;

	while (*s) {
		*s = toupper(*s);
		s++;
	}
}
