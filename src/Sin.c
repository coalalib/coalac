#include <arpa/inet.h>
#include <coala/Sin.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int Sin_SetPort(struct sockaddr_in *sin, const char *s)
{
	char *end;
	unsigned long port;

	if (sin == NULL || s == NULL) {
		errno = EINVAL;
		return -1;
	}

	port = strtoul(s, &end, 10);
	if (*end != '\0' ||
	    port > UINT16_MAX) {
		errno = EINVAL;
		return -1;
	}

	sin->sin_port = htons(port);

	return 0;
}

int Sin_SetIp(struct sockaddr_in *sin, const char *s)
{
	if (sin == NULL || s == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (inet_pton(AF_INET, s, &sin->sin_addr) != 1) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int Sin_SetIpPort(struct sockaddr_in *sin, const char *s)
{
	char buf[SIN_IP_SIZE] = "";
	const char *p;

	if (sin == NULL || s == NULL) {
		errno = EINVAL;
		return -1;
	}

	if ((p = strchr(s, ':')) == NULL) {
		errno = EINVAL;
		return -1;
	}

	strncpy(buf, s, p - s);
	p++;

	if (Sin_SetIp(sin, buf) < 0)
		return -1;

	if (Sin_SetPort(sin, p) < 0)
		return -1;

	return 0;
}

int Sin_GetPort(struct sockaddr_in *sin, char *s, size_t size)
{
	if (sin == NULL || s == NULL || size < SIN_PORT_SIZE) {
		errno = EINVAL;
		return -1;
	}

	snprintf(s, size, "%hu", ntohs(sin->sin_port));

	return 0;
}

int Sin_GetIp(struct sockaddr_in *sin, char *s, size_t size)
{
	if (sin == NULL || s == NULL || size < SIN_IP_SIZE) {
		errno = EINVAL;
		return -1;
	}

	if (inet_ntop(AF_INET, &sin->sin_addr, s, size) == NULL)
		return -1;

	return 0;
}

int Sin_GetIpPort(struct sockaddr_in *sin, char *s, size_t size)
{
	size_t l;

	if (sin == NULL || sin == NULL || size < SIN_IPPORT_SIZE) {
		errno = EINVAL;
		return -1;
	}

	if (Sin_GetIp(sin, s, size) < 0)
		return -1;

	l = strlen(s);
	s += l;
	size -= l;

	*s++ = ':';
	size--;

	if (Sin_GetPort(sin, s, size) < 0)
		return -1;

	return 0;
}

void Sin_Print(struct sockaddr_in *sin, FILE *fp)
{
	char buf[SIN_IPPORT_SIZE];

	if (sin == NULL)
		return;

	fprintf(fp, "IpPort: ");

	if (Sin_GetIpPort(sin, buf, sizeof buf) < 0) {
		fputs("(none)\n", fp);
		return;
	}

	fprintf(fp, "%s\n", buf);
}
