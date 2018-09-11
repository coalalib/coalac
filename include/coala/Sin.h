#ifndef _SIN_H_
#define _SIN_H_

#include <netinet/ip.h> /* struct sockaddr_in */
#include <stdio.h>	/* FILE * */

extern int Sin_SetPort(struct sockaddr_in *sin, const char *s);
extern int Sin_SetIp(struct sockaddr_in *sin, const char *s);
extern int Sin_SetIpPort(struct sockaddr_in *sin, const char *s);

#define SIN_PORT_SIZE	sizeof("65535")
#define SIN_IP_SIZE	sizeof("123.123.123.123")
#define SIN_IPPORT_SIZE	sizeof("123.123.123.123:65535")

extern int Sin_GetPort(struct sockaddr_in *sin, char *s, size_t size);
extern int Sin_GetIp(struct sockaddr_in *sin, char *s, size_t size);
extern int Sin_GetIpPort(struct sockaddr_in *sin, char *s, size_t size);

extern void Sin_Print(struct sockaddr_in *sin, FILE *fp);

#endif
