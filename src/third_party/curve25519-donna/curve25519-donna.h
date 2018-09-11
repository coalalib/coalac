#ifndef _CURVE25519_DONNA_H_
#define _CURVE25519_DONNA_H_

#define CURVE25519_DONNA_KEY_SIZE 32

extern int curve25519_donna(unsigned char *mypublic,
			    const unsigned char *secret,
			    const unsigned char *basepoint);
#endif
