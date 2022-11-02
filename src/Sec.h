#ifndef _SEC_H_
#define _SEC_H_

struct Err;
struct CoAPMessage;

extern int Sec_CookieDecrypt(struct CoAPMessage *m, struct Aead *aead,
			     struct Err *err);
extern int Sec_CookieEncrypt(struct CoAPMessage *m, struct Aead *aead,
			     struct Err *err);

extern int Sec_PayloadDecrypt(struct CoAPMessage *m, struct Aead *aead,
			      struct Err *err);
extern int Sec_PayloadEncrypt(struct CoAPMessage *from, struct CoAPMessage *to,
			      struct Aead *aead, struct Err *err);

extern int Sec_UriDecrypt(struct CoAPMessage *m, struct Aead *aead,
			  struct Err *err);
extern int Sec_UriEncrypt(struct CoAPMessage *m, struct Aead *aead,
			  struct Err *err);

#endif
