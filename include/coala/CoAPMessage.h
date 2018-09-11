#ifndef _COAP_MESSAGE_H_
#define _COAP_MESSAGE_H_

#include <stdbool.h>
#include <stddef.h>	/* size_t */
#include <stdint.h>	/* uint8_t and etc. */
#include <stdio.h>	/* FILE */

#include <coala/queue.h>

#ifndef BIT
	#define BIT(x)	(1ul << (x))
#endif

struct Buf_Handle;
struct CoAPMessage;
struct Coala;
struct ndm_ip_sockaddr_t;

enum CoAPMessage_Type {
	/* Request */
	CoAPMessage_TypeCon,
	CoAPMessage_TypeNon,
	/* Response */
	CoAPMessage_TypeAck,
	CoAPMessage_TypeRst,
	CoAPMessage_TypeMax
};

#define COAP_MESSAGE_CODE(n)	((n / 100) << 5 | n % 100)

enum CoAPMessage_Code {
	CoAPMessage_CodeEmpty				= COAP_MESSAGE_CODE(0),
	/* Request */
	CoAPMessage_CodeGet				= COAP_MESSAGE_CODE(1),
	CoAPMessage_CodePost				= COAP_MESSAGE_CODE(2),
	CoAPMessage_CodePut				= COAP_MESSAGE_CODE(3),
	CoAPMessage_CodeDelete				= COAP_MESSAGE_CODE(4),
	/* Response */
	/* 2xx: success */
	CoAPMessage_CodeCreated				= COAP_MESSAGE_CODE(201),
	CoAPMessage_CodeDeleted				= COAP_MESSAGE_CODE(202),
	CoAPMessage_CodeValid				= COAP_MESSAGE_CODE(203),
	CoAPMessage_CodeChanged				= COAP_MESSAGE_CODE(204),
	CoAPMessage_CodeContent				= COAP_MESSAGE_CODE(205),
	CoAPMessage_CodeContinue			= COAP_MESSAGE_CODE(231),	/* block-wise */
	/* 4xx: client error */
	CoAPMessage_CodeBadRequest			= COAP_MESSAGE_CODE(400),
	CoAPMessage_CodeUnauthorized			= COAP_MESSAGE_CODE(401),
	CoAPMessage_CodeBadOption			= COAP_MESSAGE_CODE(402),
	CoAPMessage_CodeForbidden			= COAP_MESSAGE_CODE(403),
	CoAPMessage_CodeNotFound			= COAP_MESSAGE_CODE(404),
	CoAPMessage_CodeMethodNotAllowed		= COAP_MESSAGE_CODE(405),
	CoAPMessage_CodeNotAcceptable			= COAP_MESSAGE_CODE(406),
	CoAPMessage_CodeRequestEntityIncomplete		= COAP_MESSAGE_CODE(408),	/* block-wise */
	CoAPMessage_CodePreconditionFailed		= COAP_MESSAGE_CODE(412),
	CoAPMessage_CodeRequestEntityTooLarge		= COAP_MESSAGE_CODE(413),	/* block-wise */
	CoAPMessage_CodeUnsupportedContentFormat	= COAP_MESSAGE_CODE(415),
	/* 5xx: server error */
	CoAPMessage_CodeInternalServerError		= COAP_MESSAGE_CODE(500),
	CoAPMessage_CodeNotImplemented			= COAP_MESSAGE_CODE(501),
	CoAPMessage_CodeBadGateway			= COAP_MESSAGE_CODE(502),
	CoAPMessage_CodeServiceUnavailable		= COAP_MESSAGE_CODE(503),
	CoAPMessage_CodeGatewayTimeout			= COAP_MESSAGE_CODE(504),
	CoAPMessage_CodeProxyingNotSupported		= COAP_MESSAGE_CODE(505),
	CoAPMessage_CodeMax
};

enum CoAPMessage_OptionCode {
	CoAPMessage_OptionCodeIfMatch			= 1,
	CoAPMessage_OptionCodeUriHost			= 3,
	CoAPMessage_OptionCodeEtag			= 4,
	CoAPMessage_OptionCodeIfNoneMatch		= 5,
	CoAPMessage_OptionCodeObserve			= 6,
	CoAPMessage_OptionCodeUriPort			= 7,
	CoAPMessage_OptionCodeLocationPath		= 8,
	CoAPMessage_OptionCodeUriPath			= 11,
	CoAPMessage_OptionCodeContentFormat		= 12,
	CoAPMessage_OptionCodeMaxAge			= 14,
	CoAPMessage_OptionCodeUriQuery			= 15,
	CoAPMessage_OptionCodeAccept			= 17,
	CoAPMessage_OptionCodeLocationQuery		= 20,
	CoAPMessage_OptionCodeBlock2			= 23,
	CoAPMessage_OptionCodeBlock1			= 27,
	CoAPMessage_OptionCodeSize2			= 28,
	CoAPMessage_OptionCodeProxyUri			= 35,
	CoAPMessage_OptionCodeProxyScheme		= 39,
	CoAPMessage_OptionCodeSize1			= 60,
	CoAPMessage_OptionCodeUriScheme			= 2111,
	CoAPMessage_OptionCodeSelectiveRepeatWindowSize	= 3001,
	CoAPMessage_OptionCodeHandshakeType		= 3999,
	CoAPMessage_OptionCodeSessionNotFound		= 4001,
	CoAPMessage_OptionCodeSessionExpired		= 4003,
	CoAPMessage_OptionCodeCoapsUri			= 4005
};

enum CoAPMessage_ContentFormat {
	CoAPMessage_ContentFormatTextPlain	= 0,
	CoAPMessage_ContentFormatLink		= 40,
	CoAPMessage_ContentFormatXml		= 41,
	CoAPMessage_ContentFormatOctetStream	= 42,
	CoAPMessage_ContentFormatEsi		= 47,
	CoAPMessage_ContentFormatJson		= 50
};


struct CoAPMessage_Option {
	enum CoAPMessage_OptionCode code;
	uint8_t *value;
	uint32_t value_len;				/* max = 12 + 1 + 255 + 65535 = 65804 */
	TAILQ_ENTRY(CoAPMessage_Option) list;
};

TAILQ_HEAD(CoAPMessage_OptionHead, CoAPMessage_Option);


static inline bool CoAPMessage_CodeIsEmpty(enum CoAPMessage_Code code)
{
	return code == CoAPMessage_CodeEmpty;
}

static inline bool CoAPMessage_CodeIsRequest(enum CoAPMessage_Code code)
{
	return code >= CoAPMessage_CodeGet && code <= CoAPMessage_CodeDelete;
}

static inline bool CoAPMessage_CodeIsResponse(enum CoAPMessage_Code code)
{
	return code >= CoAPMessage_CodeCreated && code <= CoAPMessage_CodeMax;
}

static inline bool CoAPMessage_TypeIsRequest(enum CoAPMessage_Type type)
{
	return type == CoAPMessage_TypeCon || type == CoAPMessage_TypeNon;
}

static inline bool CoAPMessage_TypeIsResponse(enum CoAPMessage_Type type)
{
	return type == CoAPMessage_TypeAck || type == CoAPMessage_TypeRst;
}

extern void CoAPMessage_Init(void);

extern struct CoAPMessage *CoAPMessage(enum CoAPMessage_Type type,
				       enum CoAPMessage_Code code,
				       int id);
extern struct CoAPMessage *CoAPMessage_Clone(struct CoAPMessage *m,
					     bool payload);
extern void CoAPMessage_Decref(struct CoAPMessage *m);
extern struct CoAPMessage *CoAPMessage_Incref(struct CoAPMessage *m);

extern uint16_t CoAPMessage_GenId(void);
extern int CoAPMessage_GetId(struct CoAPMessage *m);
extern int CoAPMessage_SetId(struct CoAPMessage *m, uint16_t id);

extern int CoAPMessage_GetType(struct CoAPMessage *m);
extern const char *CoAPMessage_GetTypeStr(struct CoAPMessage *m);
extern int CoAPMessage_SetType(struct CoAPMessage *m,
			       enum CoAPMessage_Type type);

extern int CoAPMessage_GetCode(struct CoAPMessage *m);
extern char *CoAPMessage_GetCodeStr(struct CoAPMessage *m, char *buf,
				    size_t size);
extern int CoAPMessage_SetCode(struct CoAPMessage *m,
			       enum CoAPMessage_Code code);

enum CoAPMessage_CodeStr_Fmt {
	CoAPMessage_CodeStr_Fmt1,	/* "0.01" */
	CoAPMessage_CodeStr_Fmt2,	/* "Get" */
	CoAPMessage_CodeStr_Fmt3	/* "0.01 (Get)" */
};

extern char *CoAPMessage_CodeStr(enum CoAPMessage_Code code, char *buf,
				 size_t size, enum CoAPMessage_CodeStr_Fmt fmt);

static inline bool CoAPMessage_IsCon(struct CoAPMessage *m)
{
	return CoAPMessage_GetType(m) == CoAPMessage_TypeCon;
}

static inline bool CoAPMessage_IsNon(struct CoAPMessage *m)
{
	return CoAPMessage_GetType(m) == CoAPMessage_TypeNon;
}

static inline bool CoAPMessage_IsEmpty(struct CoAPMessage *m)
{
	return CoAPMessage_CodeIsEmpty(CoAPMessage_GetCode(m));
}

static inline bool CoAPMessage_IsRequest(struct CoAPMessage *m)
{
	return CoAPMessage_CodeIsRequest(CoAPMessage_GetCode(m));
}

static inline bool CoAPMessage_IsResponse(struct CoAPMessage *m)
{
	return CoAPMessage_CodeIsResponse(CoAPMessage_GetCode(m));
}

static inline bool CoAPMessage_IsPing(struct CoAPMessage *m)
{
	return CoAPMessage_IsCon(m) && CoAPMessage_IsEmpty(m);
}

extern bool CoAPMessage_IsMulticast(struct CoAPMessage *m);

#define CoAPMessage_GetPayload_Alloc	BIT(0)
#define CoAPMessage_GetPayload_Zero	BIT(1)
extern uint8_t *CoAPMessage_GetPayload(struct CoAPMessage *m, size_t *size,
				       unsigned flags);
extern int CoAPMessage_SetPayload(struct CoAPMessage *m, const uint8_t *payload,
				  size_t size);

#define COAP_MESSAGE_MAX_TOKEN_SIZE	8
extern int CoAPMessage_GenToken(uint8_t *token, size_t size);
extern int CoAPMessage_GetToken(struct CoAPMessage *m, uint8_t *token,
				size_t *size);
extern int CoAPMessage_SetToken(struct CoAPMessage *m, const uint8_t *token,
				size_t size);
extern int CoAPMessage_CopyToken(struct CoAPMessage *d, struct CoAPMessage *s);

extern char *CoAPMessage_GetUri(struct CoAPMessage *m, bool encode);

#define CoAPMessage_SetUri_OnlySecure	BIT(0)
#define CoAPMessage_SetUri_OnlyIpPort	BIT(1)
#define CoAPMessage_SetUri_OnlyPath	BIT(2)
#define CoAPMessage_SetUri_OnlyQuery	BIT(3)
extern int CoAPMessage_SetUri(struct CoAPMessage *m, const char *uri,
			      unsigned flags);

extern char *CoAPMessage_GetUriPath(struct CoAPMessage *m, bool encode);
extern int CoAPMessage_SetUriPath(struct CoAPMessage *m, const char *path);

extern int CoAPMessage_SetSecure(struct CoAPMessage *m, bool on);
extern int CoAPMessage_GetSecure(struct CoAPMessage *m, bool *on);
static inline bool CoAPMessage_IsSecure(struct CoAPMessage *m)
{
	bool on;
	return !CoAPMessage_GetSecure(m, &on) && on;
}


extern int CoAPMessage_SetUriQuery(struct CoAPMessage *m, const char *query);
extern char *CoAPMessage_GetUriQuery(struct CoAPMessage *m, bool encode);

extern int CoAPMessage_AddOptionOpaque(struct CoAPMessage *m,
				       enum CoAPMessage_OptionCode code,
				       const uint8_t *data, size_t size);
extern int CoAPMessage_AddOptionEmpty(struct CoAPMessage *m,
				      enum CoAPMessage_OptionCode code);
extern int CoAPMessage_AddOptionString(struct CoAPMessage *m,
				       enum CoAPMessage_OptionCode code,
				       const char *s);
extern int CoAPMessage_AddOptionUint(struct CoAPMessage *m,
				     enum CoAPMessage_OptionCode code,
				     uint32_t val);
extern int CoAPMessage_RemoveOptions(struct CoAPMessage *m,
				     enum CoAPMessage_OptionCode code);
extern int CoAPMessage_GetOptions(struct CoAPMessage *m,
				  enum CoAPMessage_OptionCode code,
				  struct CoAPMessage_OptionHead *h);
extern void CoAPMessage_GetOptionsFree(struct CoAPMessage_OptionHead *h);

enum {
	CoAPMessage_IterOptionsFuncError = -1,
	CoAPMessage_IterOptionsFuncStop = 0,
	CoAPMessage_IterOptionsFuncOk = 1
};

typedef int (*CoAPMessage_IterOptionsFunc)(enum CoAPMessage_OptionCode code,
					   uint8_t *v, size_t s, bool last,
					   void *data);
extern int CoAPMessage_IterOptions(struct CoAPMessage *m,
				   CoAPMessage_IterOptionsFunc f,
				   void *data);
extern char *CoAPMessage_OptionCodeStr(enum CoAPMessage_OptionCode code,
				       char *buf, size_t size);

extern uint8_t *CoAPMessage_GetOptionOpaque(struct CoAPMessage *m,
					    enum CoAPMessage_OptionCode code,
					    size_t *size);
extern int CoAPMessage_GetOptionUint(struct CoAPMessage *m,
				     enum CoAPMessage_OptionCode code,
				     uint32_t *val);
extern char *CoAPMessage_GetOptionString(struct CoAPMessage *m,
					 enum CoAPMessage_OptionCode code,
					 size_t *len);
extern int CoAPMessage_CopyOption(struct CoAPMessage *d, struct CoAPMessage *s,
				  enum CoAPMessage_OptionCode code);

extern uint8_t *CoAPMessage_ToBytes(struct CoAPMessage *m, size_t *size);

extern struct CoAPMessage *CoAPMessage_FromBytes(uint8_t *d, size_t size);

extern int CoAPMessage_Equals(struct CoAPMessage *m1, struct CoAPMessage *m2);

extern int CoAPMessage_ToBuf(struct CoAPMessage *m, struct Buf_Handle *b);
extern int CoAPMessage_Print(struct CoAPMessage *m, FILE *fp);

extern struct CoAPMessage_Option *CoAPMessage_Option(
					enum CoAPMessage_OptionCode code,
					const uint8_t *value,
					size_t value_len);
extern void CoAPMessage_OptionFree(struct CoAPMessage_Option *o);
extern struct CoAPMessage_Option *CoAPMessage_OptionDup(
					struct CoAPMessage_Option *o);

enum CoAPMessage_BlockSize {
	CoAPMessage_BlockSize16,
	CoAPMessage_BlockSize32,
	CoAPMessage_BlockSize64,
	CoAPMessage_BlockSize128,
	CoAPMessage_BlockSize256,
	CoAPMessage_BlockSize512,
	CoAPMessage_BlockSize1024,
/*	CoAPMessage_BlockSize2048, reserved */
	CoAPMessage_BlockSizeMax
};

struct CoAPMessage_Block {
	uint32_t num;				/* 4, 12 or 20 bits */
	enum CoAPMessage_BlockSize szx;		/* 4 bits */
	bool m;					/* 1 bit */
};

extern int CoAPMessage_AddOptionBlock(struct CoAPMessage *m,
				      enum CoAPMessage_OptionCode code,
				      struct CoAPMessage_Block *b);
extern int CoAPMessage_GetOptionBlock(struct CoAPMessage *m,
				      enum CoAPMessage_OptionCode code,
				      struct CoAPMessage_Block *b);
static inline size_t CoAPMessage_BlockSize(enum CoAPMessage_BlockSize bs)
{
	return 1 << (bs + 4);
}

extern int CoAPMessage_GetSockAddr(struct CoAPMessage *m,
				   struct ndm_ip_sockaddr_t *sa);
extern int CoAPMessage_SetSockAddr(struct CoAPMessage *m,
				   struct ndm_ip_sockaddr_t *sa);
extern int CoAPMessage_CopySockAddr(struct CoAPMessage *d,
				    struct CoAPMessage *s);

typedef int (*CoAPMessage_Handler_t)(struct Coala *, struct CoAPMessage *);

extern int CoAPMessage_SetHandler(struct CoAPMessage *m,
				  CoAPMessage_Handler_t h);
extern CoAPMessage_Handler_t CoAPMessage_GetHandler(struct CoAPMessage *m);

#endif
