/* cmp.h
 * CMP (RFC 4210) header file for OpenSSL
 */
/* ====================================================================
 * Originally written by Martin Peylo for the OpenSSL project.
 * <martin dot peylo at nsn dot com>
 * 2010-2012 Miikka Viljanen <mviljane@users.sourceforge.net>
 */
/* ====================================================================
 * Copyright (c) 2007-2010 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in
 *        the documentation and/or other materials provided with the
 *        distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *        software must display the following acknowledgment:
 *        "This product includes software developed by the OpenSSL Project
 *        for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *        endorse or promote products derived from this software without
 *        prior written permission. For written permission, please contact
 *        openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *        nor may "OpenSSL" appear in their names without prior written
 *        permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *        acknowledgment:
 *        "This product includes software developed by the OpenSSL Project
 *        for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.      IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 */
/* ====================================================================
 * Copyright 2007-2014 Nokia Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by
 * Nokia for contribution to the OpenSSL project.
 */

#ifndef HEADER_CMP_H
# define HEADER_CMP_H

# include <openssl/opensslconf.h>

# include <openssl/ossl_typ.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
# include <openssl/safestack.h>
# if OPENSSL_VERSION_NUMBER >= 0x10101000L
#  include <openssl/cmperr.h>
# endif

# if OPENSSL_VERSION_NUMBER < 0x10100000L
#  define DEFINE_STACK_OF(T) DECLARE_STACK_OF(T)
#  define X509_get0_subject_key_id(x) \
       (X509_check_purpose((x), -1, -1),(x)->skid)
#  define OPENSSL_strndup strndup
# endif
# if OPENSSL_VERSION_NUMBER < 0x1010001fL
#  define OPENSSL_zalloc(num) CRYPTO_malloc(num, __FILE__, __LINE__)
#  define X509_up_ref(x)((x)->references++)
#  define ASN1_STRING_get0_data ASN1_STRING_data
#  define X509_OBJECT_get0_X509(obj) ((obj)->data.x509)
#  define X509_STORE_get0_objects(store) ((store)->objs)
#  define X509_STORE_CTX_get0_untrusted(ctx) ((ctx)->untrusted)
#  define X509_STORE_CTX_get0_chain X509_STORE_CTX_get_chain
#  define X509_STORE_CTX_get_by_subject X509_STORE_get_by_subject
#  define X509_STORE_CTX_set_current_cert(ctx, x) { (ctx)->current_cert = (x); }
#  define X509_STORE_CTX_set_error_depth(ctx, n) { (ctx)->error_depth = (n); }
typedef int (*X509_STORE_CTX_verify_cb)(int, X509_STORE_CTX *);
#  define X509_STORE_CTX_get_verify_cb(ctx) ((ctx)->verify_cb)
#  define X509_STORE_get_verify_cb(store) ((store)->verify_cb)
#  define X509_STORE_get0_param(ctx) ((ctx)->param)
#  define X509_STORE_set_ex_data(ctx, idx, data) \
       CRYPTO_set_ex_data(&(ctx)->ex_data, (idx), (data))
#  define X509_STORE_get_ex_data(ctx, idx) \
       CRYPTO_get_ex_data(&(ctx)->ex_data, (idx))
#  ifndef X509_V_ERR_STORE_LOOKUP
#   define X509_V_ERR_STORE_LOOKUP 70
#  endif
#  define X509_STORE_set_lookup_crls X509_STORE_set_lookup_crls_cb
#  define X509_VERIFY_PARAM_get_time(param) ((param)->check_time)
#  define X509_V_FLAG_NO_CHECK_TIME 0x200000
#  define X509_set_proxy_flag(x) { (x)->ex_flags |= EXFLAG_PROXY; }
#  define X509_get0_notBefore X509_get_notBefore
#  define X509_get0_notAfter X509_get_notAfter
#  define X509_CRL_get0_lastUpdate X509_CRL_get_lastUpdate
#  define X509_CRL_get0_nextUpdate X509_CRL_get_nextUpdate
#  define X509_get_key_usage(x) ((X509_check_purpose((x), -1, -1), \
       (x)->ex_flags & EXFLAG_KUSAGE) ? (x)->ex_kusage : (unsigned long) ~0)
# endif

# include <openssl/crmf.h>

# define CMP_VERSION 2L

# ifdef  __cplusplus
extern "C" {
# endif

/*-
 *   PKIFailureInfo ::= BIT STRING {
 *   -- since we can fail in more than one way!
 *   -- More codes may be added in the future if/when required.
 *       badAlg              (0),
 *       -- unrecognized or unsupported Algorithm Identifier
 *       badMessageCheck     (1),
 *       -- integrity check failed (e.g., signature did not verify)
 *       badRequest          (2),
 *       -- transaction not permitted or supported
 *       badTime             (3),
 *       -- messageTime was not sufficiently close to the system time,
 *       -- as defined by local policy
 *       badCertId           (4),
 *       -- no certificate could be found matching the provided criteria
 *       badDataFormat       (5),
 *       -- the data submitted has the wrong format
 *       wrongAuthority      (6),
 *       -- the authority indicated in the request is different from the
 *       -- one creating the response token
 *       incorrectData       (7),
 *       -- the requester's data is incorrect (for notary services)
 *       missingTimeStamp    (8),
 *       -- when the timestamp is missing but should be there
 *       -- (by policy)
 *       badPOP              (9),
 *       -- the proof-of-possession failed
 *       certRevoked         (10),
 *          -- the certificate has already been revoked
 *       certConfirmed       (11),
 *          -- the certificate has already been confirmed
 *       wrongIntegrity      (12),
 *          -- invalid integrity, password based instead of signature or
 *          -- vice versa
 *       badRecipientNonce   (13),
 *          -- invalid recipient nonce, either missing or wrong value
 *       timeNotAvailable    (14),
 *          -- the TSA's time source is not available
 *       unacceptedPolicy    (15),
 *          -- the requested TSA policy is not supported by the TSA.
 *       unacceptedExtension (16),
 *          -- the requested extension is not supported by the TSA.
 *       addInfoNotAvailable (17),
 *          -- the additional information requested could not be
 *          -- understood or is not available
 *       badSenderNonce      (18),
 *          -- invalid sender nonce, either missing or wrong size
 *       badCertTemplate     (19),
 *          -- invalid cert. template or missing mandatory information
 *       signerNotTrusted    (20),
 *          -- signer of the message unknown or not trusted
 *       transactionIdInUse  (21),
 *          -- the transaction identifier is already in use
 *       unsupportedVersion  (22),
 *          -- the version of the message is not supported
 *       notAuthorized       (23),
 *          -- the sender was not authorized to make the preceding
 *          -- request or perform the preceding action
 *       systemUnavail       (24),
 *       -- the request cannot be handled due to system unavailability
 *       systemFailure       (25),
 *       -- the request cannot be handled due to system failure
 *       duplicateCertReq    (26)
 *       -- certificate cannot be issued because a duplicate
 *       -- certificate already exists
 *   }
 */
# define CMP_PKIFAILUREINFO_badAlg 0
# define CMP_PKIFAILUREINFO_badMessageCheck 1
# define CMP_PKIFAILUREINFO_badRequest 2
# define CMP_PKIFAILUREINFO_badTime 3
# define CMP_PKIFAILUREINFO_badCertId 4
# define CMP_PKIFAILUREINFO_badDataFormat 5
# define CMP_PKIFAILUREINFO_wrongAuthority 6
# define CMP_PKIFAILUREINFO_incorrectData 7
# define CMP_PKIFAILUREINFO_missingTimeStamp 8
# define CMP_PKIFAILUREINFO_badPOP 9
# define CMP_PKIFAILUREINFO_certRevoked 10
# define CMP_PKIFAILUREINFO_certConfirmed 11
# define CMP_PKIFAILUREINFO_wrongIntegrity 12
# define CMP_PKIFAILUREINFO_badRecipientNonce 13
# define CMP_PKIFAILUREINFO_timeNotAvailable 14
# define CMP_PKIFAILUREINFO_unacceptedPolicy 15
# define CMP_PKIFAILUREINFO_unacceptedExtension 16
# define CMP_PKIFAILUREINFO_addInfoNotAvailable 17
# define CMP_PKIFAILUREINFO_badSenderNonce 18
# define CMP_PKIFAILUREINFO_badCertTemplate 19
# define CMP_PKIFAILUREINFO_signerNotTrusted 20
# define CMP_PKIFAILUREINFO_transactionIdInUse 21
# define CMP_PKIFAILUREINFO_unsupportedVersion 22
# define CMP_PKIFAILUREINFO_notAuthorized 23
# define CMP_PKIFAILUREINFO_systemUnavail 24
# define CMP_PKIFAILUREINFO_systemFailure 25
# define CMP_PKIFAILUREINFO_duplicateCertReq 26
# define CMP_PKIFAILUREINFO_MAX 26
typedef ASN1_BIT_STRING CMP_PKIFAILUREINFO;

# define CMP_CTX_FAILINFO_badAlg (1 << 0)
# define CMP_CTX_FAILINFO_badMessageCheck (1 << 1)
# define CMP_CTX_FAILINFO_badRequest (1 << 2)
# define CMP_CTX_FAILINFO_badTime (1 << 3)
# define CMP_CTX_FAILINFO_badCertId (1 << 4)
# define CMP_CTX_FAILINFO_badDataFormat (1 << 5)
# define CMP_CTX_FAILINFO_wrongAuthority (1 << 6)
# define CMP_CTX_FAILINFO_incorrectData (1 << 7)
# define CMP_CTX_FAILINFO_missingTimeStamp (1 << 8)
# define CMP_CTX_FAILINFO_badPOP (1 << 9)
# define CMP_CTX_FAILINFO_certRevoked (1 << 10)
# define CMP_CTX_FAILINFO_certConfirmed (1 << 11)
# define CMP_CTX_FAILINFO_wrongIntegrity (1 << 12)
# define CMP_CTX_FAILINFO_badRecipientNonce (1 << 13)
# define CMP_CTX_FAILINFO_timeNotAvailable (1 << 14)
# define CMP_CTX_FAILINFO_unacceptedPolicy (1 << 15)
# define CMP_CTX_FAILINFO_unacceptedExtension (1 << 16)
# define CMP_CTX_FAILINFO_addInfoNotAvailable (1 << 17)
# define CMP_CTX_FAILINFO_badSenderNonce (1 << 18)
# define CMP_CTX_FAILINFO_badCertTemplate (1 << 19)
# define CMP_CTX_FAILINFO_signerNotTrusted (1 << 20)
# define CMP_CTX_FAILINFO_transactionIdInUse (1 << 21)
# define CMP_CTX_FAILINFO_unsupportedVersion (1 << 22)
# define CMP_CTX_FAILINFO_notAuthorized (1 << 23)
# define CMP_CTX_FAILINFO_systemUnavail (1 << 24)
# define CMP_CTX_FAILINFO_systemFailure (1 << 25)
# define CMP_CTX_FAILINFO_duplicateCertReq (1 << 26)

/*-
 *   PKIStatus ::= INTEGER {
 *       accepted                (0),
 *       -- you got exactly what you asked for
 *       grantedWithMods        (1),
 *       -- you got something like what you asked for; the
 *       -- requester is responsible for ascertaining the differences
 *       rejection              (2),
 *       -- you don't get it, more information elsewhere in the message
 *       waiting                (3),
 *       -- the request body part has not yet been processed; expect to
 *       -- hear more later (note: proper handling of this status
 *       -- response MAY use the polling req/rep PKIMessages specified
 *       -- in Section 5.3.22; alternatively, polling in the underlying
 *       -- transport layer MAY have some utility in this regard)
 *       revocationWarning      (4),
 *       -- this message contains a warning that a revocation is
 *       -- imminent
 *       revocationNotification (5),
 *       -- notification that a revocation has occurred
 *       keyUpdateWarning       (6)
 *       -- update already done for the oldCertId specified in
 *       -- CertReqMsg
 *   }
 */
# define CMP_PKISTATUS_accepted 0
# define CMP_PKISTATUS_grantedWithMods 1
# define CMP_PKISTATUS_rejection 2
# define CMP_PKISTATUS_waiting 3
# define CMP_PKISTATUS_revocationWarning 4
# define CMP_PKISTATUS_revocationNotification 5
# define CMP_PKISTATUS_keyUpdateWarning 6

typedef ASN1_INTEGER CMP_PKISTATUS;

# define CMP_CERTORENCCERT_CERTIFICATE 0
# define CMP_CERTORENCCERT_ENCRYPTEDCERT 1

/* Forward declarations */
typedef struct cmp_ctx_st CMP_CTX;
typedef struct cmp_pkiheader_st CMP_PKIHEADER;
typedef struct cmp_pkimessage_st CMP_PKIMESSAGE;
typedef struct cmp_certstatus_st CMP_CERTSTATUS;
typedef struct cmp_infotypeandvalue_st CMP_INFOTYPEANDVALUE;
typedef struct cmp_revrepcontent_st CMP_REVREPCONTENT;
typedef struct cmp_pkistatusinfo_st CMP_PKISTATUSINFO;
typedef struct cmp_certrepmessage_st CMP_CERTREPMESSAGE;
typedef struct cmp_pollrep_st CMP_POLLREP;
typedef STACK_OF(CMP_POLLREP) CMP_POLLREPCONTENT;
typedef struct cmp_certresponse_st CMP_CERTRESPONSE;
DEFINE_STACK_OF(CMP_CERTSTATUS)
DEFINE_STACK_OF(CMP_INFOTYPEANDVALUE)
DECLARE_ASN1_FUNCTIONS(CMP_INFOTYPEANDVALUE)
DEFINE_STACK_OF(CMP_PKISTATUSINFO)
DEFINE_STACK_OF(CMP_CERTREPMESSAGE)
DEFINE_STACK_OF(CMP_CERTRESPONSE)


/*
 * context DECLARATIONS
 */
typedef void (*cmp_log_cb_t) (const char *msg);
typedef int (*cmp_certConf_cb_t) (CMP_CTX *ctx, const X509 *cert, int failure,
                                 const char **txt);
typedef int (*cmp_transfer_cb_t) (CMP_CTX *ctx, const CMP_PKIMESSAGE *req,
                                  CMP_PKIMESSAGE **res);
typedef STACK_OF(ASN1_UTF8STRING) CMP_PKIFREETEXT;

/*
 * function DECLARATIONS
 */
/* cmp_msg.c */

/* CMP_PKIMESSAGE bodytype ASN.1 choice indices for CMP_certreq_new() */
# define V_CMP_PKIBODY_IR 0
# define V_CMP_PKIBODY_CR 2
# define V_CMP_PKIBODY_P10CR 4
# define V_CMP_PKIBODY_KUR 7
CMP_PKIMESSAGE *CMP_certreq_new(CMP_CTX *ctx, int bodytype, int err_code);
CMP_PKIMESSAGE *CMP_rr_new(CMP_CTX *ctx);
CMP_PKIMESSAGE *CMP_certConf_new(CMP_CTX *ctx, int failure, const char *text);
CMP_PKIMESSAGE *CMP_genm_new(CMP_CTX *ctx);
CMP_PKIMESSAGE *CMP_error_new(CMP_CTX *ctx, CMP_PKISTATUSINFO *si,
                              int errorCode, CMP_PKIFREETEXT *errorDetails);
CMP_PKIMESSAGE *CMP_pollReq_new(CMP_CTX *ctx, int reqId);

/* cmp_lib.c */
void CMP_add_error_txt(const char *separator, const char *txt);
# define CMP_add_error_data(txt) CMP_add_error_txt(":", txt)
# define CMP_add_error_line(txt) CMP_add_error_txt("\n", txt)

# define TRANSACTIONID_LENGTH 16
# define SENDERNONCE_LENGTH 16
CMP_PKIHEADER *CMP_PKIMESSAGE_get0_header(const CMP_PKIMESSAGE *msg);
ASN1_OCTET_STRING *CMP_PKIHEADER_get0_transactionID(const CMP_PKIHEADER *hdr);
ASN1_OCTET_STRING *CMP_PKIHEADER_get0_senderNonce(const CMP_PKIHEADER *hdr);
ASN1_OCTET_STRING *CMP_PKIHEADER_get0_recipNonce(const CMP_PKIHEADER *hdr);

int CMP_PKIHEADER_set_version(CMP_PKIHEADER *hdr, int version);
int CMP_PKIHEADER_set1_sender(CMP_PKIHEADER *hdr, const X509_NAME *nm);
int CMP_PKIHEADER_set1_recipient(CMP_PKIHEADER *hdr, const X509_NAME *nm);
int CMP_PKIHEADER_set_messageTime(CMP_PKIHEADER *hdr);
int CMP_PKIHEADER_set1_senderKID(CMP_PKIHEADER *hdr,
                                 const ASN1_OCTET_STRING *senderKID);
int CMP_CTX_set1_expected_sender(CMP_CTX *ctx, const X509_NAME *name);
int CMP_PKIHEADER_push0_freeText(CMP_PKIHEADER *hdr,
                                 ASN1_UTF8STRING *text);
int CMP_PKIHEADER_push1_freeText(CMP_PKIHEADER *hdr,
                                 ASN1_UTF8STRING *text);
int CMP_PKIHEADER_generalInfo_item_push0(CMP_PKIHEADER *hdr,
                                         const CMP_INFOTYPEANDVALUE *itav);
int CMP_PKIHEADER_init(CMP_CTX *ctx, CMP_PKIHEADER *hdr);
ASN1_BIT_STRING *CMP_calc_protection(const CMP_PKIMESSAGE *pkimessage,
                                     const ASN1_OCTET_STRING *secret,
                                     const EVP_PKEY *pkey);

CMP_PKISTATUSINFO *CMP_REVREPCONTENT_PKIStatusInfo_get(CMP_REVREPCONTENT *rrep,
                                                long reqId);
int CMP_PKIMESSAGE_set_implicitConfirm(CMP_PKIMESSAGE *msg);
int CMP_PKIMESSAGE_check_implicitConfirm(CMP_PKIMESSAGE *msg);
int CMP_PKIMESSAGE_protect(CMP_CTX *ctx, CMP_PKIMESSAGE *msg);
int CMP_PKIMESSAGE_add_extraCerts(CMP_CTX *ctx, CMP_PKIMESSAGE *msg);
int CMP_CERTSTATUS_set_certHash(CMP_CERTSTATUS *certStatus,
                                const X509 *cert);
int CMP_PKIMESSAGE_generalInfo_items_push1(CMP_PKIMESSAGE *msg,
                                         STACK_OF(CMP_INFOTYPEANDVALUE) *itavs);
int CMP_PKIMESSAGE_genm_item_push0(CMP_PKIMESSAGE *msg,
                                   const CMP_INFOTYPEANDVALUE *itav);
int CMP_PKIMESSAGE_genm_items_push1(CMP_PKIMESSAGE *msg,
                                    STACK_OF(CMP_INFOTYPEANDVALUE) *itavs);
int CMP_ITAV_stack_item_push0(STACK_OF(CMP_INFOTYPEANDVALUE) **
                              itav_sk_p, const CMP_INFOTYPEANDVALUE *itav);
CMP_INFOTYPEANDVALUE *CMP_ITAV_new(const ASN1_OBJECT *type,
                                   const ASN1_TYPE *value);
CMP_PKISTATUSINFO *CMP_statusInfo_new(int status, int failure,
                                      const char *text);
long CMP_PKISTATUSINFO_PKIStatus_get(CMP_PKISTATUSINFO *statusInfo);

X509 *CMP_CERTRESPONSE_get_certificate(CMP_CTX *ctx, CMP_CERTRESPONSE *crep);
int CMP_PKIFAILUREINFO_check(ASN1_BIT_STRING *failInfo, int codeBit);
CMP_POLLREP *CMP_POLLREPCONTENT_pollRep_get0(CMP_POLLREPCONTENT *prc, long rid);
CMP_CERTRESPONSE *CMP_CERTREPMESSAGE_certResponse_get0(CMP_CERTREPMESSAGE
                                                       *crepmsg, long rid);
int CMP_PKIMESSAGE_set_bodytype(CMP_PKIMESSAGE *msg, int type);
int CMP_PKIMESSAGE_get_bodytype(const CMP_PKIMESSAGE *msg);
# define CMP_PKISTATUSINFO_BUFLEN 1024
char *CMP_PKISTATUSINFO_snprint(CMP_PKISTATUSINFO *si, char *buf, int bufsize);
STACK_OF(X509) *CMP_build_cert_chain(const STACK_OF(X509) *certs,
                                     const X509 *cert);
int CMP_PKIMESSAGE_check_received(CMP_CTX *ctx, const CMP_PKIMESSAGE *msg,
        int callback_arg,
        int (*allow_unprotected)(const CMP_CTX *, int, const CMP_PKIMESSAGE *));

int CMP_ASN1_OCTET_STRING_set1(ASN1_OCTET_STRING **tgt,
                               const ASN1_OCTET_STRING *src);
int CMP_sk_X509_add1_cert (STACK_OF(X509) *sk, X509 *cert, int not_duplicate);
int CMP_sk_X509_add1_certs(STACK_OF(X509) *sk, const STACK_OF(X509) *certs,
                           int no_self_signed, int no_duplicates);
int CMP_X509_STORE_add1_certs(X509_STORE *store, STACK_OF(X509) *certs,
                              int only_self_signed);
STACK_OF(X509) *CMP_X509_STORE_get1_certs(const X509_STORE *store);

/* cmp_vfy.c */
int CMP_validate_msg(CMP_CTX *ctx, const CMP_PKIMESSAGE *msg);
int CMP_validate_cert_path(const CMP_CTX *ctx, const X509_STORE *trusted_store,
                           const X509 *cert, int defer_errors);
int CMP_print_cert_verify_cb(int ok, X509_STORE_CTX *ctx);

/*
 * from cmp_http.c
 */
/*
 * TODO dvo: push generic defs upstream with extended load_cert_crl_http(),
 * simplifying also other uses, e.g., in query_responder() in apps/ocsp.c
 */
# ifndef OPENSSL_NO_SOCK
int socket_wait(int fd, int for_read, int timeout);
int bio_wait(BIO *bio, int timeout);
int bio_connect(BIO *bio, int timeout);
# endif
# if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
typedef int (*http_fn)(OCSP_REQ_CTX *rctx,ASN1_VALUE **resp);
int bio_http(BIO *bio, OCSP_REQ_CTX *rctx, http_fn fn, ASN1_VALUE **resp,
             time_t max_time);
int CMP_PKIMESSAGE_http_perform(CMP_CTX *ctx, const CMP_PKIMESSAGE *msg,
                                CMP_PKIMESSAGE **out);
# endif

/* from cmp_ses.c */

X509 *CMP_exec_IR_ses(CMP_CTX *ctx);
X509 *CMP_exec_CR_ses(CMP_CTX *ctx);
X509 *CMP_exec_KUR_ses(CMP_CTX *ctx);
X509 *CMP_exec_P10CR_ses(CMP_CTX *ctx);
int CMP_exec_RR_ses(CMP_CTX *ctx);
STACK_OF(CMP_INFOTYPEANDVALUE) *CMP_exec_GENM_ses(CMP_CTX *ctx);

/* from cmp_asn.c */
void CMP_INFOTYPEANDVALUE_set(CMP_INFOTYPEANDVALUE *itav,
                              const ASN1_OBJECT *type,
                              const ASN1_TYPE *value);
ASN1_OBJECT *CMP_INFOTYPEANDVALUE_get0_type(CMP_INFOTYPEANDVALUE *itav);
ASN1_TYPE *CMP_INFOTYPEANDVALUE_get0_value(CMP_INFOTYPEANDVALUE *itav);

/* from cmp_ctx.c */
CMP_CTX *CMP_CTX_create(void);
int CMP_CTX_init(CMP_CTX *ctx);
X509_STORE *CMP_CTX_get0_trustedStore(CMP_CTX *ctx);
int CMP_CTX_set0_trustedStore(CMP_CTX *ctx, X509_STORE *store);
/*
 * There must *not* be a space between STACK_OFand (X509), otherwise mkdef.pl
 * does not recognize it correctly which leads to the file not being global in
 * the shared object when building with GNU.
 */
STACK_OF(X509) *CMP_CTX_get0_untrusted_certs(CMP_CTX *ctx);
int CMP_CTX_set1_untrusted_certs(CMP_CTX *ctx, const STACK_OF(X509) *certs);
void CMP_CTX_delete(CMP_CTX *ctx);
int CMP_CTX_set_error_cb(CMP_CTX *ctx, cmp_log_cb_t cb);
int CMP_CTX_set_debug_cb(CMP_CTX *ctx, cmp_log_cb_t cb);
int CMP_CTX_set_certConf_cb(CMP_CTX *ctx, cmp_certConf_cb_t cb);
int CMP_CTX_set1_referenceValue(CMP_CTX *ctx, const unsigned char *ref,
                                size_t len);
int CMP_CTX_set1_secretValue(CMP_CTX *ctx, const unsigned char *sec,
                             const size_t len);
int CMP_CTX_set1_srvCert(CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set1_clCert(CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set1_oldClCert(CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set1_p10CSR(CMP_CTX *ctx, const X509_REQ *csr);
int CMP_CTX_set1_issuer(CMP_CTX *ctx, const X509_NAME *name);
int CMP_CTX_set1_subjectName(CMP_CTX *ctx, const X509_NAME *name);
int CMP_CTX_set1_recipient(CMP_CTX *ctx, const X509_NAME *name);
int CMP_CTX_subjectAltName_push1(CMP_CTX *ctx, const GENERAL_NAME *name);
STACK_OF(X509) *CMP_CTX_caPubs_get1(CMP_CTX *ctx);
X509 *CMP_CTX_caPubs_pop(CMP_CTX *ctx);
int CMP_CTX_caPubs_num(CMP_CTX *ctx);
int CMP_CTX_set1_caPubs(CMP_CTX *ctx, STACK_OF(X509) *caPubs);
int CMP_CTX_policyOID_push1(CMP_CTX *ctx, const char *policyOID);
int CMP_CTX_geninfo_itav_push0(CMP_CTX *ctx, const CMP_INFOTYPEANDVALUE *itav);
int CMP_CTX_genm_itav_push0(CMP_CTX *ctx, const CMP_INFOTYPEANDVALUE *itav);

int CMP_CTX_set1_extraCertsOut(CMP_CTX *ctx, STACK_OF(X509) *extraCertsOut);
int CMP_CTX_extraCertsOut_push1(CMP_CTX *ctx, const X509 *val);
int CMP_CTX_extraCertsOut_num(CMP_CTX *ctx);
STACK_OF(X509) *CMP_CTX_extraCertsIn_get1(CMP_CTX *ctx);
int CMP_CTX_set1_extraCertsIn(CMP_CTX *ctx, STACK_OF(X509) *extraCertsIn);
X509 *CMP_CTX_extraCertsIn_pop(CMP_CTX *ctx);
int CMP_CTX_extraCertsIn_num(CMP_CTX *ctx);

int CMP_CTX_set1_newClCert(CMP_CTX *ctx, const X509 *cert);
X509 *CMP_CTX_get0_newClCert(CMP_CTX *ctx);
int CMP_CTX_set0_pkey(CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set1_pkey(CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set0_newPkey(CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set1_newPkey(CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set1_transactionID(CMP_CTX *ctx, const ASN1_OCTET_STRING *id);
int CMP_CTX_set1_recipNonce(CMP_CTX *ctx, const ASN1_OCTET_STRING *nonce);
int CMP_CTX_set1_last_senderNonce(CMP_CTX *ctx, const ASN1_OCTET_STRING *nonce);
int CMP_CTX_set1_serverName(CMP_CTX *ctx, const char *name);
int CMP_CTX_set_serverPort(CMP_CTX *ctx, int port);
int CMP_CTX_set1_proxyName(CMP_CTX *ctx, const char *name);
int CMP_CTX_set_proxyPort(CMP_CTX *ctx, int port);
int CMP_CTX_set0_tlsBIO(CMP_CTX *ctx, BIO *sbio);
BIO *CMP_CTX_get0_tlsBIO(CMP_CTX *ctx);
int CMP_CTX_set_transfer_cb(CMP_CTX *ctx, cmp_transfer_cb_t cb);
int CMP_CTX_set_transfer_cb_arg(CMP_CTX *ctx, void *opts);
void *CMP_CTX_get_transfer_cb_arg(CMP_CTX *ctx);
int CMP_CTX_set0_reqExtensions(CMP_CTX *ctx, X509_EXTENSIONS *exts);
int CMP_CTX_reqExtensions_have_SAN(CMP_CTX *ctx);
int CMP_CTX_set1_serverPath(CMP_CTX *ctx, const char *path);
int CMP_CTX_set_failInfoCode(CMP_CTX *ctx, CMP_PKIFAILUREINFO *failInfo);
unsigned long CMP_CTX_failInfoCode_get(CMP_CTX *ctx);
long CMP_CTX_status_get(CMP_CTX *ctx);
CMP_PKIFREETEXT *CMP_CTX_statusString_get(CMP_CTX *ctx);
# define CMP_CTX_OPT_MSGTIMEOUT 0
# define CMP_CTX_OPT_MAXPOLLTIME 1
# define CMP_CTX_OPT_SUBJECTALTNAME_CRITICAL 2
# define CMP_CTX_PERMIT_TA_IN_EXTRACERTS_FOR_IR 3
# define CMP_CTX_OPT_POPOMETHOD 4
# define CMP_CTX_OPT_DIGEST_ALGNID 5
# define CMP_CTX_OPT_REVOCATION_REASON 6
# define CMP_CTX_OPT_IMPLICITCONFIRM 7
# define CMP_CTX_OPT_DISABLECONFIRM 8
# define CMP_CTX_OPT_UNPROTECTED_ERRORS 9
# define CMP_CTX_OPT_UNPROTECTED_REQUESTS 10
# define CMP_CTX_OPT_VALIDITYDAYS 11
# define CMP_CTX_OPT_IGNORE_KEYUSAGE 12
# define CMP_CTX_OPT_SUBJECTALTNAME_NODEFAULT 13
# define CMP_CTX_OPT_POLICIES_CRITICAL 14
int CMP_CTX_set_option(CMP_CTX *ctx, const int opt, const int val);
# if 0
int CMP_CTX_push_freeText(CMP_CTX *ctx, const char *text);
# endif

int CMP_CTX_error_cb(const char *str, size_t len, void *u);
void CMP_printf(const CMP_CTX *ctx, const char *fmt, ...);

/* BIO definitions */
# define d2i_CMP_PKIMESSAGE_bio(bp, p) \
         ASN1_d2i_bio_of(CMP_PKIMESSAGE, CMP_PKIMESSAGE_new,\
                         d2i_CMP_PKIMESSAGE, bp, p)
# define i2d_CMP_PKIMESSAGE_bio(bp, o) \
         ASN1_i2d_bio_of(CMP_PKIMESSAGE, i2d_CMP_PKIMESSAGE, bp, o)
# define d2i_CMP_PROTECTEDPART_bio(bp, p) \
         ASN1_d2i_bio_of(CMP_PROTECTEDPART, CMP_PROTECTEDPART_new, \
                         d2i_CMP_PROTECTEDPART, bp, p)
# define i2d_CMP_PROTECTEDPART_bio(bp, o) \
         ASN1_i2d_bio_of(CMP_PROTECTEDPART, i2d_CMP_PROTECTEDPART, bp, o)
CMP_PKIMESSAGE *d2i_CMP_PKIMESSAGE(CMP_PKIMESSAGE **,
                                   const unsigned char **, long);
int i2d_CMP_PKIMESSAGE(CMP_PKIMESSAGE *, unsigned char **);
void CMP_PKIMESSAGE_free(CMP_PKIMESSAGE *msg);

# ifdef  __cplusplus
}
# endif
#endif /* fndef HEADER_CMP_H */

#if OPENSSL_VERSION_NUMBER < 0x10101000L && !defined(HEADER_CMP_ERROR_CODES)
# define HEADER_CMP_ERROR_CODES
# ifdef  __cplusplus
extern "C" {
# endif
/* BEGIN ERROR CODES */
# ifdef  __cplusplus
}
# endif
#endif
