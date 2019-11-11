/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CMP_H
# define OPENSSL_CMP_H

# include <openssl/opensslconf.h>
# ifndef OPENSSL_NO_CMP

#  include <openssl/crmf.h>

#  ifdef CMP_STANDALONE
#   include <openssl/err.h>
#  endif
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L || defined(CMP_STANDALONE)
#  include <openssl/cmperr.h>
#  endif

#  if OPENSSL_VERSION_NUMBER < 0x10101000L
#   define X509_V_ERR_OCSP_VERIFY_NEEDED 73 /* Need OCSP verification */
#   define X509_V_ERR_OCSP_VERIFY_FAILED 74 /* Could not verify cert via OCSP */
#  endif
#  if OPENSSL_VERSION_NUMBER >= 0x10100007L
#  define OPENSSL_CMP_CONST const
#  else
#   define OPENSSL_CMP_CONST
#  endif
#  if OPENSSL_VERSION_NUMBER < 0x10100004L
#   define OPENSSL_FILE __FILE__
#   define OPENSSL_LINE __LINE__
#  endif
#  if OPENSSL_VERSION_NUMBER >= 0x30000000L
#   define OpenSSL_version_num() ((unsigned long) \
                                  ((OPENSSL_version_major()<<28) \
                                  |(OPENSSL_version_minor()<<20) \
                                  |(OPENSSL_version_patch()<<4L) \
                                  |_OPENSSL_VERSION_PRE_RELEASE ))
#  endif
#  if OPENSSL_VERSION_NUMBER < 0x10100000L
#   define OpenSSL_version_num SSLeay
#   define X509_get0_subject_key_id(x) (X509_check_purpose((x),-1,-1),(x)->skid)
#   define X509_STORE_CTX_get1_crls X509_STORE_get1_crls
#   define OPENSSL_strndup strndup
#   define SSL_AD_REASON_OFFSET 1000
#   define TLS1_AD_UNKNOWN_CA     48
#  endif
#  if OPENSSL_VERSION_NUMBER < 0x10100005L
#   define X509_REQ_get0_pubkey(x) X509_PUBKEY_get0((x)->req_info->pubkey)
#  endif
#  if OPENSSL_VERSION_NUMBER < 0x10100006L
#   define EVP_PKEY_up_ref(x)((x)->references++)
    typedef int (*X509_STORE_CTX_check_revocation_fn) (X509_STORE_CTX *ctx);
#   ifdef CMP_STANDALONE
DECLARE_STACK_OF(ASN1_UTF8STRING)
#   endif
#  endif
#  if OPENSSL_VERSION_NUMBER < 0x10100007L
#   define X509_get0_notBefore X509_get_notBefore
#   define X509_get0_notAfter X509_get_notAfter
#   define X509_get_issuer_name(x) ((x)->cert_info->issuer)
#   define X509_get0_serialNumber(x) ((x)->cert_info->serialNumber)
#   define X509_get0_extensions(x) ((x)->cert_info->extensions)
#  endif
#  if OPENSSL_VERSION_NUMBER < 0x1010001fL
#   define OPENSSL_zalloc(num) CRYPTO_zalloc(num, __FILE__, __LINE__)
#   include <string.h>
static inline void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    void *ret = CRYPTO_malloc((int)num, file, line);
    if(ret)
        memset(ret, 0, num);
    return ret;
}
#   define X509_up_ref(x)((x)->references++)
#   define X509_STORE_up_ref(x)((x)->references++)
#   define ASN1_STRING_get0_data ASN1_STRING_data
#   define X509_OBJECT_get0_X509(obj) ((obj) == NULL || \
                          (obj)->type != X509_LU_X509 ? NULL : (obj)->data.x509)
#   define X509_STORE_get0_objects(store) ((store)->objs)
#   define X509_STORE_CTX_get0_untrusted(ctx) ((ctx)->untrusted)
#   define X509_STORE_CTX_get0_chain X509_STORE_CTX_get_chain
#   define X509_STORE_CTX_get_by_subject X509_STORE_get_by_subject
#   define X509_STORE_CTX_set_current_cert(ctx, x) { (ctx)->current_cert = (x); }
#   define X509_STORE_CTX_set_error_depth(ctx, n) { (ctx)->error_depth = (n); }
    typedef int (*X509_STORE_CTX_verify_cb)(int, X509_STORE_CTX *);
#   define X509_STORE_CTX_get_verify_cb(ctx) ((ctx)->verify_cb)
#   define X509_STORE_CTX_set0_verified_chain(ctx, sk) { \
        sk_X509_pop_free((ctx)->chain, X509_free); (ctx)->chain = (sk); }
#   define X509_STORE_CTX_get_check_revocation(ctx) ((ctx)->check_revocation)
#   define X509_STORE_get_verify_cb(store) ((store)->verify_cb)
#   define X509_STORE_get0_param(ctx) ((ctx)->param)
#   define X509_STORE_set_ex_data(ctx, idx, data) \
       CRYPTO_set_ex_data(&(ctx)->ex_data, (idx), (data))
#   define X509_STORE_get_ex_data(ctx, idx) \
       CRYPTO_get_ex_data(&(ctx)->ex_data, (idx))
#   define X509_STORE_get_check_revocation(st)    ((st)->check_revocation)
#   define X509_STORE_set_check_revocation(st, f) {(st)->check_revocation=(f);}
#   if OPENSSL_VERSION_NUMBER < 0x10002090L
#    define X509_V_ERR_STORE_LOOKUP 70 /* from x509_vfy.h */
#   endif
#   define X509_STORE_set_lookup_crls X509_STORE_set_lookup_crls_cb
#   define X509_VERIFY_PARAM_get_time(param) ((param)->check_time)
#   define X509_V_FLAG_NO_CHECK_TIME 0x200000
#   define X509_set_proxy_flag(x) { (x)->ex_flags |= EXFLAG_PROXY; }
#   define X509_CRL_get0_lastUpdate X509_CRL_get_lastUpdate
#   define X509_CRL_get0_nextUpdate X509_CRL_get_nextUpdate
#   define X509_get_key_usage(x) ((X509_check_purpose((x), -1, -1), \
           (x)->ex_flags & EXFLAG_KUSAGE) ? (x)->ex_kusage : (unsigned long) ~0)
#   define TLS_client_method SSLv23_client_method
#  endif

/* explicit #includes not strictly needed since implied by the above: */
#  include <openssl/ossl_typ.h>
#  include <openssl/safestack.h>
#  include <openssl/x509.h>
#  include <openssl/x509v3.h>
#  ifdef  __cplusplus
extern "C" {
#  endif

#  define OSSL_CMP_PVNO 2

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
#  define OSSL_CMP_PKIFAILUREINFO_badAlg 0
#  define OSSL_CMP_PKIFAILUREINFO_badMessageCheck 1
#  define OSSL_CMP_PKIFAILUREINFO_badRequest 2
#  define OSSL_CMP_PKIFAILUREINFO_badTime 3
#  define OSSL_CMP_PKIFAILUREINFO_badCertId 4
#  define OSSL_CMP_PKIFAILUREINFO_badDataFormat 5
#  define OSSL_CMP_PKIFAILUREINFO_wrongAuthority 6
#  define OSSL_CMP_PKIFAILUREINFO_incorrectData 7
#  define OSSL_CMP_PKIFAILUREINFO_missingTimeStamp 8
#  define OSSL_CMP_PKIFAILUREINFO_badPOP 9
#  define OSSL_CMP_PKIFAILUREINFO_certRevoked 10
#  define OSSL_CMP_PKIFAILUREINFO_certConfirmed 11
#  define OSSL_CMP_PKIFAILUREINFO_wrongIntegrity 12
#  define OSSL_CMP_PKIFAILUREINFO_badRecipientNonce 13
#  define OSSL_CMP_PKIFAILUREINFO_timeNotAvailable 14
#  define OSSL_CMP_PKIFAILUREINFO_unacceptedPolicy 15
#  define OSSL_CMP_PKIFAILUREINFO_unacceptedExtension 16
#  define OSSL_CMP_PKIFAILUREINFO_addInfoNotAvailable 17
#  define OSSL_CMP_PKIFAILUREINFO_badSenderNonce 18
#  define OSSL_CMP_PKIFAILUREINFO_badCertTemplate 19
#  define OSSL_CMP_PKIFAILUREINFO_signerNotTrusted 20
#  define OSSL_CMP_PKIFAILUREINFO_transactionIdInUse 21
#  define OSSL_CMP_PKIFAILUREINFO_unsupportedVersion 22
#  define OSSL_CMP_PKIFAILUREINFO_notAuthorized 23
#  define OSSL_CMP_PKIFAILUREINFO_systemUnavail 24
#  define OSSL_CMP_PKIFAILUREINFO_systemFailure 25
#  define OSSL_CMP_PKIFAILUREINFO_duplicateCertReq 26
#  define OSSL_CMP_PKIFAILUREINFO_MAX 26
#  define OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN \
    ( (1<<(OSSL_CMP_PKIFAILUREINFO_MAX+1)) - 1)
#  if OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN > INT_MAX
#   error  CMP_PKIFAILUREINFO_MAX bit pattern does not fit in type int
#  endif

typedef ASN1_BIT_STRING OSSL_CMP_PKIFAILUREINFO;

#  define OSSL_CMP_CTX_FAILINFO_badAlg (1 << 0)
#  define OSSL_CMP_CTX_FAILINFO_badMessageCheck (1 << 1)
#  define OSSL_CMP_CTX_FAILINFO_badRequest (1 << 2)
#  define OSSL_CMP_CTX_FAILINFO_badTime (1 << 3)
#  define OSSL_CMP_CTX_FAILINFO_badCertId (1 << 4)
#  define OSSL_CMP_CTX_FAILINFO_badDataFormat (1 << 5)
#  define OSSL_CMP_CTX_FAILINFO_wrongAuthority (1 << 6)
#  define OSSL_CMP_CTX_FAILINFO_incorrectData (1 << 7)
#  define OSSL_CMP_CTX_FAILINFO_missingTimeStamp (1 << 8)
#  define OSSL_CMP_CTX_FAILINFO_badPOP (1 << 9)
#  define OSSL_CMP_CTX_FAILINFO_certRevoked (1 << 10)
#  define OSSL_CMP_CTX_FAILINFO_certConfirmed (1 << 11)
#  define OSSL_CMP_CTX_FAILINFO_wrongIntegrity (1 << 12)
#  define OSSL_CMP_CTX_FAILINFO_badRecipientNonce (1 << 13)
#  define OSSL_CMP_CTX_FAILINFO_timeNotAvailable (1 << 14)
#  define OSSL_CMP_CTX_FAILINFO_unacceptedPolicy (1 << 15)
#  define OSSL_CMP_CTX_FAILINFO_unacceptedExtension (1 << 16)
#  define OSSL_CMP_CTX_FAILINFO_addInfoNotAvailable (1 << 17)
#  define OSSL_CMP_CTX_FAILINFO_badSenderNonce (1 << 18)
#  define OSSL_CMP_CTX_FAILINFO_badCertTemplate (1 << 19)
#  define OSSL_CMP_CTX_FAILINFO_signerNotTrusted (1 << 20)
#  define OSSL_CMP_CTX_FAILINFO_transactionIdInUse (1 << 21)
#  define OSSL_CMP_CTX_FAILINFO_unsupportedVersion (1 << 22)
#  define OSSL_CMP_CTX_FAILINFO_notAuthorized (1 << 23)
#  define OSSL_CMP_CTX_FAILINFO_systemUnavail (1 << 24)
#  define OSSL_CMP_CTX_FAILINFO_systemFailure (1 << 25)
#  define OSSL_CMP_CTX_FAILINFO_duplicateCertReq (1 << 26)

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
#  define OSSL_CMP_PKISTATUS_accepted 0
#  define OSSL_CMP_PKISTATUS_grantedWithMods 1
#  define OSSL_CMP_PKISTATUS_rejection 2
#  define OSSL_CMP_PKISTATUS_waiting 3
#  define OSSL_CMP_PKISTATUS_revocationWarning 4
#  define OSSL_CMP_PKISTATUS_revocationNotification 5
#  define OSSL_CMP_PKISTATUS_keyUpdateWarning 6

typedef ASN1_INTEGER OSSL_CMP_PKISTATUS;
DECLARE_ASN1_ITEM(OSSL_CMP_PKISTATUS)

#  define OSSL_CMP_CERTORENCCERT_CERTIFICATE 0
#  define OSSL_CMP_CERTORENCCERT_ENCRYPTEDCERT 1

/* data type declarations */
typedef struct ossl_cmp_ctx_st OSSL_CMP_CTX;
typedef struct ossl_cmp_pkiheader_st OSSL_CMP_PKIHEADER;
DECLARE_ASN1_FUNCTIONS(OSSL_CMP_PKIHEADER)
typedef struct ossl_cmp_msg_st OSSL_CMP_MSG;
DECLARE_ASN1_ENCODE_FUNCTIONS(OSSL_CMP_MSG, OSSL_CMP_MSG, OSSL_CMP_MSG)
typedef struct ossl_cmp_certstatus_st OSSL_CMP_CERTSTATUS;
DEFINE_STACK_OF(OSSL_CMP_CERTSTATUS)
typedef struct ossl_cmp_itav_st OSSL_CMP_ITAV;
DEFINE_STACK_OF(OSSL_CMP_ITAV)
typedef struct ossl_cmp_revrepcontent_st OSSL_CMP_REVREPCONTENT;
typedef struct ossl_cmp_pkisi_st OSSL_CMP_PKISI;
DEFINE_STACK_OF(OSSL_CMP_PKISI)
typedef struct ossl_cmp_certrepmessage_st OSSL_CMP_CERTREPMESSAGE;
DEFINE_STACK_OF(OSSL_CMP_CERTREPMESSAGE)
typedef struct ossl_cmp_pollrep_st OSSL_CMP_POLLREP;
typedef STACK_OF(OSSL_CMP_POLLREP) OSSL_CMP_POLLREPCONTENT;
typedef struct ossl_cmp_certresponse_st OSSL_CMP_CERTRESPONSE;
DEFINE_STACK_OF(OSSL_CMP_CERTRESPONSE)
typedef STACK_OF(ASN1_UTF8STRING) OSSL_CMP_PKIFREETEXT;

#include <openssl/cmp_util.h>
/*
 * function DECLARATIONS
 */
/* from cmp_asn.c */
OSSL_CMP_ITAV *OSSL_CMP_ITAV_create(ASN1_OBJECT *type, ASN1_TYPE *value);
void OSSL_CMP_ITAV_set0(OSSL_CMP_ITAV *itav, ASN1_OBJECT *type,
                        ASN1_TYPE *value);
ASN1_OBJECT *OSSL_CMP_ITAV_get0_type(const OSSL_CMP_ITAV *itav);
ASN1_TYPE *OSSL_CMP_ITAV_get0_value(const OSSL_CMP_ITAV *itav);
int OSSL_CMP_ITAV_push0_stack_item(STACK_OF(OSSL_CMP_ITAV) **itav_sk_p,
                                   OSSL_CMP_ITAV *itav);
void OSSL_CMP_ITAV_free(OSSL_CMP_ITAV *itav);
void OSSL_CMP_MSG_free(OSSL_CMP_MSG *msg);

/* from cmp_ctx.c */
OSSL_CMP_CTX *OSSL_CMP_CTX_new(void);
void OSSL_CMP_CTX_free(OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_reinit(OSSL_CMP_CTX *ctx);
/* various CMP options: */
#  define OSSL_CMP_OPT_LOG_VERBOSITY 0
#  define OSSL_CMP_OPT_MSGTIMEOUT 1
#  define OSSL_CMP_OPT_TOTALTIMEOUT 2
#  define OSSL_CMP_OPT_VALIDITYDAYS 3
#  define OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT 4
#  define OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL 5
#  define OSSL_CMP_OPT_POLICIES_CRITICAL 6
#  define OSSL_CMP_OPT_POPOMETHOD 7
#  define OSSL_CMP_OPT_DIGEST_ALGNID 8
#  define OSSL_CMP_OPT_OWF_ALGNID 9
#  define OSSL_CMP_OPT_MAC_ALGNID 10
#  define OSSL_CMP_OPT_REVOCATION_REASON 11
#  define OSSL_CMP_OPT_IMPLICITCONFIRM 12
#  define OSSL_CMP_OPT_DISABLECONFIRM 13
#  define OSSL_CMP_OPT_UNPROTECTED_SEND 14
#  define OSSL_CMP_OPT_UNPROTECTED_ERRORS 15
#  define OSSL_CMP_OPT_IGNORE_KEYUSAGE 16
#  define OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR 17
int OSSL_CMP_CTX_set_option(OSSL_CMP_CTX *ctx, int opt, int val);
int OSSL_CMP_CTX_get_option(const OSSL_CMP_CTX *ctx, int opt);
/* CMP-specific callback for logging and outputting the error queue: */
int OSSL_CMP_CTX_set_log_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_log_cb_t cb);
#  define OSSL_CMP_CTX_set_log_verbosity(ctx, level) \
    OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_LOG_VERBOSITY, level)
void OSSL_CMP_CTX_print_errors(OSSL_CMP_CTX *ctx);
/* message transfer: */
int OSSL_CMP_CTX_set1_serverPath(OSSL_CMP_CTX *ctx, const char *path);
int OSSL_CMP_CTX_set1_serverName(OSSL_CMP_CTX *ctx, const char *name);
int OSSL_CMP_CTX_set_serverPort(OSSL_CMP_CTX *ctx, int port);
int OSSL_CMP_CTX_set1_proxyName(OSSL_CMP_CTX *ctx, const char *name);
int OSSL_CMP_CTX_set_proxyPort(OSSL_CMP_CTX *ctx, int port);
#  define OSSL_CMP_DEFAULT_PORT 80
typedef BIO *(*OSSL_cmp_http_cb_t) (OSSL_CMP_CTX *ctx, BIO *hbio,
                                    unsigned long detail);
int OSSL_CMP_CTX_set_http_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_http_cb_t cb);
int OSSL_CMP_CTX_set_http_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
void *OSSL_CMP_CTX_get_http_cb_arg(const OSSL_CMP_CTX *ctx);
typedef int (*OSSL_cmp_transfer_cb_t) (OSSL_CMP_CTX *ctx,
                                       const OSSL_CMP_MSG *req,
                                       OSSL_CMP_MSG **res);
int OSSL_CMP_CTX_set_transfer_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_transfer_cb_t cb);
int OSSL_CMP_CTX_set_transfer_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
void *OSSL_CMP_CTX_get_transfer_cb_arg(const OSSL_CMP_CTX *ctx);
/* server authentication: */
int OSSL_CMP_CTX_set1_srvCert(OSSL_CMP_CTX *ctx, X509 *cert);
int OSSL_CMP_CTX_set1_expected_sender(OSSL_CMP_CTX *ctx, const X509_NAME *name);
int OSSL_CMP_CTX_set0_trustedStore(OSSL_CMP_CTX *ctx, X509_STORE *store);
X509_STORE *OSSL_CMP_CTX_get0_trustedStore(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set1_untrusted_certs(OSSL_CMP_CTX *ctx, STACK_OF(X509) *certs);
STACK_OF(X509) *OSSL_CMP_CTX_get0_untrusted_certs(const OSSL_CMP_CTX *ctx);
/* client authentication: */
int OSSL_CMP_CTX_set1_clCert(OSSL_CMP_CTX *ctx, X509 *cert);
int OSSL_CMP_CTX_set1_pkey(OSSL_CMP_CTX *ctx, EVP_PKEY *pkey);
int OSSL_CMP_CTX_set1_referenceValue(OSSL_CMP_CTX *ctx,
                                     const unsigned char *ref, int len);
int OSSL_CMP_CTX_set1_secretValue(OSSL_CMP_CTX *ctx, const unsigned char *sec,
                                  const int len);
/* CMP message header and extra certificates: */
int OSSL_CMP_CTX_set1_recipient(OSSL_CMP_CTX *ctx, const X509_NAME *name);
int OSSL_CMP_CTX_push0_geninfo_ITAV(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav);
int OSSL_CMP_CTX_set1_extraCertsOut(OSSL_CMP_CTX *ctx,
                                    STACK_OF(X509) *extraCertsOut);
/* certificate template: */
int OSSL_CMP_CTX_set0_newPkey(OSSL_CMP_CTX *ctx, const EVP_PKEY *pkey);
int OSSL_CMP_CTX_set1_newPkey(OSSL_CMP_CTX *ctx, const EVP_PKEY *pkey);
EVP_PKEY *OSSL_CMP_CTX_get0_newPkey(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_set1_issuer(OSSL_CMP_CTX *ctx, const X509_NAME *name);
int OSSL_CMP_CTX_set1_subjectName(OSSL_CMP_CTX *ctx, const X509_NAME *name);
int OSSL_CMP_CTX_push1_subjectAltName(OSSL_CMP_CTX *ctx, const GENERAL_NAME *name);
int OSSL_CMP_CTX_set0_reqExtensions(OSSL_CMP_CTX *ctx, X509_EXTENSIONS *exts);
int OSSL_CMP_CTX_reqExtensions_have_SAN(OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_policyOID_push1(OSSL_CMP_CTX *ctx, const char *policyOID);
int OSSL_CMP_CTX_set1_oldCert(OSSL_CMP_CTX *ctx, X509 *cert);
int OSSL_CMP_CTX_set1_p10CSR(OSSL_CMP_CTX *ctx, const X509_REQ *csr);
/* misc body contents: */
int OSSL_CMP_CTX_push0_genm_ITAV(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav);
/* certificate confirmation: */
typedef int (*OSSL_cmp_certConf_cb_t) (OSSL_CMP_CTX *ctx, X509 *cert,
                                       int fail_info, const char **txt);
int OSSL_CMP_CTX_set_certConf_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_certConf_cb_t cb);
int OSSL_CMP_CTX_set_certConf_cb_arg(OSSL_CMP_CTX *ctx, void *arg);
void *OSSL_CMP_CTX_get_certConf_cb_arg(const OSSL_CMP_CTX *ctx);
/* result fetching: */
int OSSL_CMP_CTX_get_status(const OSSL_CMP_CTX *ctx);
OSSL_CMP_PKIFREETEXT *OSSL_CMP_CTX_get0_statusString(const OSSL_CMP_CTX *ctx);
int OSSL_CMP_CTX_get_failInfoCode(const OSSL_CMP_CTX *ctx);
#  define OSSL_CMP_PKISI_BUFLEN 1024
X509 *OSSL_CMP_CTX_get0_newCert(const OSSL_CMP_CTX *ctx);
STACK_OF(X509) *OSSL_CMP_CTX_get1_caPubs(const OSSL_CMP_CTX *ctx);
STACK_OF(X509) *OSSL_CMP_CTX_get1_extraCertsIn(const OSSL_CMP_CTX *ctx);
/* support application-level CMP debugging in cmp.c: */
int OSSL_CMP_CTX_set1_transactionID(OSSL_CMP_CTX *ctx,
                                    const ASN1_OCTET_STRING *id);
int OSSL_CMP_CTX_set1_senderNonce(OSSL_CMP_CTX *ctx,
                                  const ASN1_OCTET_STRING *nonce);

/* from cmp_status.c */
char *OSSL_CMP_PKISI_snprint(OSSL_CMP_PKISI *si, char *buf, int bufsize);
#  define OSSL_CMP_PKISI_BUFLEN 1024

/* from cmp_hdr.c */
/* support application-level CMP debugging in cmp.c: */
ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_transactionID(const OSSL_CMP_PKIHEADER *hdr);
ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_recipNonce(const OSSL_CMP_PKIHEADER *hdr);

/* from cmp_msg.c */
/* BIO definitions */
#  define OSSL_d2i_CMP_MSG_bio(bp, p) \
    ASN1_d2i_bio_of(OSSL_CMP_MSG, OSSL_CMP_MSG_new, d2i_OSSL_CMP_MSG, bp, p)
#  define OSSL_i2d_CMP_MSG_bio(bp, o) \
    ASN1_i2d_bio_of(OSSL_CMP_MSG, i2d_OSSL_CMP_MSG, bp, o)
/* support application-level CMP debugging in cmp.c: */
OSSL_CMP_PKIHEADER *OSSL_CMP_MSG_get0_header(const OSSL_CMP_MSG *msg);

/* from cmp_vfy.c */
/* TODO better push OSSL_CMP_cmp_timeframe() to crypto/x509/x509_vfy.c */
int OSSL_CMP_cmp_timeframe(const ASN1_TIME *start,
                           const ASN1_TIME *end, X509_VERIFY_PARAM *vpm);
int OSSL_CMP_validate_msg(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg);
int OSSL_CMP_validate_cert_path(OSSL_CMP_CTX *ctx,
                                X509_STORE *trusted_store,
                                const STACK_OF(X509) *extra_untrusted,
                                X509 *cert, int defer_errors);
int OSSL_CMP_print_cert_verify_cb(int ok, X509_STORE_CTX *ctx);

/*
 * from cmp_http.c
 */
/*
 * TODO dvo: push generic defs upstream with extended load_cert_crl_http(),
 * simplifying also other uses, e.g., in query_responder() in apps/ocsp.c
 */
#  if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
int OSSL_CMP_proxy_connect(BIO *bio, OSSL_CMP_CTX *ctx,
                           BIO *bio_err, const char *prog);
int OSSL_CMP_MSG_http_perform(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg,
                              OSSL_CMP_MSG **out);
int OSSL_CMP_load_cert_crl_http_timeout(const char *url, int req_timeout,
                                        X509 **pcert, X509_CRL **pcrl,
                                        BIO *bio_err);
#  endif

/* from cmp_client.c */
X509 *OSSL_CMP_exec_IR_ses(OSSL_CMP_CTX *ctx);
X509 *OSSL_CMP_exec_CR_ses(OSSL_CMP_CTX *ctx);
X509 *OSSL_CMP_exec_P10CR_ses(OSSL_CMP_CTX *ctx);
X509 *OSSL_CMP_exec_KUR_ses(OSSL_CMP_CTX *ctx);
X509 *OSSL_CMP_exec_RR_ses(OSSL_CMP_CTX *ctx);
STACK_OF(OSSL_CMP_ITAV) *OSSL_CMP_exec_GENM_ses(OSSL_CMP_CTX *ctx);
int OSSL_CMP_certConf_cb(OSSL_CMP_CTX *ctx, X509 *cert, int fail_info,
                         const char **text);

/* from cmp_server.c */
typedef struct OSSL_cmp_srv_ctx_st OSSL_CMP_SRV_CTX;
int OSSL_CMP_mock_server_perform(OSSL_CMP_CTX *cmp_ctx, const OSSL_CMP_MSG *req,
                                 OSSL_CMP_MSG **res);
OSSL_CMP_SRV_CTX *OSSL_CMP_SRV_CTX_new(void);
void OSSL_CMP_SRV_CTX_free(OSSL_CMP_SRV_CTX *srv_ctx);
OSSL_CMP_CTX *OSSL_CMP_SRV_CTX_get0_ctx(const OSSL_CMP_SRV_CTX *srv_ctx);
int OSSL_CMP_SRV_CTX_set1_certOut(OSSL_CMP_SRV_CTX *srv_ctx, X509 *cert);
int OSSL_CMP_SRV_CTX_set1_chainOut(OSSL_CMP_SRV_CTX *srv_ctx,
                                   STACK_OF(X509) *chain);
int OSSL_CMP_SRV_CTX_set1_caPubsOut(OSSL_CMP_SRV_CTX *srv_ctx,
                                    STACK_OF(X509) *caPubs);
int OSSL_CMP_SRV_CTX_set_statusInfo(OSSL_CMP_SRV_CTX *srv_ctx, int status,
                                    int fail_info, const char *text);
int OSSL_CMP_SRV_CTX_set_checkAfterTime(OSSL_CMP_SRV_CTX *srv_ctx, int64_t sec);
int OSSL_CMP_SRV_CTX_set_pollCount(OSSL_CMP_SRV_CTX *srv_ctx, int64_t count);
int OSSL_CMP_SRV_CTX_set_send_error(OSSL_CMP_SRV_CTX *srv_ctx, int error);
int OSSL_CMP_SRV_CTX_set_send_unprotected_errors(OSSL_CMP_SRV_CTX *srv_ctx,
                                                 int value);
int OSSL_CMP_SRV_CTX_set_accept_unprotected(OSSL_CMP_SRV_CTX *srv_ctx,
                                            int value);
int OSSL_CMP_SRV_CTX_set_accept_raverified(OSSL_CMP_SRV_CTX *srv_ctx,
                                           int raverified);
int OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(OSSL_CMP_SRV_CTX *srv_ctx,
                                                int value);

#  ifdef  __cplusplus
}
#  endif
# endif /* !defined OPENSSL_NO_CMP */
#endif /* !defined OPENSSL_CMP_H */
#if OPENSSL_VERSION_NUMBER < 0x10101000L && !defined(OSSL_HEADER_CMP_ERROR_CODES)
# define OSSL_HEADER_CMP_ERROR_CODES
# ifdef  __cplusplus
extern "C" {
# endif
/* BEGIN ERROR CODES */
# ifdef  __cplusplus
}
# endif
#endif
