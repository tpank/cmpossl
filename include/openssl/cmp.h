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
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define DEFINE_STACK_OF(T) DECLARE_STACK_OF(T)
#endif

# include <openssl/crmf.h>

# define CMP_VERSION 2L

# ifdef  __cplusplus
extern "C" {
# endif

/* PKIFailureInfo ::= BIT STRING {
-- since we can fail in more than one way!
-- More codes may be added in the future if/when required.
        badAlg                          (0),
        -- unrecognized or unsupported Algorithm Identifier
        badMessageCheck         (1),
        -- integrity check failed (e.g., signature did not verify)
        badRequest                      (2),
        -- transaction not permitted or supported
        badTime                         (3),
        -- messageTime was not sufficiently close to the system time,
        -- as defined by local policy
        badCertId                       (4),
        -- no certificate could be found matching the provided criteria
        badDataFormat           (5),
        -- the data submitted has the wrong format
        wrongAuthority          (6),
        -- the authority indicated in the request is different from the
        -- one creating the response token
        incorrectData           (7),
        -- the requester's data is incorrect (for notary services)
        missingTimeStamp        (8),
        -- when the timestamp is missing but should be there
        -- (by policy)
        badPOP                          (9),
        -- the proof-of-possession failed
        certRevoked             (10),
               -- the certificate has already been revoked
        certConfirmed           (11),
               -- the certificate has already been confirmed
        wrongIntegrity          (12),
               -- invalid integrity, password based instead of signature or
               -- vice versa
        badRecipientNonce       (13),
               -- invalid recipient nonce, either missing or wrong value
        timeNotAvailable        (14),
               -- the TSA's time source is not available
        unacceptedPolicy        (15),
               -- the requested TSA policy is not supported by the TSA.
        unacceptedExtension (16),
               -- the requested extension is not supported by the TSA.
        addInfoNotAvailable (17),
               -- the additional information requested could not be
               -- understood or is not available
        badSenderNonce          (18),
               -- invalid sender nonce, either missing or wrong size
        badCertTemplate         (19),
               -- invalid cert. template or missing mandatory information
        signerNotTrusted        (20),
               -- signer of the message unknown or not trusted
        transactionIdInUse  (21),
               -- the transaction identifier is already in use
        unsupportedVersion  (22),
               -- the version of the message is not supported
        notAuthorized           (23),
               -- the sender was not authorized to make the preceding
               -- request or perform the preceding action
        systemUnavail           (24),
        -- the request cannot be handled due to system unavailability
        systemFailure           (25),
        -- the request cannot be handled due to system failure
        duplicateCertReq        (26)
        -- certificate cannot be issued because a duplicate
        -- certificate already exists
}
*/
# define CMP_PKIFAILUREINFO_badAlg               0
# define CMP_PKIFAILUREINFO_badMessageCheck      1
# define CMP_PKIFAILUREINFO_badRequest           2
# define CMP_PKIFAILUREINFO_badTime              3
# define CMP_PKIFAILUREINFO_badCertId            4
# define CMP_PKIFAILUREINFO_badDataFormat        5
# define CMP_PKIFAILUREINFO_wrongAuthority       6
# define CMP_PKIFAILUREINFO_incorrectData        7
# define CMP_PKIFAILUREINFO_missingTimeStamp     8
# define CMP_PKIFAILUREINFO_badPOP               9
# define CMP_PKIFAILUREINFO_certRevoked         10
# define CMP_PKIFAILUREINFO_certConfirmed       11
# define CMP_PKIFAILUREINFO_wrongIntegrity      12
# define CMP_PKIFAILUREINFO_badRecipientNonce   13
# define CMP_PKIFAILUREINFO_timeNotAvailable    14
# define CMP_PKIFAILUREINFO_unacceptedPolicy    15
# define CMP_PKIFAILUREINFO_unacceptedExtension 16
# define CMP_PKIFAILUREINFO_addInfoNotAvailable 17
# define CMP_PKIFAILUREINFO_badSenderNonce      18
# define CMP_PKIFAILUREINFO_badCertTemplate     19
# define CMP_PKIFAILUREINFO_signerNotTrusted    20
# define CMP_PKIFAILUREINFO_transactionIdInUse  21
# define CMP_PKIFAILUREINFO_unsupportedVersion  22
# define CMP_PKIFAILUREINFO_notAuthorized       23
# define CMP_PKIFAILUREINFO_systemUnavail       24
# define CMP_PKIFAILUREINFO_systemFailure       25
# define CMP_PKIFAILUREINFO_duplicateCertReq    26
# define CMP_PKIFAILUREINFO_MAX                 26
typedef ASN1_BIT_STRING CMP_PKIFAILUREINFO;

# define CMP_CTX_FAILINFO_badAlg               (1 << 0)
# define CMP_CTX_FAILINFO_badMessageCheck      (1 << 1)
# define CMP_CTX_FAILINFO_badRequest           (1 << 2)
# define CMP_CTX_FAILINFO_badTime              (1 << 3)
# define CMP_CTX_FAILINFO_badCertId            (1 << 4)
# define CMP_CTX_FAILINFO_badDataFormat        (1 << 5)
# define CMP_CTX_FAILINFO_wrongAuthority       (1 << 6)
# define CMP_CTX_FAILINFO_incorrectData        (1 << 7)
# define CMP_CTX_FAILINFO_missingTimeStamp     (1 << 8)
# define CMP_CTX_FAILINFO_badPOP               (1 << 9)
# define CMP_CTX_FAILINFO_certRevoked          (1 << 10)
# define CMP_CTX_FAILINFO_certConfirmed        (1 << 11)
# define CMP_CTX_FAILINFO_wrongIntegrity       (1 << 12)
# define CMP_CTX_FAILINFO_badRecipientNonce    (1 << 13)
# define CMP_CTX_FAILINFO_timeNotAvailable     (1 << 14)
# define CMP_CTX_FAILINFO_unacceptedPolicy     (1 << 15)
# define CMP_CTX_FAILINFO_unacceptedExtension  (1 << 16)
# define CMP_CTX_FAILINFO_addInfoNotAvailable  (1 << 17)
# define CMP_CTX_FAILINFO_badSenderNonce       (1 << 18)
# define CMP_CTX_FAILINFO_badCertTemplate      (1 << 19)
# define CMP_CTX_FAILINFO_signerNotTrusted     (1 << 20)
# define CMP_CTX_FAILINFO_transactionIdInUse   (1 << 21)
# define CMP_CTX_FAILINFO_unsupportedVersion   (1 << 22)
# define CMP_CTX_FAILINFO_notAuthorized        (1 << 23)
# define CMP_CTX_FAILINFO_systemUnavail        (1 << 24)
# define CMP_CTX_FAILINFO_systemFailure        (1 << 25)
# define CMP_CTX_FAILINFO_duplicateCertReq     (1 << 26)

/* PKIStatus ::= INTEGER {
        accepted                                (0),
        -- you got exactly what you asked for
        grantedWithMods                (1),
        -- you got something like what you asked for; the
        -- requester is responsible for ascertaining the differences
        rejection                              (2),
        -- you don't get it, more information elsewhere in the message
        waiting                                (3),
        -- the request body part has not yet been processed; expect to
        -- hear more later (note: proper handling of this status
        -- response MAY use the polling req/rep PKIMessages specified
        -- in Section 5.3.22; alternatively, polling in the underlying
        -- transport layer MAY have some utility in this regard)
        revocationWarning              (4),
        -- this message contains a warning that a revocation is
        -- imminent
        revocationNotification (5),
        -- notification that a revocation has occurred
        keyUpdateWarning               (6)
        -- update already done for the oldCertId specified in
        -- CertReqMsg
} */
# define CMP_PKISTATUS_accepted                0
# define CMP_PKISTATUS_grantedWithMods         1
# define CMP_PKISTATUS_rejection               2
# define CMP_PKISTATUS_waiting                 3
# define CMP_PKISTATUS_revocationWarning       4
# define CMP_PKISTATUS_revocationNotification  5
# define CMP_PKISTATUS_keyUpdateWarning        6

typedef ASN1_INTEGER CMP_PKISTATUS;

# define CMP_CERTORENCCERT_ERROR        -1
# define CMP_CERTORENCCERT_CERTIFICATE   0
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
typedef struct cmp_certresponse_st CMP_CERTRESPONSE;
DEFINE_STACK_OF(CMP_CERTSTATUS)
DEFINE_STACK_OF(CMP_INFOTYPEANDVALUE)
DECLARE_ASN1_FUNCTIONS(CMP_INFOTYPEANDVALUE)
DEFINE_STACK_OF(CMP_PKISTATUSINFO)
DEFINE_STACK_OF(CMP_CERTREPMESSAGE)
DEFINE_STACK_OF(CMP_CERTRESPONSE)


/* ########################################################################## *
 * context DECLARATIONS
 * ########################################################################## */
typedef void (*cmp_logfn_t) (const char *msg);
typedef int (*cmp_certConfFn_t) (CMP_CTX *ctx, int status, const X509 *cert);
typedef int (*cert_verify_cb_t) (int ok, X509_STORE_CTX *ctx);
typedef int (*cmp_transfer_fn_t) (const CMP_CTX *ctx, const CMP_PKIMESSAGE *req,
                                  CMP_PKIMESSAGE **res);
typedef STACK_OF (ASN1_UTF8STRING) CMP_PKIFREETEXT;

/* ########################################################################## *
 * function DECLARATIONS
 * ########################################################################## */
/* cmp_msg.c */
CMP_PKIMESSAGE *CMP_certreq_new(CMP_CTX *ctx, int bodytype, int err_code);
CMP_PKIMESSAGE *CMP_rr_new(CMP_CTX *ctx);
CMP_PKIMESSAGE *CMP_certConf_new(CMP_CTX *ctx, int failure, const char *text);
CMP_PKIMESSAGE *CMP_genm_new(CMP_CTX *ctx);
CMP_PKIMESSAGE *CMP_error_new(CMP_CTX *ctx, CMP_PKISTATUSINFO *si,
                              int errorCode, CMP_PKIFREETEXT *errorDetails);
CMP_PKIMESSAGE *CMP_pollReq_new(CMP_CTX *ctx, int reqId);

/* cmp_lib.c */
long CMP_REVREPCONTENT_PKIStatus_get(CMP_REVREPCONTENT *revRep,
                                     long reqId);
int CMP_PKIHEADER_set_version(CMP_PKIHEADER *hdr, int version);
int CMP_PKIHEADER_set1_recipient(CMP_PKIHEADER *hdr, const X509_NAME *nm);
int CMP_PKIHEADER_set1_transactionID(CMP_PKIHEADER *hdr,
                                     const ASN1_OCTET_STRING
                                     *transactionID);
int CMP_PKIHEADER_new_senderNonce(CMP_PKIHEADER *hdr);
int CMP_PKIHEADER_set1_recipNonce(CMP_PKIHEADER *hdr,
                                  const ASN1_OCTET_STRING *recipNonce);
int CMP_PKIHEADER_set1_sender(CMP_PKIHEADER *hdr, const X509_NAME *nm);
int CMP_PKIHEADER_set1_senderKID(CMP_PKIHEADER *hdr,
                                 const ASN1_OCTET_STRING *senderKID);
int CMP_PKIHEADER_set_messageTime(CMP_PKIHEADER *hdr);
int CMP_PKIMESSAGE_set_implicitConfirm(CMP_PKIMESSAGE *msg);
int CMP_PKIMESSAGE_check_implicitConfirm(CMP_PKIMESSAGE *msg);
int CMP_PKIHEADER_push0_freeText(CMP_PKIHEADER *hdr,
                                 ASN1_UTF8STRING *text);
int CMP_PKIHEADER_push1_freeText(CMP_PKIHEADER *hdr,
                                 ASN1_UTF8STRING *text);
int CMP_PKIHEADER_init(CMP_CTX *ctx, CMP_PKIHEADER *hdr);
ASN1_BIT_STRING *CMP_calc_protection_pbmac(CMP_PKIMESSAGE *pkimessage,
                                           const ASN1_OCTET_STRING
                                           *secret);
ASN1_BIT_STRING *CMP_calc_protection_sig(CMP_PKIMESSAGE *pkimessage,
                                         EVP_PKEY *pkey);
int CMP_PKIMESSAGE_protect(CMP_CTX *ctx, CMP_PKIMESSAGE *msg);
int CMP_PKIMESSAGE_add_extraCerts(CMP_CTX *ctx, CMP_PKIMESSAGE *msg);
int CMP_CERTSTATUS_set_certHash(CMP_CERTSTATUS *certStatus,
                                const X509 *cert);
int CMP_PKIHEADER_generalInfo_item_push0(CMP_PKIHEADER *hdr,
                                         const CMP_INFOTYPEANDVALUE *itav);
int CMP_PKIMESSAGE_generalInfo_items_push1(CMP_PKIMESSAGE *msg,
                                         STACK_OF(CMP_INFOTYPEANDVALUE) *itavs);
int CMP_PKIMESSAGE_genm_item_push0(CMP_PKIMESSAGE *msg,
                                   const CMP_INFOTYPEANDVALUE *itav);
int CMP_PKIMESSAGE_genm_items_push1(CMP_PKIMESSAGE *msg,
                                         STACK_OF(CMP_INFOTYPEANDVALUE) *itavs);
int CMP_ITAV_stack_item_push0(STACK_OF (CMP_INFOTYPEANDVALUE) **
                              itav_sk_p,
                              const CMP_INFOTYPEANDVALUE *itav);
CMP_INFOTYPEANDVALUE *CMP_ITAV_new(const ASN1_OBJECT *type,
                                   const ASN1_TYPE *value);
CMP_PKISTATUSINFO *CMP_statusInfo_new(int status, int failure,
                                      const char *text);
long CMP_PKISTATUSINFO_PKIStatus_get(CMP_PKISTATUSINFO *statusInfo);

X509 *CMP_CERTRESPONSE_get_certificate(CMP_CTX *ctx, CMP_CERTRESPONSE *crep);
int CMP_PKIFAILUREINFO_check(ASN1_BIT_STRING *failInfo, int codeBit);
CMP_CERTRESPONSE *CMP_CERTREPMESSAGE_certResponse_get0(CMP_CERTREPMESSAGE
                                                       *crepmsg, long rid);
int CMP_PKIMESSAGE_set_bodytype(CMP_PKIMESSAGE *msg, int type);
int CMP_PKIMESSAGE_get_bodytype(CMP_PKIMESSAGE *msg);
#define CMP_PKISTATUSINFO_BUFLEN 1024
char *CMP_PKISTATUSINFO_snprint(CMP_PKISTATUSINFO *si, char *buf, int bufsize);
ASN1_OCTET_STRING *CMP_get_cert_subject_key_id(const X509 *cert);
STACK_OF(X509) * CMP_build_cert_chain(X509_STORE *store, X509 *cert);

/* cmp_vfy.c */
int CMP_validate_msg(CMP_CTX *ctx, CMP_PKIMESSAGE *msg);
int CMP_validate_cert_path(CMP_CTX *ctx, X509_STORE *trusted_store,
                           X509_STORE *untrusted_store, X509 *cert);

/* from cmp_http.c */
int CMP_PKIMESSAGE_http_perform(const CMP_CTX *ctx,
                                const CMP_PKIMESSAGE *msg,
                                CMP_PKIMESSAGE **out);

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
int CMP_CTX_set0_untrustedStore(CMP_CTX *ctx, X509_STORE *store);
int CMP_CTX_set0_crls(CMP_CTX *ctx, STACK_OF(X509_CRL) *crls);
void CMP_CTX_delete(CMP_CTX *ctx);
int CMP_CTX_set_error_callback(CMP_CTX *ctx, cmp_logfn_t cb);
int CMP_CTX_set_debug_callback(CMP_CTX *ctx, cmp_logfn_t cb);
int CMP_CTX_set_certConf_callback(CMP_CTX *ctx, cmp_certConfFn_t cb);
int CMP_CTX_set_certVerify_callback(CMP_CTX *ctx, cert_verify_cb_t cb);
int CMP_CTX_set1_referenceValue(CMP_CTX *ctx, const unsigned char *ref,
                                size_t len);
int CMP_CTX_set1_secretValue(CMP_CTX *ctx, const unsigned char *sec,
                             const size_t len);
int CMP_CTX_set1_regToken(CMP_CTX *ctx, const char *regtoken,
                          const size_t len);
int CMP_CTX_set1_srvCert(CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set1_clCert(CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set1_oldClCert(CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set1_p10CSR(CMP_CTX *ctx, const X509_REQ *csr);
int CMP_CTX_set1_issuer(CMP_CTX *ctx, const X509_NAME *name);
int CMP_CTX_set1_subjectName(CMP_CTX *ctx, const X509_NAME *name);
int CMP_CTX_set1_recipient(CMP_CTX *ctx, const X509_NAME *name);
int CMP_CTX_subjectAltName_push1(CMP_CTX *ctx, const GENERAL_NAME *name);
STACK_OF(X509) * CMP_CTX_caPubs_get1(CMP_CTX *ctx);
X509 *CMP_CTX_caPubs_pop(CMP_CTX *ctx);
int CMP_CTX_caPubs_num(CMP_CTX *ctx);
int CMP_CTX_set1_caPubs(CMP_CTX *ctx, const STACK_OF (X509) * caPubs);
int CMP_CTX_policyOID_push1(CMP_CTX *ctx, const char *policyOID);
int CMP_CTX_geninfo_itav_push0(CMP_CTX *ctx, const CMP_INFOTYPEANDVALUE *itav);
int CMP_CTX_genm_itav_push0(CMP_CTX *ctx, const CMP_INFOTYPEANDVALUE *itav);

int CMP_CTX_set1_extraCertsOut(CMP_CTX *ctx,
                               const STACK_OF (X509) * extraCertsOut);
int CMP_CTX_extraCertsOut_push1(CMP_CTX *ctx, const X509 *val);
int CMP_CTX_extraCertsOut_num(CMP_CTX *ctx);
STACK_OF(X509) * CMP_CTX_extraCertsIn_get1(CMP_CTX *ctx);
int CMP_CTX_set1_extraCertsIn(CMP_CTX *ctx,
                              const STACK_OF (X509) * extraCertsIn);
X509 *CMP_CTX_extraCertsIn_pop(CMP_CTX *ctx);
int CMP_CTX_extraCertsIn_num(CMP_CTX *ctx);
int CMP_CTX_loadUntrustedStack(CMP_CTX *ctx, STACK_OF (X509) * stack);

int CMP_CTX_set1_newClCert(CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set0_pkey(CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set1_pkey(CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set0_newPkey(CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set1_newPkey(CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set1_transactionID(CMP_CTX *ctx, const ASN1_OCTET_STRING *id);
int CMP_CTX_set1_recipNonce(CMP_CTX *ctx, const ASN1_OCTET_STRING *nonce);
int CMP_CTX_set1_serverName(CMP_CTX *ctx, const char *name);
int CMP_CTX_set_serverPort(CMP_CTX *ctx, int port);
int CMP_CTX_set1_proxyName(CMP_CTX *ctx, const char *name);
int CMP_CTX_set_proxyPort(CMP_CTX *ctx, int port);
int CMP_CTX_set0_tlsBIO(CMP_CTX *ctx, BIO *sbio);
BIO *CMP_CTX_get0_tlsBIO(CMP_CTX *ctx);
int CMP_CTX_set_msg_transfer(CMP_CTX *ctx, cmp_transfer_fn_t cb);
int CMP_CTX_set0_reqExtensions(CMP_CTX *ctx, X509_EXTENSIONS *exts);
int CMP_CTX_set1_serverPath(CMP_CTX *ctx, const char *path);
int CMP_CTX_set_failInfoCode(CMP_CTX *ctx, CMP_PKIFAILUREINFO * failInfo);
unsigned long CMP_CTX_failInfoCode_get(CMP_CTX *ctx);
CMP_PKIFREETEXT *CMP_CTX_statusString_get(CMP_CTX *ctx);
# define CMP_CTX_OPT_MSGTIMEOUT                 0
# define CMP_CTX_OPT_MAXPOLLTIME                1
# define CMP_CTX_OPT_SUBJECTALTNAME_CRITICAL    2
# define CMP_CTX_PERMIT_TA_IN_EXTRACERTS_FOR_IR 3
# define CMP_CTX_OPT_POPOMETHOD                 4
# define CMP_CTX_OPT_DIGEST_ALGNID              5
# define CMP_CTX_OPT_REVOCATION_REASON          6
# define CMP_CTX_OPT_IMPLICITCONFIRM            7
# define CMP_CTX_OPT_DISABLECONFIRM             8
# define CMP_CTX_OPT_UNPROTECTED_ERRORS         9
# define CMP_CTX_OPT_UNPROTECTED_REQUESTS      10
int CMP_CTX_set_option(CMP_CTX *ctx, const int opt, const int val);
# if 0
int CMP_CTX_push_freeText(CMP_CTX *ctx, const char *text);
# endif

int CMP_CTX_error_callback(const char *str, size_t len, void *u);
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

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_CMP_strings(void);

/* Error codes for the CMP functions. */

/* Function codes. */
# define CMP_F_CMP_CALC_PROTECTION_PBMAC                  101
# define CMP_F_CMP_CALC_PROTECTION_SIG                    102
# define CMP_F_CMP_CERTCONF_NEW                           103
# define CMP_F_CMP_CERTREPMESSAGE_CERTRESPONSE_GET0       104
# define CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1            175
# define CMP_F_CMP_CERTREPMESSAGE_GET_CERTIFICATE         176
# define CMP_F_CMP_CERTREPMESSAGE_PKIFAILUREINFOSTRING_GET0 177
# define CMP_F_CMP_CERTREPMESSAGE_PKIFAILUREINFO_GET0     178
# define CMP_F_CMP_CERTREPMESSAGE_PKISTATUSSTRING_GET0    179
# define CMP_F_CMP_CERTREPMESSAGE_PKISTATUS_GET           180
# define CMP_F_CMP_CERTREQ_NEW                            100
# define CMP_F_CMP_CERTRESPONSE_ENCCERT_GET1              105
# define CMP_F_CMP_CERTRESPONSE_GET_CERTIFICATE           106
# define CMP_F_CMP_CERTRESPONSE_PKIFAILUREINFO_GET0       107
# define CMP_F_CMP_CERTRESPONSE_PKISTATUSSTRING_GET0      108
# define CMP_F_CMP_CERTRESPONSE_PKISTATUS_GET             109
# define CMP_F_CMP_CERTSTATUS_SET_CERTHASH                110
# define CMP_F_CMP_CTX_CAPUBS_GET1                        112
# define CMP_F_CMP_CTX_CAPUBS_NUM                         113
# define CMP_F_CMP_CTX_CAPUBS_POP                         114
# define CMP_F_CMP_CTX_CREATE                             115
# define CMP_F_CMP_CTX_EXTRACERTSIN_GET1                  116
# define CMP_F_CMP_CTX_EXTRACERTSIN_NUM                   117
# define CMP_F_CMP_CTX_EXTRACERTSIN_POP                   118
# define CMP_F_CMP_CTX_EXTRACERTSOUT_NUM                  119
# define CMP_F_CMP_CTX_EXTRACERTSOUT_PUSH1                120
# define CMP_F_CMP_CTX_INIT                               121
# define CMP_F_CMP_CTX_SET0_NEWPKEY                       122
# define CMP_F_CMP_CTX_SET0_PKEY                          123
# define CMP_F_CMP_CTX_SET0_REQEXTENSIONS                 124
# define CMP_F_CMP_CTX_SET0_TLSBIO                        125
# define CMP_F_CMP_CTX_SET1_CAPUBS                        126
# define CMP_F_CMP_CTX_SET1_CLCERT                        127
# define CMP_F_CMP_CTX_SET1_EXTRACERTSIN                  128
# define CMP_F_CMP_CTX_SET1_EXTRACERTSOUT                 129
# define CMP_F_CMP_CTX_SET1_ISSUER                        130
# define CMP_F_CMP_CTX_SET1_NEWCLCERT                     131
# define CMP_F_CMP_CTX_SET1_NEWPKEY                       132
# define CMP_F_CMP_CTX_SET1_OLDCLCERT                     133
# define CMP_F_CMP_CTX_SET1_P10CSR                        193
# define CMP_F_CMP_CTX_SET1_PKEY                          134
# define CMP_F_CMP_CTX_SET1_PROXYNAME                     135
# define CMP_F_CMP_CTX_SET1_RECIPIENT                     136
# define CMP_F_CMP_CTX_SET1_RECIPNONCE                    137
# define CMP_F_CMP_CTX_SET1_REFERENCEVALUE                138
# define CMP_F_CMP_CTX_SET1_REGTOKEN                      139
# define CMP_F_CMP_CTX_SET1_SECRETVALUE                   140
# define CMP_F_CMP_CTX_SET1_SERVERNAME                    141
# define CMP_F_CMP_CTX_SET1_SERVERPATH                    142
# define CMP_F_CMP_CTX_SET1_SRVCERT                       143
# define CMP_F_CMP_CTX_SET1_SUBJECTNAME                   144
# define CMP_F_CMP_CTX_SET1_TRANSACTIONID                 145
# define CMP_F_CMP_CTX_SET_PROXYPORT                      146
# define CMP_F_CMP_CTX_SET_SERVERPORT                     147
# define CMP_F_CMP_CTX_SUBJECTALTNAME_PUSH1               148
# define CMP_F_CMP_DOCERTIFICATEREQUESTSEQ                149
# define CMP_F_CMP_DOGENERALMESSAGESEQ                    150
# define CMP_F_CMP_DOINITIALREQUESTSEQ                    151
# define CMP_F_CMP_DOKEYUPDATEREQUESTSEQ                  152
# define CMP_F_CMP_DOPKCS10CERTIFICATIONREQUESTSEQ        156
# define CMP_F_CMP_DOREVOCATIONREQUESTSEQ                 153
# define CMP_F_CMP_ERROR_NEW                              154
# define CMP_F_CMP_EXEC_CR_SES                            111
# define CMP_F_CMP_EXEC_GENM_SES                          174
# define CMP_F_CMP_EXEC_IR_SES                            181
# define CMP_F_CMP_EXEC_KUR_SES                           182
# define CMP_F_CMP_EXEC_P10CR_SES                         185
# define CMP_F_CMP_EXEC_P10_CR_SES                        183
# define CMP_F_CMP_EXEC_RR_SES                            184
# define CMP_F_CMP_GENM_NEW                               155
# define CMP_F_CMP_PKIHEADER_GENERALINFO_ITEM_PUSH0       158
# define CMP_F_CMP_PKIMESSAGE_GENERALINFO_ITEMS_PUSH1     159
# define CMP_F_CMP_PKIMESSAGE_GENM_ITEMS_PUSH1            160
# define CMP_F_CMP_PKIMESSAGE_GENM_ITEM_PUSH0             161
# define CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM                162
# define CMP_F_CMP_PKIMESSAGE_PROTECT                     163
# define CMP_F_CMP_PKISTATUSINFO_PKISTATUS_GET            164
# define CMP_F_CMP_PKISTATUSINFO_PKISTATUS_GET_STRING     165
# define CMP_F_CMP_POLLREQ_NEW                            166
# define CMP_F_CMP_REVREPCONTENT_PKISTATUS_GET            167
# define CMP_F_CMP_RR_NEW                                 168
# define CMP_F_CMP_VALIDATE_CERT_PATH                     169
# define CMP_F_CMP_VALIDATE_MSG                           170
# define CMP_F_CMP_VERIFY_SIGNATURE                       171
# define CMP_F_EXCHANGE_CERTCONF                          172
# define CMP_F_EXCHANGE_ERROR                             173
# define CMP_F_POLLFORRESPONSE                            157

/* Reason codes. */
# define CMP_R_ALGORITHM_NOT_SUPPORTED                    100
# define CMP_R_BAD_INPUT                                  101
# define CMP_R_CERTIFICATE_NOT_ACCEPTED                   102
# define CMP_R_CERTIFICATE_NOT_FOUND                      103
# define CMP_R_CERTRESPONSE_NOT_FOUND                     104
# define CMP_R_CERT_AND_KEY_DO_NOT_MATCH                  105
# define CMP_R_CONNECT_TIMEOUT                            177
# define CMP_R_CP_NOT_RECEIVED                            106
# define CMP_R_ENCOUNTERED_KEYUPDATEWARNING               107
# define CMP_R_ENCOUNTERED_UNEXPECTED_REVOCATIONNOTIFICATION 108
# define CMP_R_ENCOUNTERED_UNEXPECTED_REVOCATIONWARNING   109
# define CMP_R_ENCOUNTERED_UNSUPPORTED_PKISTATUS          110
# define CMP_R_ENCOUNTERED_WAITING                        111
# define CMP_R_ERROR_CALCULATING_PROTECTION               112
# define CMP_R_ERROR_CREATING_CERTCONF                    113
# define CMP_R_ERROR_CREATING_CR                          114
# define CMP_R_ERROR_CREATING_ERROR                       115
# define CMP_R_ERROR_CREATING_GENM                        116
# define CMP_R_ERROR_CREATING_IR                          117
# define CMP_R_ERROR_CREATING_KUR                         118
# define CMP_R_ERROR_CREATING_P10CR                       179
# define CMP_R_ERROR_CREATING_POLLREQ                     119
# define CMP_R_ERROR_CREATING_REQUEST_MESSAGE             120
# define CMP_R_ERROR_CREATING_RR                          121
# define CMP_R_ERROR_DECODING_CERTIFICATE                 122
# define CMP_R_ERROR_DECODING_MESSAGE                     175
# define CMP_R_ERROR_DECRYPTING_CERTIFICATE               123
# define CMP_R_ERROR_DECRYPTING_ENCCERT                   124
# define CMP_R_ERROR_DECRYPTING_KEY                       125
# define CMP_R_ERROR_DECRYPTING_SYMMETRIC_KEY             126
# define CMP_R_ERROR_NONCES_DO_NOT_MATCH                  127
# define CMP_R_ERROR_PARSING_ERROR_MESSAGE                169
# define CMP_R_ERROR_PARSING_PKISTATUS                    128
# define CMP_R_ERROR_PROTECTING_MESSAGE                   129
# define CMP_R_ERROR_PUSHING_GENERALINFO_ITEM             130
# define CMP_R_ERROR_PUSHING_GENERALINFO_ITEMS            131
# define CMP_R_ERROR_PUSHING_GENM_ITEMS                   132
# define CMP_R_ERROR_REQID_NOT_FOUND                      170
# define CMP_R_ERROR_SENDING_REQUEST                      174
# define CMP_R_ERROR_SETTING_CERTHASH                     133
# define CMP_R_ERROR_STATUS_NOT_FOUND                     134
# define CMP_R_ERROR_TRANSACTIONID_UNMATCHED              135
# define CMP_R_ERROR_VALIDATING_PROTECTION                136
# define CMP_R_FAILED_TO_DECODE_PKIMESSAGE                171
# define CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE               137
# define CMP_R_FAILED_TO_SEND_REQUEST                     138
# define CMP_R_FAIL_EXTRACT_CERT_FROM_CERTREP_WITH_ACCEPT_STATUS 139
# define CMP_R_GENP_NOT_RECEIVED                          140
# define CMP_R_INVALID_ARGS                               141
# define CMP_R_INVALID_CONTENT_TYPE                       172
# define CMP_R_INVALID_CONTEXT                            142
# define CMP_R_INVALID_KEY                                143
# define CMP_R_INVALID_PARAMETERS                         144
# define CMP_R_IP_NOT_RECEIVED                            145
# define CMP_R_KUP_NOT_RECEIVED                           146
# define CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION  147
# define CMP_R_NO_CERTIFICATE_RECEIVED                    173
# define CMP_R_NO_SECRET_VALUE_GIVEN_FOR_PBMAC            148
# define CMP_R_NO_TRUSTED_CERTIFICATES_SET                149
# define CMP_R_NO_VALID_SRVCERT_FOUND                     150
# define CMP_R_NULL_ARGUMENT                              151
# define CMP_R_PKIBODY_ERROR                              152
# define CMP_R_PKICONF_NOT_RECEIVED                       153
# define CMP_R_POLLREP_NOT_RECEIVED                       154
# define CMP_R_READ_TIMEOUT                               178
# define CMP_R_RECEIVED_NEGATIVE_CHECKAFTER_IN_POLLREP    155
# define CMP_R_REQUEST_REJECTED_BY_CA                     156
# define CMP_R_RP_NOT_RECEIVED                            157
# define CMP_R_SERVER_NOT_REACHABLE                       158
# define CMP_R_TLS_SETUP_FAILURE                          176
# define CMP_R_UNABLE_TO_CREATE_CONTEXT                   159
# define CMP_R_UNEXPECTED_PKIBODY                         180
# define CMP_R_UNEXPECTED_PKISTATUS                       160
# define CMP_R_UNKNOWN_ALGORITHM_ID                       161
# define CMP_R_UNKNOWN_CERTTYPE                           162
# define CMP_R_UNKNOWN_PKISTATUS                          163
# define CMP_R_UNSUPPORTED_ALGORITHM                      164
# define CMP_R_UNSUPPORTED_CIPHER                         165
# define CMP_R_UNSUPPORTED_KEY_TYPE                       166
# define CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC      167
# define CMP_R_WRONG_ALGORITHM_OID                        168

# ifdef  __cplusplus
}
# endif
#endif
