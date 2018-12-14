/*
 * Copyright 2007-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CRMF implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

#ifndef OSSL_HEADER_CRMF_H
# define OSSL_HEADER_CRMF_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_CRMF
#  include <openssl/opensslv.h>
#  if OPENSSL_VERSION_NUMBER < 0x10100002L
#   define ossl_inline __inline
#   define OPENSSL_FILE __FILE__
#   define OPENSSL_LINE __LINE__
#   define EVP_MD_CTX_new()      EVP_MD_CTX_create()
#   define EVP_MD_CTX_reset(ctx) EVP_MD_CTX_init((ctx))
#   define EVP_MD_CTX_free(ctx)  EVP_MD_CTX_destroy((ctx))
#   ifndef CMP_STANDALONE
#    define DEFINE_STACK_OF DECLARE_STACK_OF
#   endif
#  endif

#  ifdef CMP_STANDALONE
#   if OPENSSL_VERSION_NUMBER < 0x10101000L
#    define OPENSSL_sk_new_reserve(f,n) sk_new(f) /* sorry, no reservation */
#    define OPENSSL_sk_reserve(sk,n) 1 /* sorry, no-op */
#   endif
#   if OPENSSL_VERSION_NUMBER < 0x10100006L
#    include <openssl/safestack_backport.h>
#   endif
#  endif

#  ifdef CMP_STANDALONE
#   if OPENSSL_VERSION_NUMBER < 0x10101000L
#    include <openssl/err.h>
int ERR_load_strings_const(const ERR_STRING_DATA *str);
#   endif
#   undef  ERR_LIB_CRMF
#   define ERR_LIB_CRMF  (ERR_LIB_USER-2)
#   undef  CRMFerr
#   define CRMFerr(f,r) ERR_PUT_error(ERR_LIB_CRMF,(f),(r),__FILE__,__LINE__)
#   undef  ERR_LIB_CMP
#   define ERR_LIB_CMP  (ERR_LIB_USER-1)
#   undef  CMPerr
#   define CMPerr(f,r) ERR_PUT_error(ERR_LIB_CMP,(f),(r),__FILE__,__LINE__)
#  endif

#  include <openssl/safestack.h>
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L || defined(CMP_STANDALONE)
#  include <openssl/crmferr.h>
#  endif
#  include <openssl/x509v3.h> /* for GENERAL_NAME etc. */

#  if OPENSSL_VERSION_NUMBER < 0x10100000L
#    define ERR_R_PASSED_INVALID_ARGUMENT CRMF_R_NULL_ARGUMENT
#   define int64_t long
#   define ASN1_INTEGER_get_int64(pvar, a) ((*(pvar)=ASN1_INTEGER_get(a)) != -1)
#   define static_ASN1_SEQUENCE_END(T) ASN1_SEQUENCE_END(T)
#   define ASN1_R_TOO_SMALL ASN1_R_INVALID_NUMBER
#   define ASN1_R_TOO_LARGE ASN1_R_INVALID_NUMBER
#   define X509_ALGOR_cmp(a,b) (OBJ_cmp((a)->algorithm, (b)->algorithm) ? OBJ_cmp((a)->algorithm, (b)->algorithm) : (!(a)->parameter && !(b)->parameter) ? 0 : ASN1_TYPE_cmp(a->parameter, b->parameter))
#  endif
#  if OPENSSL_VERSION_NUMBER < 0x10100005L
#   define X509_PUBKEY_get0(x)((x)->pkey)
#  endif
#  if OPENSSL_VERSION_NUMBER < 0x10101000L
#   define OBJ_obj2nid(alg) \
    (OBJ_obj2nid(alg) == NID_hmac_md5  ? NID_hmacWithMD5 : \
     OBJ_obj2nid(alg) == NID_hmac_sha1 ? NID_hmacWithSHA1 : OBJ_obj2nid(alg))
    /*
     * OID 1.3.6.1.5.5.8.1.2 associated with NID_hmac_sha1 is explicitly
     * mentioned in RFC 4210 and RFC 3370, but NID_hmac_sha1 is not included in
     * builitin_pbe[] of crypto/evp/evp_pbe.c
     */
    /*
     * NID_hmac_md5 not included in builtin_pbe[] of crypto/evp/evp_pbe.c as
     * it is not explicitly referenced in the RFC it might not be used by any
     * implementation although its OID 1.3.6.1.5.5.8.1.1 it is in the same OID
     * branch as NID_hmac_sha1
     */
#  endif

/* explicit #includes not strictly needed since implied by the above: */
#  include <openssl/ossl_typ.h>
#  include <openssl/x509.h>

#  ifdef  __cplusplus
extern "C" {
#  endif

#  define OSSL_CRMF_POPOPRIVKEY_THISMESSAGE          0
#  define OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE    1
#  define OSSL_CRMF_POPOPRIVKEY_DHMAC                2
#  define OSSL_CRMF_POPOPRIVKEY_AGREEMAC             3
#  define OSSL_CRMF_POPOPRIVKEY_ENCRYPTEDKEY         4

#  define OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT       0
#  define OSSL_CRMF_SUBSEQUENTMESSAGE_CHALLENGERESP  1

typedef struct OSSL_crmf_encryptedvalue_st OSSL_CRMF_ENCRYPTEDVALUE;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_ENCRYPTEDVALUE)
typedef struct OSSL_crmf_msg_st OSSL_CRMF_MSG;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_MSG)
DEFINE_STACK_OF(OSSL_CRMF_MSG)
typedef struct OSSL_crmf_attributetypeandvalue_st OSSL_CRMF_ATTRIBUTETYPEANDVALUE;
typedef struct OSSL_crmf_pbmparameter_st OSSL_CRMF_PBMPARAMETER;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_PBMPARAMETER)
typedef struct OSSL_crmf_poposigningkey_st OSSL_CRMF_POPOSIGNINGKEY;
typedef struct OSSL_crmf_certrequest_st OSSL_CRMF_CERTREQUEST;
typedef struct OSSL_crmf_certid_st OSSL_CRMF_CERTID;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_CERTID)
DEFINE_STACK_OF(OSSL_CRMF_CERTID)

typedef struct OSSL_crmf_pkipublicationinfo_st OSSL_CRMF_PKIPUBLICATIONINFO;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_PKIPUBLICATIONINFO)
typedef struct OSSL_crmf_singlepubinfo_st OSSL_CRMF_SINGLEPUBINFO;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_SINGLEPUBINFO)
typedef struct OSSL_crmf_certtemplate_st OSSL_CRMF_CERTTEMPLATE;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_CERTTEMPLATE)
typedef STACK_OF(OSSL_CRMF_MSG) OSSL_CRMF_MSGS;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_MSGS)

typedef struct OSSL_crmf_optionalvalidity_st OSSL_CRMF_OPTIONALVALIDITY;

/* crmf_pbm.c */
OSSL_CRMF_PBMPARAMETER *OSSL_CRMF_pbmp_new(size_t slen, int owfnid,
                                           int itercnt, int macnid);
int OSSL_CRMF_pbm_new(const OSSL_CRMF_PBMPARAMETER *pbmp,
                      const unsigned char *msg, size_t msglen,
                      const unsigned char *sec, size_t seclen,
                      unsigned char **mac, unsigned int *maclen);

/* crmf_lib.c */
int OSSL_CRMF_MSG_set1_regCtrl_regToken(OSSL_CRMF_MSG *msg,
                                        const ASN1_UTF8STRING *tok);
int OSSL_CRMF_MSG_set1_regCtrl_authenticator(OSSL_CRMF_MSG *msg,
                                             const ASN1_UTF8STRING *auth);
int OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(
                                               OSSL_CRMF_PKIPUBLICATIONINFO *pi,
                                               OSSL_CRMF_SINGLEPUBINFO *spi);
#  define OSSL_CRMF_PUB_METHOD_DONTCARE 0
#  define OSSL_CRMF_PUB_METHOD_X500     1
#  define OSSL_CRMF_PUB_METHOD_WEB      2
#  define OSSL_CRMF_PUB_METHOD_LDAP     3
int OSSL_CRMF_MSG_set0_SinglePubInfo(OSSL_CRMF_SINGLEPUBINFO *spi,
                                     int method, GENERAL_NAME *nm);
#  define OSSL_CRMF_PUB_ACTION_DONTPUBLISH   0
#  define OSSL_CRMF_PUB_ACTION_PLEASEPUBLISH 1
int OSSL_CRMF_MSG_set_PKIPublicationInfo_action(
                                  OSSL_CRMF_PKIPUBLICATIONINFO *pi, int action);
int OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo(OSSL_CRMF_MSG *msg,
                                        const OSSL_CRMF_PKIPUBLICATIONINFO *pi);
int OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey(OSSL_CRMF_MSG *msg,
                                               const X509_PUBKEY *pubkey);
int OSSL_CRMF_MSG_set1_regCtrl_oldCertID(OSSL_CRMF_MSG *msg,
                                         const OSSL_CRMF_CERTID *cid);
OSSL_CRMF_CERTID *OSSL_CRMF_CERTID_gen(const X509_NAME *issuer,
                                       const ASN1_INTEGER *serial);

int OSSL_CRMF_MSG_set1_regInfo_utf8Pairs(OSSL_CRMF_MSG *msg,
                                         const ASN1_UTF8STRING *utf8pairs);
int OSSL_CRMF_MSG_set1_regInfo_certReq(OSSL_CRMF_MSG *msg,
                                       const OSSL_CRMF_CERTREQUEST *cr);

int OSSL_CRMF_MSG_set_validity(OSSL_CRMF_MSG *crm, time_t from, time_t to);
int OSSL_CRMF_MSG_set_certReqId(OSSL_CRMF_MSG *crm, int rid);
int OSSL_CRMF_MSG_get_certReqId(OSSL_CRMF_MSG *crm);
int OSSL_CRMF_MSG_set0_extensions(OSSL_CRMF_MSG *crm, X509_EXTENSIONS *exts);

int OSSL_CRMF_MSG_push0_extension(OSSL_CRMF_MSG *crm, const X509_EXTENSION *ext);
#  define OSSL_CRMF_POPO_NONE      -1
#  define OSSL_CRMF_POPO_RAVERIFIED 0
#  define OSSL_CRMF_POPO_SIGNATURE  1
#  define OSSL_CRMF_POPO_KEYENC     2
#  define OSSL_CRMF_POPO_KEYAGREE   3
int OSSL_CRMF_MSG_create_popo(OSSL_CRMF_MSG *crm, const EVP_PKEY *pkey,
                              int dgst, int ppmtd);
int OSSL_CRMF_MSGS_verify_popo(const OSSL_CRMF_MSGS *reqs,
                               int rid, int acceptRAVerified);
OSSL_CRMF_CERTTEMPLATE *OSSL_CRMF_MSG_get0_tmpl(const OSSL_CRMF_MSG *crm);
ASN1_INTEGER *OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(OSSL_CRMF_CERTTEMPLATE *t);
X509_NAME *OSSL_CRMF_CERTTEMPLATE_get0_issuer(OSSL_CRMF_CERTTEMPLATE *tmpl);
int OSSL_CRMF_CERTTEMPLATE_fill(OSSL_CRMF_CERTTEMPLATE *tmpl,
                                const EVP_PKEY *pubkey,
                                const X509_NAME *subject,
                                const X509_NAME *issuer,
                                const ASN1_INTEGER *serial);
X509 *OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(OSSL_CRMF_ENCRYPTEDVALUE *ecert,
                                            EVP_PKEY *pkey);

#  ifdef __cplusplus
}
#  endif
# endif /* !defined OPENSSL_NO_CRMF */
#endif /* !defined OSSL_HEADER_CRMF_H */


#if OPENSSL_VERSION_NUMBER < 0x10101000L && !defined(OSSL_HEADER_CRMF_ERROR_CODES)
# define OSSL_HEADER_CRMF_ERROR_CODES
# ifdef  __cplusplus
extern "C" {
# endif
/* BEGIN ERROR CODES */
# ifdef  __cplusplus
}
# endif
#endif
