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
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
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
#  endif
#  if OPENSSL_VERSION_NUMBER < 0x10100006L
typedef int (*OPENSSL_sk_compfunc)(const void *, const void *);
typedef void (*OPENSSL_sk_freefunc)(void *);
typedef void *(*OPENSSL_sk_copyfunc)(void *);
#   define OPENSSL_STACK _STACK
#   define DECLARE_STACK_OF DEFINE_STACK_OF
#   define OPENSSL_sk_value sk_value
#   define OPENSSL_sk_num sk_num
#   define OPENSSL_sk_new sk_new
#   define OPENSSL_sk_new_null sk_new_null
#   define OPENSSL_sk_free sk_free
#   define OPENSSL_sk_zero sk_zero
#   define OPENSSL_sk_delete sk_delete
#   define OPENSSL_sk_delete_ptr sk_delete_ptr
#   define OPENSSL_sk_push sk_push
#   define OPENSSL_sk_unshift sk_unshift
#   define OPENSSL_sk_pop sk_pop
#   define OPENSSL_sk_shift sk_shift
#   define OPENSSL_sk_pop_free sk_pop_free
#   define OPENSSL_sk_insert sk_insert
#   define OPENSSL_sk_set sk_set
#   define OPENSSL_sk_find sk_find
#   define OPENSSL_sk_find_ex sk_find_ex
#   define OPENSSL_sk_sort sk_sort
#   define OPENSSL_sk_is_sorted sk_is_sorted
#   define OPENSSL_sk_dup sk_dup
#   define OPENSSL_sk_deep_copy sk_deep_copy
#   define OPENSSL_sk_set_cmp_func sk_set_cmp_func
#  endif
#  if OPENSSL_VERSION_NUMBER < 0x10101000L
#   define OPENSSL_sk_new_reserve(f,n) sk_new(f) /* sorry, no reservation */
#   define OPENSSL_sk_reserve(sk,n) 1 /* sorry, no-op */
#  endif
#  include <openssl/ossl_typ.h>
#  include <openssl/x509.h>
#  include <openssl/x509v3.h>
#  include <openssl/safestack.h>
#  if OPENSSL_VERSION_NUMBER >= 0x10101000L || OPENSSL_API_COMPAT < 0x10100000L
#   include <openssl/crmferr.h>
#  endif

#  if OPENSSL_VERSION_NUMBER < 0x10100000L
/*#   define ERR_LIB_CRMF  55
  #   define CRMFerr(f,r) ERR_PUT_error(ERR_LIB_CRMF,(f),(r),__FILE__,__LINE__)
  #   define ERR_R_PASSED_INVALID_ARGUMENT CRMF_R_NULL_ARGUMENT
*/
#   define uint64_t unsigned long
#   ifndef DEFINE_STACK_OF
#    define DEFINE_STACK_OF(T) DECLARE_STACK_OF(T)
#   endif
#   define static_ASN1_SEQUENCE_END(T) ASN1_SEQUENCE_END(T)
#   define ASN1_R_TOO_SMALL ASN1_R_INVALID_NUMBER
#   define ASN1_R_TOO_LARGE ASN1_R_INVALID_NUMBER
#  endif
#  if OPENSSL_VERSION_NUMBER < 0x10100002L
#   define DEFINE_LHASH_OF DECLARE_LHASH_OF
#  endif
#  if OPENSSL_VERSION_NUMBER < 0x10100005L
#   define X509_PUBKEY_get0(x)((x)->pkey)
#  endif

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

typedef struct OSSL_crmf_encrypetedvalue_st OSSL_CRMF_ENCRYPTEDVALUE;
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
int OSSL_CRMF_ASN1_get_int(int *pr, const ASN1_INTEGER *a); /* TODO move to crypto/asn1/a_int.c, adapting its name */
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
