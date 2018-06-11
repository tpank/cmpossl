/*
 * Copyright OpenSSL 2007-2018
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Contents licensed under the terms of the OpenSSL license
 * See https://www.openssl.org/source/license.html for details
 *
 * SPDX-License-Identifier: OpenSSL
 *
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

#ifndef HEADER_CRMF_H
# define HEADER_CRMF_H

# include <openssl/opensslconf.h>

# include <openssl/ossl_typ.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
# include <openssl/safestack.h>
# if OPENSSL_VERSION_NUMBER >= 0x10101000L
#  include <openssl/crmferr.h>
# endif

# if OPENSSL_VERSION_NUMBER < 0x10100000L
#  define DEFINE_STACK_OF(T) DECLARE_STACK_OF(T)
# endif

# ifdef  __cplusplus
extern "C" {
# endif

# define CRMF_POPOPRIVKEY_THISMESSAGE          0
# define CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE    1
# define CRMF_POPOPRIVKEY_DHMAC                2
# define CRMF_POPOPRIVKEY_AGREEMAC             3
# define CRMF_POPOPRIVKEY_ENCRYPTEDKEY         4
# define CRMF_SUBSEQUENTMESSAGE_ENCRCERT       0
# define CRMF_SUBSEQUENTMESSAGE_CHALLENGERESP  1


typedef struct OSSL_crmf_encrypetedvalue_st CRMF_ENCRYPTEDVALUE;
DECLARE_ASN1_FUNCTIONS(CRMF_ENCRYPTEDVALUE)
typedef struct OSSL_crmf_certreqmsg_st CRMF_CERTREQMSG;
DEFINE_STACK_OF(CRMF_CERTREQMSG)
typedef struct OSSL_crmf_attributetypeandvalue_st CRMF_ATTRIBUTETYPEANDVALUE;
typedef struct OSSL_crmf_pbmparameter_st CRMF_PBMPARAMETER;
DECLARE_ASN1_FUNCTIONS(CRMF_PBMPARAMETER)
typedef struct OSSL_crmf_poposigningkey_st CRMF_POPOSIGNINGKEY;
typedef struct OSSL_crmf_certrequest_st CRMF_CERTREQUEST;
typedef struct OSSL_crmf_certid_st CRMF_CERTID;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTID)
typedef struct OSSL_crmf_pkipublicationinfo_st CRMF_PKIPUBLICATIONINFO;
DECLARE_ASN1_FUNCTIONS(CRMF_PKIPUBLICATIONINFO)
typedef struct OSSL_crmf_pkiarchiveoptions_st CRMF_PKIARCHIVEOPTIONS;
typedef struct OSSL_crmf_certtemplate_st CRMF_CERTTEMPLATE;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTTEMPLATE)
typedef STACK_OF(CRMF_CERTREQMSG) CRMF_CERTREQMESSAGES;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTREQMESSAGES)

typedef struct OSSL_crmf_optionalvalidity_st CRMF_OPTIONALVALIDITY;

DECLARE_ASN1_FUNCTIONS(CRMF_CERTTEMPLATE)


/* CertReqMessages */
/*
 * function DECLARATIONS
 *
 */

/* crmf_pbm.c */
CRMF_PBMPARAMETER *CRMF_pbmp_new(size_t slen, int owfnid,
                                 long itercnt, int macnid);
int CRMF_passwordBasedMac_new(const CRMF_PBMPARAMETER *pbm,
                              const unsigned char *msg, size_t msgLen,
                              const unsigned char *secret,
                              size_t secretLen, unsigned char **mac,
                              unsigned int *macLen);

/* crmf_lib.c */
int CRMF_CERTREQMSG_set1_regCtrl_regToken(CRMF_CERTREQMSG *msg,
                                          ASN1_UTF8STRING *tok);
int CRMF_CERTREQMSG_set1_regCtrl_authenticator(CRMF_CERTREQMSG *msg,
                                               ASN1_UTF8STRING *auth);
int CRMF_CERTREQMSG_set1_regCtrl_pkiPublicationInfo(CRMF_CERTREQMSG *msg,
                                                    CRMF_PKIPUBLICATIONINFO *pi);
int CRMF_CERTREQMSG_set1_regCtrl_pkiArchiveOptions(CRMF_CERTREQMSG *msg,
                                                   CRMF_PKIARCHIVEOPTIONS *aos);
int CRMF_CERTREQMSG_set1_regCtrl_protocolEncrKey(CRMF_CERTREQMSG *msg,
                                                 X509_PUBKEY *pubkey);
int CRMF_CERTREQMSG_set1_regCtrl_oldCertID(CRMF_CERTREQMSG *crm,
                                           CRMF_CERTID *cid);
int CRMF_CERTREQMSG_set1_regCtrl_oldCertID_from_cert(CRMF_CERTREQMSG *crm,
                                                     X509 *oldc);

int CRMF_CERTREQMSG_set1_regInfo_utf8Pairs(CRMF_CERTREQMSG *msg,
                                           ASN1_UTF8STRING *utf8pairs);
int CRMF_CERTREQMSG_set1_regInfo_certReq(CRMF_CERTREQMSG *msg,
                                         CRMF_CERTREQUEST *cr);

int CRMF_CERTREQMSG_set_version2(CRMF_CERTREQMSG *crm);
int CRMF_CERTREQMSG_set_validity(CRMF_CERTREQMSG *crm, time_t from, time_t to);
int CRMF_CERTREQMSG_set_certReqId(CRMF_CERTREQMSG *crm, long rid);
int CRMF_CERTREQMSG_set1_publicKey(CRMF_CERTREQMSG *crm, const EVP_PKEY *pkey);
int CRMF_CERTREQMSG_set1_subject(CRMF_CERTREQMSG *crm, const X509_NAME *subj);
int CRMF_CERTREQMSG_set1_issuer(CRMF_CERTREQMSG *crm, const X509_NAME *is);
int CRMF_CERTREQMSG_set0_extensions(CRMF_CERTREQMSG *crm,
                                    X509_EXTENSIONS *exts);

int CRMF_CERTREQMSG_push0_extension(CRMF_CERTREQMSG *crm,
                                    const X509_EXTENSION *ext);

# define CRMF_POPO_NONE       0
# define CRMF_POPO_SIGNATURE  1
# define CRMF_POPO_ENCRCERT   2
# define CRMF_POPO_RAVERIFIED 3
int CRMF_CERTREQMSG_create_popo(CRMF_CERTREQMSG *crm, const EVP_PKEY *pkey,
                                int dgst, int ppmtd);
X509 *CRMF_ENCRYPTEDVALUE_encCert_get1(CRMF_ENCRYPTEDVALUE *ecert,
                                       EVP_PKEY *pkey);

# ifdef __cplusplus
}
# endif
#endif /* ifndef HEADER_CRMF_H */

#if OPENSSL_VERSION_NUMBER < 0x10101000L && !defined(HEADER_CRMF_ERROR_CODES)
# define HEADER_CRMF_ERROR_CODES
# ifdef  __cplusplus
extern "C" {
# endif
/* BEGIN ERROR CODES */
# ifdef  __cplusplus
}
# endif
#endif
