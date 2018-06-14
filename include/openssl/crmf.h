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

#ifndef OSSL_HEADER_CRMF_H
# define OSSL_HEADER_CRMF_H

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

# define OSSL_CRMF_POPOPRIVKEY_THISMESSAGE          0
# define OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE    1
# define OSSL_CRMF_POPOPRIVKEY_DHMAC                2
# define OSSL_CRMF_POPOPRIVKEY_AGREEMAC             3
# define OSSL_CRMF_POPOPRIVKEY_ENCRYPTEDKEY         4
# define OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT       0
# define OSSL_CRMF_SUBSEQUENTMESSAGE_CHALLENGERESP  1


typedef struct OSSL_crmf_encrypetedvalue_st OSSL_CRMF_ENCRYPTEDVALUE;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_ENCRYPTEDVALUE)
typedef struct OSSL_crmf_certreqmsg_st OSSL_CRMF_CERTREQMSG;
DEFINE_STACK_OF(OSSL_CRMF_CERTREQMSG)
typedef struct OSSL_crmf_attributetypeandvalue_st OSSL_CRMF_ATTRIBUTETYPEANDVALUE;
typedef struct OSSL_crmf_pbmparameter_st OSSL_CRMF_PBMPARAMETER;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_PBMPARAMETER)
typedef struct OSSL_crmf_poposigningkey_st OSSL_CRMF_POPOSIGNINGKEY;
typedef struct OSSL_crmf_certrequest_st OSSL_CRMF_CERTREQUEST;
typedef struct OSSL_crmf_certid_st OSSL_CRMF_CERTID;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_CERTID)
typedef struct OSSL_crmf_pkipublicationinfo_st OSSL_CRMF_PKIPUBLICATIONINFO;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_PKIPUBLICATIONINFO)
typedef struct OSSL_crmf_pkiarchiveoptions_st OSSL_CRMF_PKIARCHIVEOPTIONS;
typedef struct OSSL_crmf_certtemplate_st OSSL_CRMF_CERTTEMPLATE;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_CERTTEMPLATE)
typedef STACK_OF(OSSL_CRMF_CERTREQMSG) OSSL_CRMF_CERTREQMESSAGES;
DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_CERTREQMESSAGES)

typedef struct OSSL_crmf_optionalvalidity_st OSSL_CRMF_OPTIONALVALIDITY;

DECLARE_ASN1_FUNCTIONS(OSSL_CRMF_CERTTEMPLATE)


/* CertReqMessages */
/*
 * function DECLARATIONS
 *
 */

/* crmf_pbm.c */
OSSL_CRMF_PBMPARAMETER *OSSL_CRMF_pbmp_new(size_t slen, int owfnid,
                                 long itercnt, int macnid);
int OSSL_CRMF_passwordBasedMac_new(const OSSL_CRMF_PBMPARAMETER *pbm,
                              const unsigned char *msg, size_t msgLen,
                              const unsigned char *secret,
                              size_t secretLen, unsigned char **mac,
                              unsigned int *macLen);

/* crmf_lib.c */
int OSSL_CRMF_CERTREQMSG_set1_regCtrl_regToken(OSSL_CRMF_CERTREQMSG *msg,
                                          ASN1_UTF8STRING *tok);
int OSSL_CRMF_CERTREQMSG_set1_regCtrl_authenticator(OSSL_CRMF_CERTREQMSG *msg,
                                               ASN1_UTF8STRING *auth);
int OSSL_CRMF_CERTREQMSG_set1_regCtrl_pkiPublicationInfo(OSSL_CRMF_CERTREQMSG *msg,
                                                    OSSL_CRMF_PKIPUBLICATIONINFO *pi);
int OSSL_CRMF_CERTREQMSG_set1_regCtrl_pkiArchiveOptions(OSSL_CRMF_CERTREQMSG *msg,
                                                   OSSL_CRMF_PKIARCHIVEOPTIONS *aos);
int OSSL_CRMF_CERTREQMSG_set1_regCtrl_protocolEncrKey(OSSL_CRMF_CERTREQMSG *msg,
                                                 X509_PUBKEY *pubkey);
int OSSL_CRMF_CERTREQMSG_set1_regCtrl_oldCertID(OSSL_CRMF_CERTREQMSG *crm,
                                           OSSL_CRMF_CERTID *cid);
OSSL_CRMF_CERTID *OSSL_CRMF_CERTID_gen(const X509_NAME *issuer,
                                       const ASN1_INTEGER *serial);

int OSSL_CRMF_CERTREQMSG_set1_regInfo_utf8Pairs(OSSL_CRMF_CERTREQMSG *msg,
                                           ASN1_UTF8STRING *utf8pairs);
int OSSL_CRMF_CERTREQMSG_set1_regInfo_certReq(OSSL_CRMF_CERTREQMSG *msg,
                                         OSSL_CRMF_CERTREQUEST *cr);

int OSSL_CRMF_CERTREQMSG_set_version2(OSSL_CRMF_CERTREQMSG *crm);
int OSSL_CRMF_CERTREQMSG_set_validity(OSSL_CRMF_CERTREQMSG *crm, time_t from, time_t to);
int OSSL_CRMF_CERTREQMSG_set_certReqId(OSSL_CRMF_CERTREQMSG *crm, long rid);
long OSSL_CRMF_CERTREQMSG_get_certReqId(OSSL_CRMF_CERTREQMSG *crm);
int OSSL_CRMF_CERTREQMSG_set1_publicKey(OSSL_CRMF_CERTREQMSG *crm, const EVP_PKEY *pkey);
int OSSL_CRMF_CERTREQMSG_set1_subject(OSSL_CRMF_CERTREQMSG *crm, const X509_NAME *subj);
int OSSL_CRMF_CERTREQMSG_set1_issuer(OSSL_CRMF_CERTREQMSG *crm, const X509_NAME *is);
int OSSL_CRMF_CERTREQMSG_set0_extensions(OSSL_CRMF_CERTREQMSG *crm,
                                    X509_EXTENSIONS *exts);

int OSSL_CRMF_CERTREQMSG_push0_extension(OSSL_CRMF_CERTREQMSG *crm,
                                    const X509_EXTENSION *ext);
/* TODO consolidate these with OSSL_CRMF_PROOFOFPOSESSION_RAVERIFIED etc. in crmf_int.h: */
# define OSSL_CRMF_POPO_NONE       0
# define OSSL_CRMF_POPO_SIGNATURE  1
# define OSSL_CRMF_POPO_ENCRCERT   2
# define OSSL_CRMF_POPO_RAVERIFIED 3
int OSSL_CRMF_CERTREQMSG_create_popo(OSSL_CRMF_CERTREQMSG *crm, const EVP_PKEY *pkey,
                                int dgst, int ppmtd);
int OSSL_CRMF_CERTREQMESSAGES_verify_popo(const OSSL_CRMF_CERTREQMESSAGES *reqs,
                                          long rid, int acceptRAVerified);
ASN1_INTEGER *OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(OSSL_CRMF_CERTTEMPLATE *tmpl);
X509_NAME *OSSL_CRMF_CERTTEMPLATE_get0_issuer(OSSL_CRMF_CERTTEMPLATE *tmpl);
X509 *OSSL_CRMF_ENCRYPTEDVALUE_encCert_get1(OSSL_CRMF_ENCRYPTEDVALUE *ecert,
                                       EVP_PKEY *pkey);

# ifdef __cplusplus
}
# endif
#endif

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
