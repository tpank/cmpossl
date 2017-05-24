/* vim: set cino={1s noet ts=4 sts=4 sw=4: */
/* crypto/crmf/crmf.h
 * Header file for CRMF (RFC 4211) for OpenSSL
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

#ifndef HEADER_CRMF_H
# define HEADER_CRMF_H

# include <openssl/opensslconf.h>

# include <openssl/ossl_typ.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
# include <openssl/safestack.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define DEFINE_STACK_OF(T) DECLARE_STACK_OF(T)
#endif

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


typedef struct crmf_certreqmsg_st CRMF_CERTREQMSG;
DEFINE_STACK_OF(CRMF_CERTREQMSG)
typedef struct crmf_attributetypeandvalue_st CRMF_ATTRIBUTETYPEANDVALUE;
typedef struct crmf_pbmparameter_st CRMF_PBMPARAMETER;
DECLARE_ASN1_FUNCTIONS(CRMF_PBMPARAMETER);
typedef struct crmf_poposigningkey_st CRMF_POPOSIGNINGKEY;
typedef struct crmf_certrequest_st CRMF_CERTREQUEST;
typedef struct crmf_certid_st CRMF_CERTID;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTID);
typedef struct crmf_pkipublicationinfo_st CRMF_PKIPUBLICATIONINFO;
DECLARE_ASN1_FUNCTIONS(CRMF_PKIPUBLICATIONINFO);
typedef struct crmf_certtemplate_st CRMF_CERTTEMPLATE;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTTEMPLATE);
typedef STACK_OF(CRMF_CERTREQMSG) CRMF_CERTREQMESSAGES;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTREQMESSAGES)
    
typedef struct crmf_optionalvalidity_st CRMF_OPTIONALVALIDITY;

/*
CertTemplate ::= SEQUENCE {
 version          [0] Version                           OPTIONAL,
 serialNumber [1] INTEGER                               OPTIONAL,
 signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
 issuer           [3] Name                                      OPTIONAL,
 validity         [4] OptionalValidity          OPTIONAL,
 subject          [5] Name                                      OPTIONAL,
 publicKey        [6] SubjectPublicKeyInfo      OPTIONAL,
 issuerUID        [7] UniqueIdentifier          OPTIONAL,
 subjectUID   [8] UniqueIdentifier              OPTIONAL,
 extensions   [9] Extensions                    OPTIONAL }
 */
typedef struct crmf_certtemplate_st {
    ASN1_INTEGER *version;  /* 0 */
    /* serialNumber MUST be omitted.  This field is assigned by the CA
     * during certificate creation. */
    ASN1_INTEGER *serialNumber; /* 1 */
    /* signingAlg MUST be omitted.  This field is assigned by the CA
     * during certificate creation. */
    X509_ALGOR *signingAlg; /* 2 */
    X509_NAME *issuer;      /* 3 */
    CRMF_OPTIONALVALIDITY *validity; /* 4 */
    X509_NAME *subject;     /* 5 */
    X509_PUBKEY *publicKey; /* 6 */
    /* According to rfc 3280:
       UniqueIdentifier  ::=  BIT STRING
     */
    /* issuerUID is deprecated in version 2 */
    ASN1_BIT_STRING *issuerUID; /* 7 */
    /* subjectUID is deprecated in version 2 */
    ASN1_BIT_STRING *subjectUID; /* 8 */
# if 0
    /* TODO: That should be - but that's only cosmetical */
    X509_EXTENSIONS *extensions; /* 9 */
# endif
    STACK_OF (X509_EXTENSION) * extensions; /* 9 */
} CRMF_CERTTEMPLATE;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTTEMPLATE)

/*
EncryptedValue ::= SEQUENCE {
 intendedAlg   [0] AlgorithmIdentifier  OPTIONAL,
 -- the intended algorithm for which the value will be used
 symmAlg           [1] AlgorithmIdentifier      OPTIONAL,
 -- the symmetric algorithm used to encrypt the value
 encSymmKey    [2] BIT STRING                   OPTIONAL,
 -- the (encrypted) symmetric key used to encrypt the value
 keyAlg            [3] AlgorithmIdentifier      OPTIONAL,
 -- algorithm used to encrypt the symmetric key
 valueHint         [4] OCTET STRING                     OPTIONAL,
 -- a brief description or identifier of the encValue content
 -- (may be meaningful only to the sending entity, and used only
 -- if EncryptedValue might be re-examined by the sending entity
 -- in the future)
 encValue               BIT STRING }
 -- the encrypted value itself
*/
typedef struct crmf_encrypetedvalue_st {
    X509_ALGOR *intendedAlg; /* 0 */
    X509_ALGOR *symmAlg;    /* 1 */
    ASN1_BIT_STRING *encSymmKey; /* 2 */
    X509_ALGOR *keyAlg;     /* 3 */
    ASN1_OCTET_STRING *valueHint; /* 4 */
    ASN1_BIT_STRING *encValue;
} CRMF_ENCRYPTEDVALUE;
DECLARE_ASN1_FUNCTIONS(CRMF_ENCRYPTEDVALUE)
    

/* CertReqMessages */
/* ########################################################################## *
 * function DECLARATIONS
 * ########################################################################## */
/* crmf_msg.c */
CRMF_CERTREQMSG *CRMF_certreq_new(const long certReqId,
                                  const EVP_PKEY *pkey,
                                  const X509_NAME *subject,
                                  const X509_NAME *issuer,
                                  time_t notBefore, time_t notAfter,
                                  const X509_EXTENSIONS * extensions);

/* crmf_pbm.c */
CRMF_PBMPARAMETER *CRMF_pbmp_new(size_t slen, int owfnid,
                                 long itercnt, int macnid);
int CRMF_passwordBasedMac_new(const CRMF_PBMPARAMETER *pbm,
                              const unsigned char *msg, size_t msgLen,
                              const unsigned char *secret,
                              size_t secretLen, unsigned char **mac,
                              unsigned int *macLen);

/* crmf_lib.c */
int CRMF_CERTREQMSG_push0_control(CRMF_CERTREQMSG *certReqMsg,
                                  CRMF_ATTRIBUTETYPEANDVALUE *control);
int CRMF_CERTREQMSG_set1_control_regToken(CRMF_CERTREQMSG *msg,
                                          ASN1_UTF8STRING *tok);
int CRMF_CERTREQMSG_set1_control_authenticator(CRMF_CERTREQMSG *msg,
                                               ASN1_UTF8STRING *auth);
int CRMF_CERTREQMSG_push0_regInfo(CRMF_CERTREQMSG *certReqMsg,
                                  CRMF_ATTRIBUTETYPEANDVALUE *regInfo);
int CRMF_CERTREQMSG_set1_regInfo_regToken(CRMF_CERTREQMSG *msg,
                                          ASN1_UTF8STRING *tok);

int CRMF_CERTREQMSG_set_version2(CRMF_CERTREQMSG *certReqMsg);
int CRMF_CERTREQMSG_set_validity(CRMF_CERTREQMSG *certReqMsg,
                                 time_t notBefore, time_t notAfter);
int CRMF_CERTREQMSG_set_certReqId(CRMF_CERTREQMSG *certReqMsg,
                                  const long certReqId);
int CRMF_CERTREQMSG_set1_publicKey(CRMF_CERTREQMSG *certReqMsg,
                                   const EVP_PKEY *pkey);
int CRMF_CERTREQMSG_set1_subject(CRMF_CERTREQMSG *certReqMsg,
                                 const X509_NAME *subject);
int CRMF_CERTREQMSG_set1_issuer(CRMF_CERTREQMSG *certReqMsg,
                                const X509_NAME *issuer);
int CRMF_CERTREQMSG_push0_extension(CRMF_CERTREQMSG *certReqMsg,
                                    const X509_EXTENSION *ext);

# define CRMF_POPO_NONE          0
# define CRMF_POPO_SIGNATURE     1
# define CRMF_POPO_ENCRCERT      2
# define CRMF_POPO_RAVERIFIED    3
int CRMF_CERTREQMSG_calc_and_set_popo(CRMF_CERTREQMSG *certReqMsg,
                                      const EVP_PKEY *pkey,
                                      int digest,
                                      int popoMethod);

CRMF_POPOSIGNINGKEY *CRMF_poposigningkey_new(CRMF_CERTREQUEST *certReq,
                                             const EVP_PKEY *pkey,
                                             int digest);

int CRMF_CERTREQMSG_set1_control_oldCertId(CRMF_CERTREQMSG *certReqMsg,
                                           X509 *oldCert);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
int ERR_load_CRMF_strings(void);

/* Error codes for the CRMF functions. */

/* Function codes. */
# define CRMF_F_CRMF_CERTREQMSG_CALC_AND_SET_POPO         107
# define CRMF_F_CRMF_CERTREQMSG_PUSH0_CONTROL             100
# define CRMF_F_CRMF_CERTREQMSG_PUSH0_EXTENSION           101
# define CRMF_F_CRMF_CERTREQMSG_PUSH0_REGINFO             102
# define CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_AUTHENTICATOR 121
# define CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_OLDCERTID    122
# define CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_PKIARCHIVEOPTIONS 131
# define CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_PKIPUBLICATIONINFO 123
# define CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_PROTOCOLENCRKEY 124
# define CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_REGTOKEN     108
# define CRMF_F_CRMF_CERTREQMSG_SET1_ISSUER               132
# define CRMF_F_CRMF_CERTREQMSG_SET1_PUBLICKEY            103
# define CRMF_F_CRMF_CERTREQMSG_SET1_REGINFO_CERTREQ      125
# define CRMF_F_CRMF_CERTREQMSG_SET1_REGINFO_REGTOKEN     126
# define CRMF_F_CRMF_CERTREQMSG_SET1_REGINFO_UTF8PAIRS    127
# define CRMF_F_CRMF_CERTREQMSG_SET1_SUBJECT              128
# define CRMF_F_CRMF_CERTREQMSG_SET_CERTREQID             129
# define CRMF_F_CRMF_CERTREQMSG_SET_VALIDITY              104
# define CRMF_F_CRMF_CERTREQMSG_SET_VERSION2              130
# define CRMF_F_CRMF_CERTREQ_NEW                          105
# define CRMF_F_CRMF_PASSWORDBASEDMAC_NEW                 106
# define CRMF_F_CRMF_PBMP_NEW                             133
# define CRMF_F_CRMF_POPOSIGNINGKEY_NEW                   109
# define CRMF_F_CRMF_SET1_CONTROL_AUTHENTICATOR           110
# define CRMF_F_CRMF_SET1_CONTROL_OLDCERTID               111
# define CRMF_F_CRMF_SET1_CONTROL_PKIARCHIVEOPTIONS       112
# define CRMF_F_CRMF_SET1_CONTROL_PKIPUBLICATIONINFO      113
# define CRMF_F_CRMF_SET1_CONTROL_PROTOCOLENCRKEY         114
# define CRMF_F_CRMF_SET1_REGINFO_CERTREQ                 115
# define CRMF_F_CRMF_SET1_REGINFO_UTF8PAIRS               116
# define CRMF_F_CRMF_SET1_REGTOKEN_CERTREQ                117
# define CRMF_F_CRMF_SET1_SUBJECT                         118
# define CRMF_F_CRMF_SET_CERTREQID                        119
# define CRMF_F_CRMF_SET_VERSION2                         120

/* Reason codes. */
# define CRMF_R_CRMFERROR                                 100
# define CRMF_R_ERROR_CALCULATING_AND_SETTING_POPO        103
# define CRMF_R_ERROR_SETTING_CONTROL_AUTHENTICATOR_ATAV  104
# define CRMF_R_ERROR_SETTING_CONTROL_OLDCERTID_ATAV      105
# define CRMF_R_ERROR_SETTING_CONTROL_PKIARCHIVEOPTIONS_ATAV 106
# define CRMF_R_ERROR_SETTING_CONTROL_PKIPUBLICATIONINFO_ATAV 107
# define CRMF_R_ERROR_SETTING_CONTROL_PROTOCOLENCRKEY_ATAV 108
# define CRMF_R_ERROR_SETTING_POPSIGNINGKEY               109
# define CRMF_R_ERROR_SETTING_PUBLIC_KEY                  101
# define CRMF_R_ERROR_SETTING_REGINFO_CERTREQ_ATAV        110
# define CRMF_R_ERROR_SETTING_REGINFO_UTF8PAIRS_ATAV      111
# define CRMF_R_ERROR_SETTING_REGTOKEN_ATAV               112
# define CRMF_R_ERROR_SETTING_REGTOKEN_CERTREQ_ATAV       113
# define CRMF_R_ERROR_SETTING_VERSION_2                   114
# define CRMF_R_ITERATIONCOUNT_BELOW_100                  117
# define CRMF_R_MALLOC_FAILURE                            118
# define CRMF_R_SETTING_MAC_ALRGOR_FAILURE                119
# define CRMF_R_SETTING_OWF_ALRGOR_FAILURE                120
# define CRMF_R_UNSUPPORTED_ALGORITHM                     102
# define CRMF_R_UNSUPPORTED_ALG_FOR_POPSIGNINGKEY         115
# define CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO      116
# define CRMF_R_NULL_ARGUMENT                             134

# ifdef  __cplusplus
}
# endif
#endif
