/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

#include <stdio.h>
#if defined OPENSSL_SYS_UNIX || defined DJGPP \
    || (defined __VMS_VER && __VMS_VER >= 70000000)
# include <dirent.h>
#endif

#include <openssl/asn1t.h>

#include "cmp_int.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/err.h>

/*
 * Get current certificate store containing trusted root CA certs
 */
X509_STORE *OSSL_CMP_CTX_get0_trustedStore(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->trusted_store;
}

/*
 * Set certificate store containing trusted (root) CA certs and possibly CRLs
 * and a cert verification callback function used for CMP server authentication.
 * Any already existing store entry is freed. Given NULL, the entry is reset.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set0_trustedStore(OSSL_CMP_CTX *ctx, X509_STORE *store)
{
    if (ctx == NULL)
       return 0;
    X509_STORE_free(ctx->trusted_store);
    ctx->trusted_store = store != NULL ? store : X509_STORE_new();;
    return ctx->trusted_store != NULL;
}

/*
 * Get current list of non-trusted intermediate certs
 */
STACK_OF(X509) *OSSL_CMP_CTX_get0_untrusted_certs(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->untrusted_certs;
}

/*
 * Set untrusted certificates for path construction in authentication of
 * the CMP server and potentially others (TLS server, newly enrolled cert).
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_untrusted_certs(OSSL_CMP_CTX *ctx,
                                      const STACK_OF(X509) *certs)
{
    if (ctx == NULL)
       return 0;
    sk_X509_pop_free(ctx->untrusted_certs, X509_free);
    if ((ctx->untrusted_certs = sk_X509_new_null()) == NULL)
        return 0;
    return OSSL_CMP_sk_X509_add1_certs(ctx->untrusted_certs, certs, 0, 1);
}

/*
 * Allocates and initializes OSSL_CMP_CTX context structure with default values.
 * Returns new context on success, NULL on error
 */
OSSL_CMP_CTX *OSSL_CMP_CTX_new(void)
{
    OSSL_CMP_CTX *ctx = OPENSSL_zalloc(sizeof(OSSL_CMP_CTX));

    if (ctx == NULL)
        goto err;

    ctx->transfer_cb =
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
        OSSL_CMP_MSG_http_perform;
#else
        NULL;
#endif
    /* serverPath must be an empty string if not set since it's not mandatory */
    if ((ctx->serverPath = OPENSSL_zalloc(1)) == NULL)
        goto err;
    ctx->serverPort = 8080;
    ctx->proxyPort = 8080;
    ctx->msgtimeout = 2 * 60;

    if ((ctx->trusted_store = X509_STORE_new()) == NULL)
        goto err;
    if ((ctx->untrusted_certs = sk_X509_new_null()) == NULL)
        goto err;

    ctx->pbm_slen = 16;
    ctx->pbm_owf = NID_sha256;
    ctx->pbm_itercnt = 500;
    ctx->pbm_mac = NID_hmac_sha1;

    ctx->digest = NID_sha256;
    ctx->popoMethod = OSSL_CRMF_POPO_SIGNATURE;
    ctx->revocationReason = CRL_REASON_NONE;

    /* all other elements are initialized to 0 or NULL, respectively */
    return ctx;

 err:
    OPENSSL_free(ctx);
    return NULL;
}

/*
 * Frees OSSL_CMP_CTX variables allocated in OSSL_CMP_CTX_new()
 */
void OSSL_CMP_CTX_free(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx->serverPath);
    OPENSSL_free(ctx->serverName);
    OPENSSL_free(ctx->proxyName);

    X509_free(ctx->srvCert);
    X509_free(ctx->validatedSrvCert);
    X509_NAME_free(ctx->expected_sender);
    X509_STORE_free(ctx->trusted_store);
    sk_X509_pop_free(ctx->untrusted_certs, X509_free);

    X509_free(ctx->clCert);
    EVP_PKEY_free(ctx->pkey);
    ASN1_OCTET_STRING_free(ctx->referenceValue);
    if (ctx->secretValue != NULL)
        OPENSSL_cleanse(ctx->secretValue->data, ctx->secretValue->length);
    ASN1_OCTET_STRING_free(ctx->secretValue);

    X509_NAME_free(ctx->recipient);
    ASN1_OCTET_STRING_free(ctx->transactionID);
    ASN1_OCTET_STRING_free(ctx->last_senderNonce);
    ASN1_OCTET_STRING_free(ctx->recipNonce);
    sk_OSSL_CMP_ITAV_pop_free(ctx->geninfo_itavs, OSSL_CMP_ITAV_free);
    sk_X509_pop_free(ctx->extraCertsOut, X509_free);

    EVP_PKEY_free(ctx->newPkey);
    X509_NAME_free(ctx->issuer);
    X509_NAME_free(ctx->subjectName);
    sk_GENERAL_NAME_pop_free(ctx->subjectAltNames, GENERAL_NAME_free);
    sk_X509_EXTENSION_pop_free(ctx->reqExtensions, X509_EXTENSION_free);
    sk_POLICYINFO_pop_free(ctx->policies, POLICYINFO_free);
    X509_free(ctx->oldClCert);
    X509_REQ_free(ctx->p10CSR);

    sk_OSSL_CMP_ITAV_pop_free(ctx->genm_itavs, OSSL_CMP_ITAV_free);

    sk_ASN1_UTF8STRING_pop_free(ctx->lastStatusString, ASN1_UTF8STRING_free);
    X509_free(ctx->newClCert);
    sk_X509_pop_free(ctx->caPubs, X509_free);
    sk_X509_pop_free(ctx->extraCertsIn, X509_free);

    OPENSSL_free(ctx);
}

/*
 * returns the PKIStatus from the last CertRepMessage
 * or Revocation Response, -1 on error
 */
int OSSL_CMP_CTX_status_get(OSSL_CMP_CTX *ctx)
{
    return ctx != NULL ? ctx->lastPKIStatus : -1;
}

/*
 * returns the statusString from the last CertRepMessage
 * or Revocation Response, NULL on error
 */
OSSL_CMP_PKIFREETEXT *OSSL_CMP_CTX_statusString_get(OSSL_CMP_CTX *ctx)
{
    return ctx != NULL ? ctx->lastStatusString : NULL;
}

/*
 * Set callback function for checking if the cert is ok or should
 * it be rejected.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_certConf_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_certConf_cb_t cb)
{
    if (ctx == NULL)
        return 0;
    ctx->certConf_cb = cb;
    return 1;
}

/*
 * Set argument, respectively a pointer to a structure containing arguments,
 * optionally to be used by the certConf callback
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_certConf_cb_arg(OSSL_CMP_CTX *ctx, void* arg)
{
    if (ctx == NULL)
        return 0;
    ctx->certConf_cb_arg = arg;
    return 1;
}

/*
 * Get argument, respectively the pointer to a structure containing arguments,
 * optionally to be used by certConf callback
 * returns callback argument set previously (NULL if not set or on error)
 */
void *OSSL_CMP_CTX_get_certConf_cb_arg(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->certConf_cb_arg;
}

/*
 * Set a callback function for log messages.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_log_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_log_cb_t cb)
{
    if (ctx == NULL)
        return 0;
    ctx->log_cb = cb;
    return 1;
}

/*
 * Set or clear the reference value to be used for identification (i.e. the
 * user name) when using PBMAC.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_referenceValue(OSSL_CMP_CTX *ctx,
                                     const unsigned char *ref, size_t len)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_REFERENCEVALUE, CMP_R_INVALID_ARGS);
        return 0;
    }
    return OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(&ctx->referenceValue, ref, len);
}

/*
 * Set or clear the password to be used for protecting messages with PBMAC
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_secretValue(OSSL_CMP_CTX *ctx, const unsigned char *sec,
                                  const size_t len)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SECRETVALUE, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (ctx->secretValue != NULL)
        OPENSSL_cleanse(ctx->secretValue->data, ctx->secretValue->length);
    return OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(&ctx->secretValue, sec, len);
}

/*
 * Returns the stack of certificates received in a response message.
 * The stack is duplicated so the caller must handle freeing it!
 * returns pointer to created stack on success, NULL on error
 */
STACK_OF(X509) *OSSL_CMP_CTX_extraCertsIn_get1(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_EXTRACERTSIN_GET1, CMP_R_INVALID_ARGS);
        return NULL;
    }
    if (ctx->extraCertsIn == NULL)
        return sk_X509_new_null();
    return X509_chain_up_ref(ctx->extraCertsIn);
}

/*
 * Copies any given stack of inbound X509 certificates to extraCertsIn of
 * the OSSL_CMP_CTX structure so that they may be retrieved later.
 * returns 1 on success, 0 on error
 */
int CMP_CTX_set1_extraCertsIn(OSSL_CMP_CTX *ctx,
                              STACK_OF(X509) *extraCertsIn)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_CMP_CTX_SET1_EXTRACERTSIN, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (extraCertsIn == NULL)
        return 1;

    /* if there are already inbound extraCerts on the stack delete them */
    sk_X509_pop_free(ctx->extraCertsIn, X509_free);
    if ((ctx->extraCertsIn = X509_chain_up_ref(extraCertsIn)) == NULL) {
        CMPerr(CMP_F_CMP_CTX_SET1_EXTRACERTSIN, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return 1;
}

/*
 * Duplicate and push the given X509 certificate to the stack of
 * outbound certificates to send in the extraCerts field.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_extraCertsOut_push1(OSSL_CMP_CTX *ctx, const X509 *val)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_EXTRACERTSOUT_PUSH1, CMP_R_INVALID_ARGS);
        return 0;
    }
    if ((ctx->extraCertsOut == NULL
             && (ctx->extraCertsOut = sk_X509_new_null()) == NULL)
            || !sk_X509_push(ctx->extraCertsOut, X509_dup(val))) {
        CMPerr(CMP_F_OSSL_CMP_CTX_EXTRACERTSOUT_PUSH1, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

/*
 * Duplicate and set the given stack as the new stack of X509
 * certificates to send out in the extraCerts field.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_extraCertsOut(OSSL_CMP_CTX *ctx,
                                    STACK_OF(X509) *extraCertsOut)
{
    if ((ctx == NULL) || (extraCertsOut == NULL)) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_EXTRACERTSOUT, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    sk_X509_pop_free(ctx->extraCertsOut, X509_free);
    if ((ctx->extraCertsOut = X509_chain_up_ref(extraCertsOut)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_EXTRACERTSOUT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return 1;
}

/*
 * OSSL_CMP_CTX_policyOID_push1() adds the certificate policy OID given by the
 * string to the X509_EXTENSIONS of the requested certificate template.
 * returns 1 on success, -1 on parse error, and 0 on other error.
 */
int OSSL_CMP_CTX_policyOID_push1(OSSL_CMP_CTX *ctx, const char *policyOID)
{
    ASN1_OBJECT *policy;
    POLICYINFO *pinfo = NULL;

    if ((ctx == NULL) || (policyOID == NULL))
        return 0;

    if ((policy = OBJ_txt2obj(policyOID, 1)) == 0)
        return -1; /* parse error */

    if (ctx->policies == NULL
            && (ctx->policies = CERTIFICATEPOLICIES_new()) == NULL)
        return 0;

    if ((pinfo = POLICYINFO_new()) == NULL)
        return 0;
    pinfo->policyid = policy;

    return sk_POLICYINFO_push(ctx->policies, pinfo);
}

/*
 * add an itav for geninfo of the PKI message header
 */
int OSSL_CMP_CTX_geninfo_itav_push0(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav)
{
    if (ctx == NULL)
        return 0;

    return OSSL_CMP_ITAV_stack_item_push0(&ctx->geninfo_itavs, itav);
}

/*
 * add an itav for the body of outgoing general messages
 */
int OSSL_CMP_CTX_genm_itav_push0(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *itav)
{
    if (ctx == NULL)
        return 0;

    return OSSL_CMP_ITAV_stack_item_push0(&ctx->genm_itavs, itav);
}

/*
 * Returns a duplicate of the stack of X509 certificates that
 * were received in the caPubs field of the last response message.
 * returns NULL on error
 */
STACK_OF(X509) *OSSL_CMP_CTX_caPubs_get1(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_CAPUBS_GET1, CMP_R_INVALID_ARGS);
        return NULL;
    }
    if (ctx->caPubs == NULL)
        return NULL;
    return X509_chain_up_ref(ctx->caPubs);
}

/*
 * Duplicate and copy the given stack of certificates to the given
 * OSSL_CMP_CTX structure so that they may be retrieved later.
 * returns 1 on success, 0 on error
 */
int CMP_CTX_set1_caPubs(OSSL_CMP_CTX *ctx, STACK_OF(X509) *caPubs)
{
    if ((ctx == NULL) || (caPubs == NULL)) {
        CMPerr(CMP_F_CMP_CTX_SET1_CAPUBS, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    sk_X509_pop_free(ctx->caPubs, X509_free);
    ctx->caPubs = NULL;

    if ((ctx->caPubs = X509_chain_up_ref(caPubs)) == NULL) {
        CMPerr(CMP_F_CMP_CTX_SET1_CAPUBS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return 1;
}

/*
 * Pins the server certificate to be directly trusted (even if it is expired)
 * for verifying response messages.
 * Cert pointer is not consumed. It may be NULL to clear the entry.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_srvCert(OSSL_CMP_CTX *ctx, const X509 *cert)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SRVCERT, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    X509_free(ctx->srvCert);
    ctx->srvCert = NULL;

    if (cert == NULL)
        return 1; /* srvCert has been cleared */

    if ((ctx->srvCert = X509_dup(cert)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SRVCERT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;

}

/*
 * Set the X509 name of the recipient. Set in the PKIHeader.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_recipient(OSSL_CMP_CTX *ctx, const X509_NAME *name)
{
    if (ctx == NULL || name == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_RECIPIENT, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    X509_NAME_free(ctx->recipient);
    ctx->recipient = NULL;

    if ((ctx->recipient = X509_NAME_dup(name)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_RECIPIENT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;

}

/*
 * Store the X509 name of the expected sender in the PKIHeader of responses.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_expected_sender(OSSL_CMP_CTX *ctx, const X509_NAME *name)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_EXPECTED_SENDER, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    X509_NAME_free(ctx->expected_sender);
    ctx->expected_sender = NULL;

    if (name == NULL)
        return 1;

    if ((ctx->expected_sender = X509_NAME_dup(name)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_EXPECTED_SENDER, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

/*
 * Set the X509 name of the issuer. Set in the PKIHeader.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_issuer(OSSL_CMP_CTX *ctx, const X509_NAME *name)
{
    if (ctx == NULL || name == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_ISSUER, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    X509_NAME_free(ctx->issuer);
    ctx->issuer = NULL;

    if ((ctx->issuer = X509_NAME_dup(name)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_ISSUER, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

/*
 * Set the subject name that will be placed in the certificate
 * request. This will be the subject name on the received certificate.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_subjectName(OSSL_CMP_CTX *ctx, const X509_NAME *name)
{
    if (ctx == NULL || name == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SUBJECTNAME, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    X509_NAME_free(ctx->subjectName);
    ctx->subjectName = NULL;

    if ((ctx->subjectName = X509_NAME_dup(name)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SUBJECTNAME, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

/*
 * sets the X.509v3 certificate request extensions to be used in IR/CR/KUR
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set0_reqExtensions(OSSL_CMP_CTX *ctx, X509_EXTENSIONS *exts)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET0_REQEXTENSIONS, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (sk_GENERAL_NAME_num(ctx->subjectAltNames) > 0 && exts != NULL
            && X509v3_get_ext_by_NID(exts, NID_subject_alt_name, -1) >= 0) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET0_REQEXTENSIONS, CMP_R_MULTIPLE_SAN_SOURCES);
        return 0;
    }
    ctx->reqExtensions = exts;
    return 1;
}

/*
 * sets the X.509v3 certificate request extensions to be used in IR/CR/KUR
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_reqExtensions(OSSL_CMP_CTX *ctx, const X509_EXTENSIONS *exts)
{
    X509_EXTENSIONS *exts_copy;
    int res;

    if (ctx == NULL)
       return 0;
    exts_copy = OSSL_CMP_X509_EXTENSIONS_dup(exts);

    if (exts != NULL && exts_copy == NULL)
        return 0;
    res = OSSL_CMP_CTX_set0_reqExtensions(ctx, exts_copy);
    if (res == 0)
        sk_X509_EXTENSION_pop_free(exts_copy, X509_EXTENSION_free);
    return res;
}

/* returns 1 if ctx contains a Subject Alternative Name extension, else 0 */
int OSSL_CMP_CTX_reqExtensions_have_SAN(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL || ctx->reqExtensions == NULL)
        return 0;
    return X509v3_get_ext_by_NID(ctx->reqExtensions,
                                 NID_subject_alt_name, -1) >= 0;
}

/*
 * Add a GENERAL_NAME structure that will be added to the CRMF
 * request's extensions field to request subject alternative names.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_subjectAltName_push1(OSSL_CMP_CTX *ctx,
                                      const GENERAL_NAME *name)
{
    if (ctx == NULL || name == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SUBJECTALTNAME_PUSH1, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    if (OSSL_CMP_CTX_reqExtensions_have_SAN(ctx)) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SUBJECTALTNAME_PUSH1,
               CMP_R_MULTIPLE_SAN_SOURCES);
        return 0;
    }

    if ((ctx->subjectAltNames == NULL
             && (ctx->subjectAltNames = sk_GENERAL_NAME_new_null()) == NULL)
            || !sk_GENERAL_NAME_push(ctx->subjectAltNames,
                                     GENERAL_NAME_dup(name))) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SUBJECTALTNAME_PUSH1, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

/*
 * Set our own client certificate, used for example in KUR and when
 * doing the IR with existing certificate.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_clCert(OSSL_CMP_CTX *ctx, const X509 *cert)
{
    if (ctx == NULL || cert == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_CLCERT, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    X509_free(ctx->clCert);
    ctx->clCert = NULL;

    if ((ctx->clCert = X509_dup(cert)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_CLCERT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

/*
 * Set the old certificate that we are updating in KUR
 * or the certificate to be revoked in RR, respectively.
 * Also used as reference cert (defaulting to clCert) for deriving subject DN
 * and SANs. Its issuer is used as default recipient in the CMP message header.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_oldClCert(OSSL_CMP_CTX *ctx, const X509 *cert)
{
    if (ctx == NULL || cert == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_OLDCLCERT, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    X509_free(ctx->oldClCert);
    ctx->oldClCert = NULL;

    if ((ctx->oldClCert = X509_dup(cert)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_OLDCLCERT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

/*
 * Set the PKCS#10 CSR to be sent in P10CR
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_p10CSR(OSSL_CMP_CTX *ctx, const X509_REQ *csr)
{
    if (ctx == NULL || csr == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_P10CSR, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    X509_REQ_free(ctx->p10CSR);
    ctx->p10CSR = NULL;

    if ((ctx->p10CSR = X509_REQ_dup(csr)) == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_P10CSR, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
}

/*
 * sets the (newly received in IP/KUP/CP) client Certificate to the context
 * returns 1 on success, 0 on error
 * TODO: this only permits for one client cert to be received...
 */
int CMP_CTX_set1_newClCert(OSSL_CMP_CTX *ctx, X509 *cert)
{
    if (ctx == NULL || cert == NULL)
        goto err;

    X509_free(ctx->newClCert);
    ctx->newClCert = NULL;

    if (!X509_up_ref(cert))
        goto err;
    ctx->newClCert = cert;
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_NEWCLCERT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/*
 * Get the (newly received in IP/KUP/CP) client certificate from the context
 * TODO: this only permits for one client cert to be received...
 */
X509 *CMP_CTX_get0_newClCert(const OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->newClCert;
}

/*
 * Set the client's private key. This creates a duplicate of the key
 * so the given pointer is not used directly.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_pkey(OSSL_CMP_CTX *ctx, EVP_PKEY *pkey)
{
    if (ctx == NULL || pkey == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_PKEY, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (!EVP_PKEY_up_ref(pkey))
        return 0;
    if (OSSL_CMP_CTX_set0_pkey(ctx, pkey))
        return 1;
    EVP_PKEY_free(pkey); /* down ref */
    return 0;
}

/*
 * Set the client's current private key. NOTE: this version uses
 * the given pointer directly!
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set0_pkey(OSSL_CMP_CTX *ctx, EVP_PKEY *pkey)
{
    if (ctx == NULL || pkey == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET0_PKEY, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    EVP_PKEY_free(ctx->pkey);
    ctx->pkey = NULL;

    ctx->pkey = pkey;
    return 1;
}

/*
 * Set new key pair. Used for example when doing Key Update.
 * The key is duplicated so the original pointer is not directly used.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_newPkey(OSSL_CMP_CTX *ctx, EVP_PKEY *pkey)
{
    if (ctx == NULL || pkey == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_NEWPKEY, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (!EVP_PKEY_up_ref(pkey))
        return 0;
    if (OSSL_CMP_CTX_set0_newPkey(ctx, pkey))
       return 1;
    EVP_PKEY_free(pkey); /* down ref */
    return 0;
}

/*
 * Set new key pair. Used e.g. when doing Key Update.
 * NOTE: uses the pointer directly!
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set0_newPkey(OSSL_CMP_CTX *ctx, EVP_PKEY *pkey)
{
    if (ctx == NULL || pkey == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET0_NEWPKEY, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    EVP_PKEY_free(ctx->newPkey);
    ctx->newPkey = NULL;

    ctx->newPkey = pkey;
    return 1;
}

/*
 * gets the newPkey from the context, or NULL on error
 */
EVP_PKEY *OSSL_CMP_CTX_get0_newPkey(const OSSL_CMP_CTX *ctx)
{
    return ctx == NULL ? NULL : ctx->newPkey;
}

/*
 * sets the given transactionID to the context
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_transactionID(OSSL_CMP_CTX *ctx,
                                    const ASN1_OCTET_STRING *id)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_TRANSACTIONID, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    return OSSL_CMP_ASN1_OCTET_STRING_set1(&ctx->transactionID, id);

}

/*
 * gets the transactionID from the context
 * returns a pointer to the transactionID on success, NULL on error
 */
ASN1_OCTET_STRING *OSSL_CMP_CTX_get0_transactionID(const OSSL_CMP_CTX *ctx)
{
    return ctx == NULL ? NULL : ctx->transactionID;
}

/*
 * sets the given nonce to be used for the recipNonce in the next message to be
 * created.
 * returns 1 on success, 0 on error
 */
int CMP_CTX_set1_recipNonce(OSSL_CMP_CTX *ctx,
                            const ASN1_OCTET_STRING *nonce)
{
    if (ctx == NULL || nonce == NULL) {
        CMPerr(CMP_F_CMP_CTX_SET1_RECIPNONCE, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    return OSSL_CMP_ASN1_OCTET_STRING_set1(&ctx->recipNonce, nonce);
}

/*
 * gets the recipNonce of the given context
 * returns a pointer to the nonce on success, NULL on error
 */
ASN1_OCTET_STRING *CMP_CTX_get0_recipNonce(const OSSL_CMP_CTX *ctx)
{
    return ctx == NULL ? NULL : ctx->recipNonce;
}

/*
 * stores the given nonce as the last senderNonce sent out
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_last_senderNonce(OSSL_CMP_CTX *ctx,
                                       const ASN1_OCTET_STRING *nonce)
{
    if (ctx == NULL || nonce == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_LAST_SENDERNONCE, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    return OSSL_CMP_ASN1_OCTET_STRING_set1(&ctx->last_senderNonce, nonce);
}

/*
 * gets the sender nonce of the last message sent
 * returns a pointer to the nonce on success, NULL on error
 */
ASN1_OCTET_STRING *CMP_CTX_get0_last_senderNonce(const OSSL_CMP_CTX *ctx)
{
    return ctx == NULL ? NULL : ctx->last_senderNonce;
}

/*
 * Set the host name of the (HTTP) proxy server to use for all connections
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_proxyName(OSSL_CMP_CTX *ctx, const char *name)
{
    if (ctx == NULL || name == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_PROXYNAME, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    OPENSSL_free(ctx->proxyName);
    ctx->proxyName = NULL;

    ctx->proxyName = BUF_strdup(name);
    if (ctx->proxyName == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_PROXYNAME, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return 1;
}

/*
 * Set the (HTTP) host name of the CA server
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_serverName(OSSL_CMP_CTX *ctx, const char *name)
{
    if (ctx == NULL || name == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SERVERNAME, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    OPENSSL_free(ctx->serverName);
    ctx->serverName = NULL;

    ctx->serverName = BUF_strdup(name);
    if (!ctx->serverName) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SERVERNAME, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return 1;
}

/*
 * sets the (HTTP) proxy port to be used
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_proxyPort(OSSL_CMP_CTX *ctx, int port)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET_PROXYPORT, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx->proxyPort = port;
    return 1;
}

/*
 * sets the http connect/disconnect callback function to be used for HTTP(S)
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_http_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_http_cb_t cb)
{
    if (ctx == NULL)
        return 0;
    ctx->http_cb = cb;
    return 1;
}

/*
 * Set argument optionally to be used by the http connect/disconnect callback
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_http_cb_arg(OSSL_CMP_CTX *ctx, void *arg)
{
    if (ctx == NULL)
        return 0;

    ctx->http_cb_arg = arg;
    return 1;
}

/*
 * Get argument optionally to be used by the http connect/disconnect callback
 * returns callback argument set previously (NULL if not set or on error)
 */
void *OSSL_CMP_CTX_get_http_cb_arg(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    return ctx->http_cb_arg;
}

/*
 * Set callback function for sending CMP request and receiving response.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_transfer_cb(OSSL_CMP_CTX *ctx, OSSL_cmp_transfer_cb_t cb)
{
    if (ctx == NULL)
        return 0;

    ctx->transfer_cb = cb;
    return 1;
}

/*
 * Set argument optionally to be used by the transfer callback
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_transfer_cb_arg(OSSL_CMP_CTX *ctx, void *arg)
{
    if (ctx == NULL)
        return 0;

    ctx->transfer_cb_arg = arg;
    return 1;
}

/*
 * Get argument optionally to be used by the transfer callback
 * returns callback argument set previously (NULL if not set or on error)
 */
void *OSSL_CMP_CTX_get_transfer_cb_arg(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    return ctx->transfer_cb_arg;
}

/*
 * sets the (HTTP) server port to be used
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_serverPort(OSSL_CMP_CTX *ctx, int port)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET_SERVERPORT, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx->serverPort = port;
    return 1;
}

/*
 * Sets the HTTP path to be used on the server (e.g "pkix/")
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set1_serverPath(OSSL_CMP_CTX *ctx, const char *path)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SERVERPATH, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    /* clear the old value */
    OPENSSL_free(ctx->serverPath);
    ctx->serverPath = NULL;

    if (path == NULL) {
        /* clear the serverPath */
        ctx->serverPath = OPENSSL_zalloc(1);
        if (ctx->serverPath == NULL)
            goto oom;
        return 1;
    }

    ctx->serverPath = BUF_strdup(path);
    if (ctx->serverPath == NULL)
        goto oom;

    return 1;
 oom:
    CMPerr(CMP_F_OSSL_CMP_CTX_SET1_SERVERPATH, ERR_R_MALLOC_FAILURE);
    return 0;
}

/*
 * Set the failInfo error code bits in OSSL_CMP_CTX based on the given
 * OSSL_CMP_PKIFAILUREINFO structure, which is allowed to be NULL
 * returns 1 on success, 0 on error
 */
int CMP_CTX_set_failInfoCode(OSSL_CMP_CTX *ctx,
                             OSSL_CMP_PKIFAILUREINFO *fail_info)
{
    int i;

    if (ctx == NULL)
        return 0;
    if (fail_info == NULL)
        return 1;

    ctx->failInfoCode = 0;
    for (i = 0; i <= OSSL_CMP_PKIFAILUREINFO_MAX; i++)
        if (ASN1_BIT_STRING_get_bit(fail_info, i))
            ctx->failInfoCode |= (1 << i);

    return 1;
}

/*
 * Get the failinfo error code bits in OSSL_CMP_CTX
 * returns bit string as integer on success, -1 on error
 */
int OSSL_CMP_CTX_failInfoCode_get(OSSL_CMP_CTX *ctx)
{
    if (ctx == NULL)
        return -1;
    return ctx->failInfoCode;
}

#if 0
/*
 * pushes a given 0-terminated character string to ctx->freeText
 * this is intended for human consumption
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_push_freeText(OSSL_CMP_CTX *ctx, const char *text)
{
    if (ctx == NULL) {
        CMPerr(CMP_F_OSSL_CMP_CTX_PUSH_FREETEXT, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx->freeText = CMP_PKIFREETEXT_push_str(ctx->freeText, text);
    return ctx->freeText != NULL;
}
#endif

/*
 * sets a BOOLEAN or INT option of the context to the "val" arg
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_CTX_set_option(OSSL_CMP_CTX *ctx, int opt, int val) {
    if (ctx == NULL)
        return 0;
    switch (opt) {
    case OSSL_CMP_OPT_IMPLICITCONFIRM:
        ctx->implicitConfirm = val;
        break;
    /* to cope with broken server ignoring implicit confirmation */
    case OSSL_CMP_OPT_DISABLECONFIRM:
        ctx->disableConfirm = val;
        break;
    case OSSL_CMP_OPT_UNPROTECTED_SEND:
        ctx->unprotectedSend = val;
        break;
    case OSSL_CMP_OPT_UNPROTECTED_ERRORS:
        ctx->unprotectedErrors = val;
        break;
    case OSSL_CMP_OPT_VALIDITYDAYS:
        ctx->days = val;
        break;
    case OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT:
        ctx->SubjectAltName_nodefault = val;
        break;
    case OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL:
        ctx->setSubjectAltNameCritical = val;
        break;
    case OSSL_CMP_OPT_POLICIES_CRITICAL:
        ctx->setPoliciesCritical = val;
        break;
    case OSSL_CMP_OPT_IGNORE_KEYUSAGE:
        ctx->ignore_keyusage = val;
        break;
    case OSSL_CMP_OPT_POPOMETHOD:
        ctx->popoMethod = val;
        break;
    case OSSL_CMP_OPT_DIGEST_ALGNID:
        ctx->digest = val;
        break;
    case OSSL_CMP_OPT_MSGTIMEOUT:
        ctx->msgtimeout = val;
        break;
    case OSSL_CMP_OPT_TOTALTIMEOUT:
        ctx->totaltimeout = val;
        break;
    case OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR:
        ctx->permitTAInExtraCertsForIR = val;
        break;
    case OSSL_CMP_OPT_REVOCATION_REASON:
        ctx->revocationReason = val;
        break;
    default:
        return 0;
    }

    return 1;
}

/*
 * Function used for outputting error/warn/debug messages depending on
 * log callback in ctx. By default the function OSSL_CMP_puts() is used.
 */
int OSSL_CMP_printf(const OSSL_CMP_CTX *ctx,
                    const char *func, const char *file, int lineno,
                    OSSL_CMP_severity level, const char *fmt, ...)
{
    va_list argp;
    int res;
    OSSL_cmp_log_cb_t log_fn = ctx == NULL ? NULL : ctx->log_cb;

    va_start(argp, fmt);
    res = OSSL_CMP_log_printf(log_fn, func, file, lineno, level, fmt, argp);
    va_end(argp);
    return res;
}

/* print OpenSSL and CMP errors via the log cb of the ctx or OSSL_CMP_puts */
void OSSL_CMP_print_errors(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_print_errors_cb(ctx == NULL ? NULL : ctx->log_cb);
}
