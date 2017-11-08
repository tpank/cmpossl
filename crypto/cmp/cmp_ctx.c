/* crypto/cmp/cmp_ctx.c
 * CMP (RFC 4210) context functions for OpenSSL
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

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <string.h>
#ifndef _WIN32
#include <dirent.h>
#endif

#include "cmp_int.h"

/* NAMING
 * The 0 version uses the supplied structure pointer directly in the parent and
 * it will be freed up when the parent is freed. In the above example crl would
 * be freed but rev would not.
 *
 * The 1 function uses a copy of the supplied structure pointer (or in some
 * cases increases its link count) in the parent and so both (x and obj above)
 * should be freed up.
 */

/* OpenSSL ASN.1 macros in CTX struct */
ASN1_SEQUENCE(CMP_CTX) = {
ASN1_OPT(CMP_CTX, referenceValue, ASN1_OCTET_STRING),
    ASN1_OPT(CMP_CTX, secretValue, ASN1_OCTET_STRING),
    ASN1_OPT(CMP_CTX, srvCert, X509),
    ASN1_OPT(CMP_CTX, validatedSrvCert, X509),
    ASN1_OPT(CMP_CTX, clCert, X509),
    ASN1_OPT(CMP_CTX, oldClCert, X509),
    ASN1_OPT(CMP_CTX, p10CSR, X509_REQ),
    ASN1_OPT(CMP_CTX, issuer, X509_NAME),
    ASN1_OPT(CMP_CTX, subjectName, X509_NAME),
    ASN1_SEQUENCE_OF_OPT(CMP_CTX, subjectAltNames, GENERAL_NAME),
    ASN1_SEQUENCE_OF_OPT(CMP_CTX, policies, POLICYINFO),
    ASN1_SEQUENCE_OF_OPT(CMP_CTX, reqExtensions, X509_EXTENSION),
    ASN1_SEQUENCE_OF_OPT(CMP_CTX, extraCertsOut, X509),
    ASN1_SEQUENCE_OF_OPT(CMP_CTX, extraCertsIn, X509),
    ASN1_SEQUENCE_OF_OPT(CMP_CTX, caPubs, X509),
    ASN1_SEQUENCE_OF_OPT(CMP_CTX, lastStatusString, ASN1_UTF8STRING),
    ASN1_OPT(CMP_CTX, newClCert, X509),
    ASN1_OPT(CMP_CTX, recipient, X509_NAME),
    ASN1_OPT(CMP_CTX, recip_used, X509_NAME),
    ASN1_OPT(CMP_CTX, transactionID, ASN1_OCTET_STRING),
    ASN1_OPT(CMP_CTX, recipNonce, ASN1_OCTET_STRING),
    ASN1_SEQUENCE_OF_OPT(CMP_CTX, geninfo_itavs, CMP_INFOTYPEANDVALUE),
    ASN1_SEQUENCE_OF_OPT(CMP_CTX, genm_itavs, CMP_INFOTYPEANDVALUE),
} ASN1_SEQUENCE_END(CMP_CTX)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CTX)

/* ############################################################################ *
 * Returns a duplicate of the given stack of X509 certificates.
 * ############################################################################ */
static STACK_OF (X509) * X509_stack_dup(const STACK_OF (X509) * stack)
{
    STACK_OF (X509) * newsk = NULL;
    int i;

    if (!stack)
        goto err;
    if (!(newsk = sk_X509_new_null()))
        goto err;

    for (i = 0; i < sk_X509_num(stack); i++)
        if (!sk_X509_push(newsk, X509_dup(sk_X509_value(stack, i)))) {
            sk_X509_free(newsk);
            goto err;
        }

    return newsk;
 err:
    return NULL;
}

/* For some reason EVP_PKEY_dup() is not implemented via
 * IMPLEMENT_ASN1_DUP_FUNCTION(EVP_PKEY) in OpenSSL X509
 * TODO: remove the following auxiliary declaration once done, e.g., in
 * crypto/evp/evp_pkey.c */
/* ############################################################################ *
 * Creates a copy of the given EVP_PKEY.
 * returns ptr to duplicated EVP_PKEY on success, NULL on error
 * ############################################################################ */
static EVP_PKEY *EVP_PKEY_dup(const EVP_PKEY *pkey)
{
    EVP_PKEY *pkeyDup = EVP_PKEY_new();
    if (!pkeyDup)
        goto err;

    if (EVP_PKEY_copy_parameters(pkeyDup, pkey))
        return pkeyDup;

 err:
    if (pkeyDup)
        EVP_PKEY_free(pkeyDup);
    return NULL;
}

/* ############################################################################ *
 * Get current certificate store containing trusted root CA certs
 * ############################################################################ */
X509_STORE *CMP_CTX_get0_trustedStore(CMP_CTX *ctx)
{
    if (!ctx)
        return NULL;
    return ctx->trusted_store;
}

/* ############################################################################ *
 * Set certificate store containing trusted (root) CA certs and possibly CRLs
 * and a cert verification callback function used for CMP server authentication.
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_CTX_set0_trustedStore(CMP_CTX *ctx, X509_STORE *store)
{
    if (!store)
        return 0;
    if (ctx->trusted_store)
        X509_STORE_free(ctx->trusted_store);
    ctx->trusted_store = store;
    return 1;
}

/* ############################################################################ *
 * Get current list of non-trusted intermediate certs
 * ############################################################################ */
STACK_OF (X509) *CMP_CTX_get0_untrusted_certs(CMP_CTX *ctx)
{
    if (!ctx)
        return NULL;
    return ctx->untrusted_certs;
}

/* ############################################################################ *
 * Set untrusted certificates for path construction in CMP server authentication.
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_CTX_set1_untrusted_certs(CMP_CTX *ctx, STACK_OF (X509) *certs)
{
    if (ctx->untrusted_certs)
        sk_X509_pop_free(ctx->untrusted_certs, X509_free);
    ctx->untrusted_certs = sk_X509_new_null();
    return CMP_sk_X509_add1_certs(ctx->untrusted_certs, certs, 0, 1/*no dups*/);
}

/* ################################################################ *
 * Allocates and initializes a CMP_CTX context structure with some
 * default values.
 * OpenSSL ASN.1 types are initialized to NULL by the call to CMP_CTX_new()
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_init(CMP_CTX *ctx)
{
    if (!ctx) {
        CMPerr(CMP_F_CMP_CTX_INIT, CMP_R_INVALID_CONTEXT);
        goto err;
    }

    /* all other elements are initialized through ASN1 macros */
    ctx->pkey = NULL;
    ctx->newPkey = NULL;

    ctx->pbm_slen = 16;
    ctx->pbm_owf = NID_sha256;
    ctx->pbm_itercnt = 500;
    ctx->pbm_mac = NID_hmac_sha1;

    ctx->days = 0;
    ctx->digest = NID_sha256;
    ctx->popoMethod = CRMF_POPO_SIGNATURE;
    ctx->revocationReason = CRL_REASON_NONE;
    ctx->setSubjectAltNameCritical = 0;
    ctx->permitTAInExtraCertsForIR = 0;
    ctx->implicitConfirm = 0;
    ctx->disableConfirm = 0;
    ctx->unprotectedRequests = 0;
    ctx->unprotectedErrors = 0;
    ctx->ignore_keyusage = 0;
    ctx->maxPollTime = 0;

    ctx->lastPKIStatus = 0;
    ctx->failInfoCode = 0;

    ctx->error_cb = NULL;
    ctx->debug_cb = (cmp_logfn_t) puts;
    ctx->certConf_cb = NULL;
    ctx->trusted_store = X509_STORE_new();
    ctx->untrusted_certs = sk_X509_new_null();

    ctx->serverName = NULL;
    ctx->serverPort = 8080;
    /* serverPath has to be an empty sting if not set since it is not mandatory */
    ctx->serverPath = OPENSSL_zalloc(1); /* this will be freed by CMP_CTX_delete() */
    if (!ctx->serverPath)
        goto err;
    ctx->proxyName = NULL;
    ctx->proxyPort = 8080;
    ctx->msgTimeOut = 2 * 60;
    ctx->tlsBIO = NULL;
    ctx->msg_transfer_fn = CMP_PKIMESSAGE_http_perform;
    return 1;

 err:
    return 0;
}

/* ################################################################ *
 * frees CMP_CTX variables allocated in CMP_CTX_init and calls CMP_CTX_free
 * ################################################################ */
void CMP_CTX_delete(CMP_CTX *ctx)
{
    if (!ctx)
        return;
    if (ctx->pkey)
        EVP_PKEY_free(ctx->pkey);
    if (ctx->newPkey)
        EVP_PKEY_free(ctx->newPkey);
    if (ctx->secretValue)
        OPENSSL_cleanse(ctx->secretValue->data, ctx->secretValue->length);

    if (ctx->serverName)
        OPENSSL_free(ctx->serverName);
    if (ctx->serverPath)
        OPENSSL_free(ctx->serverPath);
    if (ctx->proxyName)
        OPENSSL_free(ctx->proxyName);
    if (ctx->trusted_store)
        X509_STORE_free(ctx->trusted_store);
    if (ctx->untrusted_certs)
        sk_X509_pop_free(ctx->untrusted_certs, X509_free);

    if (ctx->tlsBIO)
        BIO_free(ctx->tlsBIO);
    CMP_CTX_free(ctx);
}

/* ################################################################ *
 * creates and initializes a CMP_CTX structure
 * returns pointer to created CMP_CTX on success, NULL on error
 * ################################################################ */
CMP_CTX *CMP_CTX_create(void)
{
    CMP_CTX *ctx = NULL;

    if (!(ctx = CMP_CTX_new()))
        goto err;
    if (!(CMP_CTX_init(ctx)))
        goto err;

    return ctx;
 err:
    CMPerr(CMP_F_CMP_CTX_CREATE, CMP_R_OUT_OF_MEMORY);
    if (ctx)
        CMP_CTX_free(ctx);
    return NULL;
}

/* ################################################################ *
 * returns the PKIStatus from the last CertRepMessage
 * or Revocation Response, -1 on error
 * ################################################################ */
long CMP_CTX_status_get(CMP_CTX *ctx)
{
    return ctx != NULL ? ctx->lastPKIStatus : -1;
}

/* ################################################################ *
 * returns the statusString from the last CertRepMessage
 * or Revocation Response, NULL on error
 * ################################################################ */
CMP_PKIFREETEXT *CMP_CTX_statusString_get(CMP_CTX *ctx)
{
    return ctx != NULL ? ctx->lastStatusString : NULL;
}

/* ################################################################ *
 * Set callback function for checking if the cert is ok or should
 * it be rejected.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set_certConf_callback(CMP_CTX *ctx, cmp_certConfFn_t cb)
{
    if (!ctx)
        goto err;
    ctx->certConf_cb = cb;
    return 1;
 err:
    return 0;
}

/* ################################################################ *
 * Set a callback function which will receive debug messages.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set_error_callback(CMP_CTX *ctx, cmp_logfn_t cb)
{
    if (!ctx)
        goto err;
    ctx->error_cb = cb;
    return 1;
 err:
    return 0;
}

/* ################################################################ *
 * Set a callback function which will receive error messages.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set_debug_callback(CMP_CTX *ctx, cmp_logfn_t cb)
{
    if (!ctx)
        goto err;
    ctx->debug_cb = cb;
    return 1;
 err:
    return 0;
}

/* ################################################################ *
 * Set the reference value to be used for identification (i.e. the
 * username) when using PBMAC.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_referenceValue(CMP_CTX *ctx, const unsigned char *ref,
                                size_t len)
{
    if (!ctx || !ref) {
        CMPerr(CMP_F_CMP_CTX_SET1_REFERENCEVALUE, CMP_R_INVALID_PARAMETERS);
        goto err;
    }

    if (!ctx->referenceValue)
        ctx->referenceValue = ASN1_OCTET_STRING_new();

    return (ASN1_OCTET_STRING_set(ctx->referenceValue, ref, len));
 err:
    return 0;
}

/* ################################################################ *
 * Set the password to be used for protecting messages with PBMAC
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_secretValue(CMP_CTX *ctx, const unsigned char *sec,
                             const size_t len)
{
    if (!ctx)
        goto err;
    if (!sec)
        goto err;

    if (ctx->secretValue)
        OPENSSL_cleanse(ctx->secretValue->data, ctx->secretValue->length);
    else
        ctx->secretValue = ASN1_OCTET_STRING_new();

    return (ASN1_OCTET_STRING_set(ctx->secretValue, sec, len));
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_SECRETVALUE, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Returns the stack of certificates received in a response message.
 * The stack is duplicated so the caller must handle freeing it!
 * returns pointer to created stack on success, NULL on error
 * ################################################################ */
STACK_OF (X509) * CMP_CTX_extraCertsIn_get1(CMP_CTX *ctx)
{
    if (!ctx)
        goto err;
    if (!ctx->extraCertsIn)
        return NULL;
    return X509_stack_dup(ctx->extraCertsIn);
 err:
    CMPerr(CMP_F_CMP_CTX_EXTRACERTSIN_GET1, CMP_R_INVALID_PARAMETERS);
    return NULL;
}

/* ################################################################ *
 * Pops and returns one certificate from the received extraCerts field
 * returns pointer certificate on success, NULL on error
 * ################################################################ */
X509 *CMP_CTX_extraCertsIn_pop(CMP_CTX *ctx)
{
    if (!ctx)
        goto err;
    if (!ctx->extraCertsIn)
        return NULL;
    return sk_X509_pop(ctx->extraCertsIn);
 err:
    CMPerr(CMP_F_CMP_CTX_EXTRACERTSIN_POP, CMP_R_NULL_ARGUMENT);
    return NULL;
}

/* ################################################################ *
 * Returns the number of extraCerts received in a response, 0 on error
 * TODO: should that return something else on error?
 * ################################################################ */
int CMP_CTX_extraCertsIn_num(CMP_CTX *ctx)
{
    if (!ctx)
        goto err;
    if (!ctx->extraCertsIn)
        return 0;
    return sk_X509_num(ctx->extraCertsIn);
 err:
    CMPerr(CMP_F_CMP_CTX_EXTRACERTSIN_NUM, CMP_R_INVALID_PARAMETERS);
    return 0;
}

/* ################################################################ *
 * Copies the given stack of inbound X509 certificates to extraCertsIn of
 * the CMP_CTX structure so that they may be retrieved later.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_extraCertsIn(CMP_CTX *ctx,
                              const STACK_OF (X509) * extraCertsIn)
{
    if (!ctx)
        goto err;
    if (!extraCertsIn)
        goto err;

    /* if there are already inbound extraCerts on the stack delete them */
    if (ctx->extraCertsIn) {
        sk_X509_pop_free(ctx->extraCertsIn, X509_free);
        ctx->extraCertsIn = NULL;
    }

    if (!(ctx->extraCertsIn = X509_stack_dup(extraCertsIn))) {
        CMPerr(CMP_F_CMP_CTX_SET1_EXTRACERTSIN, CMP_R_OUT_OF_MEMORY);
        return 0;
    }

    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_EXTRACERTSIN, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Duplicate and push the given X509 certificate to the stack of
 * outbound certificates to send in the extraCerts field.
 * returns number of pushed certificates on success, 0 on error
 * ################################################################ */
int CMP_CTX_extraCertsOut_push1(CMP_CTX *ctx, const X509 *val)
{
    if (!ctx)
        goto err;
    if ((!ctx->extraCertsOut && !(ctx->extraCertsOut = sk_X509_new_null()))
        || (!sk_X509_push(ctx->extraCertsOut, X509_dup((X509 *)val)))) {
        CMPerr(CMP_F_CMP_CTX_EXTRACERTSOUT_PUSH1, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_EXTRACERTSOUT_PUSH1, CMP_R_INVALID_PARAMETERS);
    return 0;
}

/* ################################################################ *
 * Return the number of certificates we have in the outbound
 * extraCerts stack, 0 on error
 * TODO: should that return something else on error?
 * ################################################################ */
int CMP_CTX_extraCertsOut_num(CMP_CTX *ctx)
{
    if (!ctx)
        goto err;
    if (!ctx->extraCertsOut)
        return 0;
    return sk_X509_num(ctx->extraCertsOut);
 err:
    CMPerr(CMP_F_CMP_CTX_EXTRACERTSOUT_NUM, CMP_R_INVALID_PARAMETERS);
    return 0;
}

/* ################################################################ *
 * Duplicate and set the given stack as the new stack of X509
 * certificates to send out in the extraCerts field.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_extraCertsOut(CMP_CTX *ctx,
                               const STACK_OF (X509) * extraCertsOut)
{
    if (!ctx)
        goto err;
    if (!extraCertsOut)
        goto err;

    if (ctx->extraCertsOut) {
        sk_X509_pop_free(ctx->extraCertsOut, X509_free);
        ctx->extraCertsOut = NULL;
    }

    if (!(ctx->extraCertsOut = X509_stack_dup(extraCertsOut))) {
        CMPerr(CMP_F_CMP_CTX_SET1_EXTRACERTSOUT, CMP_R_OUT_OF_MEMORY);
        return 0;
    }

    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_EXTRACERTSOUT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * CMP_CTX_policyOID_push1() adds the certificate policy OID given by the
 * string to the X509_EXTENSIONS of the certificate template we are
 * requesting.
 * ################################################################ */
int CMP_CTX_policyOID_push1(CMP_CTX *ctx, const char *policyOID)
{
    POLICYINFO *pol = NULL;

    if (!ctx || !policyOID)
        goto err;

    if (!ctx->policies && !(ctx->policies = CERTIFICATEPOLICIES_new()))
        goto err;

    if (!(pol = POLICYINFO_new()))
        goto err;

    pol->policyid = OBJ_txt2obj(policyOID, 1);
    sk_POLICYINFO_push(ctx->policies, pol);

    return 1;

 err:
    return 0;
}

/* ################################################################ *
 * add an itav for geninfo of the PKI message header
 * ################################################################ */
int CMP_CTX_geninfo_itav_push0(CMP_CTX *ctx, const CMP_INFOTYPEANDVALUE *itav)
{
    if (!ctx)
        return 0;

    return CMP_INFOTYPEANDVALUE_stack_item_push0(&ctx->geninfo_itavs, itav);
}

/* ################################################################ *
 * add an itav for the body of outgoing generalmessages
 * ################################################################ */
int CMP_CTX_genm_itav_push0(CMP_CTX *ctx, const CMP_INFOTYPEANDVALUE *itav)
{
    if (!ctx)
        return 0;

    return CMP_INFOTYPEANDVALUE_stack_item_push0(&ctx->genm_itavs, itav);
}

/* ################################################################ *
 * Returns a duplicate of the stack of X509 certificates that
 * were received in the caPubs field of the last response message.
 * returns NULL on error
 * ################################################################ */
STACK_OF (X509) * CMP_CTX_caPubs_get1(CMP_CTX *ctx)
{
    if (!ctx)
        goto err;
    if (!ctx->caPubs)
        return NULL;
    return X509_stack_dup(ctx->caPubs);
 err:
    CMPerr(CMP_F_CMP_CTX_CAPUBS_GET1, CMP_R_INVALID_PARAMETERS);
    return NULL;
}

/* ################################################################ *
 * Pop one certificate out of the list of certificates received in
 * the caPubs field, returns NULL on errror or when the stack is empty
 * ################################################################ */
X509 *CMP_CTX_caPubs_pop(CMP_CTX *ctx)
{
    if (!ctx)
        goto err;
    if (!ctx->caPubs)
        return NULL;
    return sk_X509_pop(ctx->caPubs);
 err:
    CMPerr(CMP_F_CMP_CTX_CAPUBS_POP, CMP_R_INVALID_PARAMETERS);
    return NULL;
}

/* ################################################################ *
 * Return the number of certificates received in the caPubs field
 * of the last response message, 0 on error
 * TODO: should that return something else on error?
 * ################################################################ */
int CMP_CTX_caPubs_num(CMP_CTX *ctx)
{
    if (!ctx)
        goto err;
    if (!ctx->caPubs)
        return 0;
    return sk_X509_num(ctx->caPubs);
 err:
    CMPerr(CMP_F_CMP_CTX_CAPUBS_NUM, CMP_R_INVALID_PARAMETERS);
    return 0;
}

/* ################################################################ *
 * Duplicate and copy the given stack of certificates to the given
 * CMP_CTX structure so that they may be retrieved later.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_caPubs(CMP_CTX *ctx, const STACK_OF (X509) *caPubs)
{
    if (!ctx || !caPubs)
        goto err;

    if (ctx->caPubs) {
        sk_X509_pop_free(ctx->caPubs, X509_free);
        ctx->caPubs = NULL;
    }

    if (!(ctx->caPubs = X509_stack_dup(caPubs))) {
        CMPerr(CMP_F_CMP_CTX_SET1_CAPUBS, CMP_R_OUT_OF_MEMORY);
        return 0;
    }

    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_CAPUBS, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Sets the server certificate to be directly trusted for verifying response
 * messages. Additionally using CMP_CTX_set0_trustedStore() is recommended
 * in order to be able to supply verification parameters like CRLs.
 * Cert pointer is not consumed. It may be NULL to clear the entry.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_srvCert(CMP_CTX *ctx, const X509 *cert)
{
    if (!ctx)
        goto err;

    if (ctx->srvCert) {
        X509_free(ctx->srvCert);
        ctx->srvCert = NULL;
    }
    if (!cert)
        return 1; /* srvCert has been cleared */

    if (!(ctx->srvCert = X509_dup((X509 *)cert))) {
        CMPerr(CMP_F_CMP_CTX_SET1_SRVCERT, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_SRVCERT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Set the X509 name of the recipient. Set in the PKIHeader.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_recipient(CMP_CTX *ctx, const X509_NAME *name)
{
    if (!ctx)
        goto err;
    if (!name)
        goto err;

    if (ctx->recipient) {
        X509_NAME_free(ctx->recipient);
        ctx->recipient = NULL;
    }

    if (!(ctx->recipient = X509_NAME_dup((X509_NAME *)name))) {
        CMPerr(CMP_F_CMP_CTX_SET1_RECIPIENT, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_RECIPIENT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Store the X509 name of the recipient used in the PKIHeader.
 * internal function
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_recip_used(CMP_CTX *ctx, const X509_NAME *name)
{
    if (!ctx)
        goto err;

    if (ctx->recip_used) {
        X509_NAME_free(ctx->recip_used);
        ctx->recip_used = NULL;
    }

    if (!name)
        return 1;

    if (!(ctx->recip_used = X509_NAME_dup((X509_NAME *)name))) {
        CMPerr(CMP_F_CMP_CTX_SET1_RECIP_USED, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_RECIP_USED, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Set the X509 name of the issuer. Set in the PKIHeader.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_issuer(CMP_CTX *ctx, const X509_NAME *name)
{
    if (!ctx) goto err;
    if (!name) goto err;

    if (ctx->issuer)
        {
            X509_NAME_free(ctx->issuer);
            ctx->issuer = NULL;
        }

    if (!(ctx->issuer = X509_NAME_dup( (X509_NAME*)name))) {
        CMPerr(CMP_F_CMP_CTX_SET1_ISSUER, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
err:
    CMPerr(CMP_F_CMP_CTX_SET1_ISSUER, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Set the subject name that will be placed in the certificate
 * request. This will be the subject name on the received certificate.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_subjectName(CMP_CTX *ctx, const X509_NAME *name)
{
    if (!ctx)
        goto err;
    if (!name)
        goto err;

    if (ctx->subjectName) {
        X509_NAME_free(ctx->subjectName);
        ctx->subjectName = NULL;
    }

    if (!(ctx->subjectName = X509_NAME_dup((X509_NAME *)name))) {
        CMPerr(CMP_F_CMP_CTX_SET1_SUBJECTNAME, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_SUBJECTNAME, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * sets the X.509v3 extensions to be used in IR/CR/KUR
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set0_reqExtensions(CMP_CTX *ctx, X509_EXTENSIONS *exts)
{
    if (!ctx)
        goto err;
    if (!exts)
        goto err;

    ctx->reqExtensions = exts;

    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET0_REQEXTENSIONS, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Push a GENERAL_NAME structure that will be added to the CRMF
 * request's extensions field to request subject alternative names.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_subjectAltName_push1(CMP_CTX *ctx, const GENERAL_NAME *name)
{
    if (!ctx)
        goto err;
    if (!name)
        goto err;

    if ((!ctx->subjectAltNames
         && !(ctx->subjectAltNames = sk_GENERAL_NAME_new_null())) ||
        !sk_GENERAL_NAME_push(ctx->subjectAltNames,
                              GENERAL_NAME_dup((GENERAL_NAME *)name))) {
        CMPerr(CMP_F_CMP_CTX_SUBJECTALTNAME_PUSH1, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SUBJECTALTNAME_PUSH1, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Set our own client certificate, used for example in KUR and when
 * doing the IR with existing certificate.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_clCert(CMP_CTX *ctx, const X509 *cert)
{
    if (!ctx)
        goto err;
    if (!cert)
        goto err;

    if (ctx->clCert) {
        X509_free(ctx->clCert);
        ctx->clCert = NULL;
    }

    if (!(ctx->clCert = X509_dup((X509 *)cert))) {
        CMPerr(CMP_F_CMP_CTX_SET1_CLCERT, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_CLCERT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Set the old certificate that we are updating in KUR
 * or the certificate to be revoked in RR, respectively
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_oldClCert(CMP_CTX *ctx, const X509 *cert)
{
    if (!ctx)
        goto err;
    if (!cert)
        goto err;

    if (ctx->oldClCert) {
        X509_free(ctx->oldClCert);
        ctx->oldClCert = NULL;
    }

    if (!(ctx->oldClCert = X509_dup((X509 *)cert))) {
        CMPerr(CMP_F_CMP_CTX_SET1_OLDCLCERT, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_OLDCLCERT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Set the PKCS#10 CSR to be sent in P10CR
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_p10CSR(CMP_CTX *ctx, const X509_REQ *csr)
{
    if (!ctx)
        goto err;
    if (!csr)
        goto err;

    if (ctx->p10CSR) {
        X509_REQ_free(ctx->p10CSR);
        ctx->p10CSR = NULL;
    }

    if (!(ctx->p10CSR = X509_REQ_dup((X509_REQ *)csr))) {
        CMPerr(CMP_F_CMP_CTX_SET1_P10CSR, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_P10CSR, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * sets the (newly received in IP/KUP/CP) client Certificate to the context
 * returns 1 on success, 0 on error
 * TODO: this only permits for one client cert to be received...
 * ################################################################ */
int CMP_CTX_set1_newClCert(CMP_CTX *ctx, const X509 *cert)
{
    if (!ctx)
        goto err;
    if (!cert)
        goto err;

    if (ctx->newClCert) {
        X509_free(ctx->newClCert);
        ctx->newClCert = NULL;
    }

    if (!(ctx->newClCert = X509_dup((X509 *)cert))) {
        CMPerr(CMP_F_CMP_CTX_SET1_NEWCLCERT, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_NEWCLCERT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Get the (newly received in IP/KUP/CP) client certificate from the context
 * TODO: this only permits for one client cert to be received...
 * ################################################################ */
X509 *CMP_CTX_get0_newClCert(CMP_CTX *ctx)
{
    if (!ctx)
        return NULL;
    return ctx->newClCert;
}

/* ################################################################ *
 * Set the client's private key. This creates a duplicate of the key
 * so the given pointer is not used directly.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_pkey(CMP_CTX *ctx, const EVP_PKEY *pkey)
{
    if (!ctx)
        goto err;
    if (!pkey)
        goto err;

    return CMP_CTX_set0_pkey(ctx, EVP_PKEY_dup(pkey));

 err:
    CMPerr(CMP_F_CMP_CTX_SET1_PKEY, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Set the client's current private key. NOTE: this version uses
 * the given pointer directly!
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set0_pkey(CMP_CTX *ctx, const EVP_PKEY *pkey)
{
    if (!ctx)
        goto err;
    if (!pkey)
        goto err;

    if (ctx->pkey) {
        EVP_PKEY_free(ctx->pkey);
        ctx->pkey = NULL;
    }

    ctx->pkey = (EVP_PKEY *)pkey;
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET0_PKEY, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Set new key pair. Used for example when doing Key Update.
 * The key is duplicated so the original pointer is not directly used.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_newPkey(CMP_CTX *ctx, const EVP_PKEY *pkey)
{
    if (!ctx)
        goto err;
    if (!pkey)
        goto err;

    return CMP_CTX_set0_newPkey(ctx, EVP_PKEY_dup(pkey));

 err:
    CMPerr(CMP_F_CMP_CTX_SET1_NEWPKEY, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Set new key pair. Used e.g. when doing Key Update.
 * NOTE: uses the pointer directly!
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set0_newPkey(CMP_CTX *ctx, const EVP_PKEY *pkey)
{
    if (!ctx)
        goto err;
    if (!pkey)
        goto err;

    if (ctx->newPkey) {
        EVP_PKEY_free(ctx->newPkey);
        ctx->newPkey = NULL;
    }

    ctx->newPkey = (EVP_PKEY *)pkey;
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET0_NEWPKEY, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * sets the given transactionID to the context
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_transactionID(CMP_CTX *ctx, const ASN1_OCTET_STRING *id)
{
    if (!ctx)
        goto err;

    if (ctx->transactionID) {
        ASN1_OCTET_STRING_free(ctx->transactionID);
        ctx->transactionID = NULL;
    }
    /* reset ctx->validatedSrvCert */
    X509_free(ctx->validatedSrvCert);
    ctx->validatedSrvCert = NULL;
    if (!id)
        return 1;

    if (!(ctx->transactionID = ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)id))){
        CMPerr(CMP_F_CMP_CTX_SET1_TRANSACTIONID, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_TRANSACTIONID, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * sets the given nonce to be used for the recipNonce in the next message to be
 * created.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_recipNonce(CMP_CTX *ctx, const ASN1_OCTET_STRING *nonce)
{
    if (!ctx)
        goto err;
    if (!nonce)
        goto err;

    if (ctx->recipNonce) {
        ASN1_OCTET_STRING_free(ctx->recipNonce);
        ctx->recipNonce = NULL;
    }

    if (!(ctx->recipNonce = ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)nonce))){
        CMPerr(CMP_F_CMP_CTX_SET1_RECIPNONCE, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_RECIPNONCE, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Set the hostname of the (HTTP) proxy server to use for all connections
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_proxyName(CMP_CTX *ctx, const char *name)
{
    if (!ctx)
        goto err;
    if (!name)
        goto err;

    if (ctx->proxyName) {
        OPENSSL_free(ctx->proxyName);
        ctx->proxyName = NULL;
    }

    ctx->proxyName = BUF_strdup(name);
    if (!ctx->proxyName) {
        CMPerr(CMP_F_CMP_CTX_SET1_PROXYNAME, CMP_R_OUT_OF_MEMORY);
        return 0;
    }

    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_PROXYNAME, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Set the (HTTP) hostname of the CA server
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_serverName(CMP_CTX *ctx, const char *name)
{
    if (!ctx)
        goto err;
    if (!name)
        goto err;

    if (ctx->serverName) {
        OPENSSL_free(ctx->serverName);
        ctx->serverName = NULL;
    }

    ctx->serverName = BUF_strdup(name);
    if (!ctx->serverName) {
        CMPerr(CMP_F_CMP_CTX_SET1_SERVERNAME, CMP_R_OUT_OF_MEMORY);
        return 0;
    }

    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET1_SERVERNAME, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * sets the (HTTP) proxy port to be used
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set_proxyPort(CMP_CTX *ctx, int port)
{
    if (!ctx)
        goto err;

    ctx->proxyPort = port;
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET_PROXYPORT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * sets the SSL/TLS BIO to be used for HTTPS
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set0_tlsBIO(CMP_CTX *ctx, BIO *sbio)
{
    if (!ctx)
        goto err;
    ctx->tlsBIO = sbio;
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET0_TLSBIO, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * returns the SSL/TLS BIO to be used for HTTPS, if any, else NULL
 * ################################################################ */
BIO *CMP_CTX_get0_tlsBIO(CMP_CTX *ctx)
{
    if (ctx)
        return ctx->tlsBIO;
    else
        return NULL;
}

/* ################################################################ *
 * Set callback function for sending CMP request and receiving response.
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set_msg_transfer(CMP_CTX *ctx, cmp_transfer_fn_t cb)
{
    if (!ctx)
        goto err;
    ctx->msg_transfer_fn = cb;
    return 1;
 err:
    return 0;
}

/* ################################################################ *
 * sets the (HTTP) server port to be used
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set_serverPort(CMP_CTX *ctx, int port)
{
    if (!ctx)
        goto err;

    ctx->serverPort = port;
    return 1;
 err:
    CMPerr(CMP_F_CMP_CTX_SET_SERVERPORT, CMP_R_NULL_ARGUMENT);
    return 0;
}

/* ################################################################ *
 * Sets the HTTP path to be used on the server (e.g "pkix/")
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set1_serverPath(CMP_CTX *ctx, const char *path)
{
    if (!ctx) {
        CMPerr(CMP_F_CMP_CTX_SET1_SERVERPATH, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    if (ctx->serverPath) {
        /* clear the old value */
        OPENSSL_free(ctx->serverPath);
        ctx->serverPath = NULL;
    }

    if (!path) {
        /* clear the serverPath */
        ctx->serverPath = OPENSSL_zalloc(1);
        if (!ctx->serverPath)
            goto oom;
        return 1;
    }

    ctx->serverPath = BUF_strdup(path);
    if (!ctx->serverPath)
        goto oom;

    return 1;
 oom:
    CMPerr(CMP_F_CMP_CTX_SET1_SERVERPATH, CMP_R_OUT_OF_MEMORY);
    return 0;
}

/* ################################################################ *
 * Set the failInfo error code bits in CMP_CTX based on the given
 * CMP_PKIFAILUREINFO structure, which is allowed to be NULL
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set_failInfoCode(CMP_CTX *ctx, CMP_PKIFAILUREINFO *failInfo)
{
    int i;

    if (!ctx)
        return 0;
    if (!failInfo)
        return 1;

    ctx->failInfoCode = 0;
    for (i = 0; i <= CMP_PKIFAILUREINFO_MAX; i++)
        if (ASN1_BIT_STRING_get_bit(failInfo, i))
            ctx->failInfoCode |= 1UL << i;

    return 1;
}

/* ################################################################ *
 * Get the failinfo error code bits in CMP_CTX
 * returns bitstring in ulong on success, -1 on error
 * ################################################################ */
unsigned long CMP_CTX_failInfoCode_get(CMP_CTX *ctx)
{
    if (!ctx)
        return -1;
    return ctx->failInfoCode;
}

#if 0
/* ################################################################ *
 * pushes a given 0-terminated character string to ctx->freeText
 * this is intended for human consumption
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_push_freeText(CMP_CTX *ctx, const char *text)
{
    ASN1_UTF8STRING *utf8string = NULL;

    if (!ctx)
        goto err;
    if (!text)
        goto err;

    if (!ctx->freeText)
        if (!(ctx->freeText = sk_ASN1_UTF8STRING_new()))
            goto err;

    if (!(utf8string = ASN1_UTF8STRING_new()))
        goto err;
    ASN1_UTF8STRING_set(utf8string, text, strlen(text));
    if (!(sk_ASN1_UTF8STRING_push(ctx->freeText, utf8string)))
        goto err;
    return 1;

 err:
    CMP_printf("ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
    if (utf8string) ASN1_UTF8STRING_free(utf8string);
    return 0;
}
#endif

/* ################################################################ *
 * sets a BOOLEAN or INT option of the context to the "val" arg
 * returns 1 on success, 0 on error
 * ################################################################ */
int CMP_CTX_set_option(CMP_CTX *ctx, const int opt, const int val) {
    if (!ctx) goto err;
    switch (opt) {
    case CMP_CTX_OPT_IMPLICITCONFIRM:
        ctx->implicitConfirm = val;
        break;
    case CMP_CTX_OPT_DISABLECONFIRM: /* to cope with broken server ignoring implicit confirmation */
        ctx->disableConfirm = val;
        break;
    case CMP_CTX_OPT_UNPROTECTED_REQUESTS:
        ctx->unprotectedRequests = val;
        break;
    case CMP_CTX_OPT_UNPROTECTED_ERRORS:
        ctx->unprotectedErrors = val;
        break;
    case CMP_CTX_OPT_VALIDITYDAYS:
        ctx->days = val;
        break;
    case CMP_CTX_OPT_IGNORE_KEYUSAGE:
        ctx->ignore_keyusage = val;
        break;
    case CMP_CTX_OPT_POPOMETHOD:
        ctx->popoMethod = val;
        break;
    case CMP_CTX_OPT_DIGEST_ALGNID:
        ctx->digest = val;
        break;
    case CMP_CTX_OPT_MSGTIMEOUT:
        ctx->msgTimeOut = val;
        break;
    case CMP_CTX_OPT_MAXPOLLTIME:
        ctx->maxPollTime = val;
        break;
    case CMP_CTX_PERMIT_TA_IN_EXTRACERTS_FOR_IR:
        ctx->permitTAInExtraCertsForIR = val;
        break;
    case CMP_CTX_OPT_SUBJECTALTNAME_CRITICAL:
        ctx->setSubjectAltNameCritical = val;
        break;
    case CMP_CTX_OPT_REVOCATION_REASON:
        ctx->revocationReason = val;
        break;
    default:
        goto err;
    }

    return 1;
  err:
    return 0;
}

/* ################################################################ *
 * Function used for printing debug messages if debug_cb is set
 * (CMP_CTX_INIT defaults to puts)
 * ################################################################ */
void CMP_printf(const CMP_CTX *ctx, const char *fmt, ...) {
#ifdef CMP_DEBUG
    va_list arg_ptr;
    char buf[1024];
    if (!ctx || !ctx->debug_cb)
        return;
    va_start(arg_ptr, fmt);
    BIO_vsnprintf(buf, sizeof(buf), fmt, arg_ptr);
    ctx->debug_cb(buf);
    va_end(arg_ptr);
#endif
}

/* ############################################################################ *
 * This callback is used to print out the OpenSSL error queue via'
 * ERR_print_errors_cb() to the ctx->error_cb() function set by the user
 * returns always 1
 * ############################################################################ */
int CMP_CTX_error_callback(const char *str, size_t len, void *u) {
    CMP_CTX *ctx = (CMP_CTX *)u;
    if (ctx && ctx->error_cb)
        ctx->error_cb(str);
    return 1;
}
