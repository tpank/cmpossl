/* crypto/cmp/cmp_msg.c
 * Functions for creating CMP (RFC 4210) messages for OpenSSL
 */
/* ====================================================================
 * Originally written by Martin Peylo for the OpenSSL project.
 * <martin dot peylo at nsn dot com>
 * 2010-2014 Miikka Viljanen <mviljane@users.sourceforge.net>
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
 *
 */
/* ====================================================================
 * Copyright 2007-2014 Nokia Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by
 * Nokia for contribution to the OpenSSL project.
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/safestack.h>
#include <openssl/err.h>

#include <string.h>

#include "cmp_int.h"
#include "../crmf/crmf_int.h" /* TODO: integrate into one folder */

/* ##########################################################################
 * Takes a stack of GENERAL_NAMEs and adds them to the given extension stack.
 * this is used to setting subject alternate names to a certTemplate
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
static int add_altname_extensions(X509_EXTENSIONS ** exts,
                                  STACK_OF (GENERAL_NAME) * altnames,
                                  int critical)
{
    X509_EXTENSION *ext = NULL;
    unsigned char *der = NULL;
    ASN1_OCTET_STRING *str = NULL;
    int dlen;

    if (!exts)
        goto err;
    if (!altnames)
        goto err;

    if (!(str = ASN1_OCTET_STRING_new()))
        goto err;

    dlen = i2d_GENERAL_NAMES(altnames, &der);
    if (dlen == 0 || der == NULL)
        goto err;

    if (!ASN1_STRING_set(str, der, dlen))
        goto err;
    if (!X509_EXTENSION_create_by_NID
        (&ext, NID_subject_alt_name, critical, str))
        goto err;

    ASN1_OCTET_STRING_free(str);
    OPENSSL_free(der);

    if (!X509v3_add_ext(exts, ext, 0))
        goto err;

    X509_EXTENSION_free(ext);

    return 1;
 err:
    if (ext)
        X509_EXTENSION_free(ext);
    return 0;
}

/* ##########################################################################
 * Takes a CERTIFICATEPOLICIES structure and adds it to the given extension
 * stack. This is used to setting certificate policy OIDs to a certTemplate
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
static int add_policy_extensions(X509_EXTENSIONS ** exts,
                                 CERTIFICATEPOLICIES *policies)
{
    X509_EXTENSION *ext = NULL;
    unsigned char *der = NULL;
    int derlen = 0;
    ASN1_OCTET_STRING *str = NULL;

    if (!exts || !policies)
        goto err;

    if (!(str = ASN1_OCTET_STRING_new()))
        goto err;

    derlen = i2d_CERTIFICATEPOLICIES(policies, &der);
    if (!ASN1_STRING_set(str, der, derlen))
        goto err;
    if (!X509_EXTENSION_create_by_NID(&ext, NID_certificate_policies, 1, str))
        goto err;

    ASN1_OCTET_STRING_free(str);
    OPENSSL_free(der);

    if (!X509v3_add_ext(exts, ext, 0))
        goto err;

    X509_EXTENSION_free(ext);

    return 1;
 err:
    if (ext)
        X509_EXTENSION_free(ext);
    return 0;
}

/* ########################################################################## *
 * Creates a new polling request PKIMessage for the given request ID
 * returns a pointer to the PKIMessage on success, NULL on error
 * ########################################################################## */
CMP_PKIMESSAGE *CMP_pollReq_new(CMP_CTX *ctx, int reqId)
{
    CMP_PKIMESSAGE *msg = NULL;
    CMP_POLLREQ *preq = NULL;

    if (!ctx)
        goto err;

    if (!(msg = CMP_PKIMESSAGE_new()))
        goto err;
    if (!CMP_PKIHEADER_init(ctx, msg->header))
        goto err;
    if (!CMP_PKIMESSAGE_set_bodytype(msg, V_CMP_PKIBODY_POLLREQ))
        goto err;

    if (!(preq = CMP_POLLREQ_new()))
        goto err;
    /* TODO support multiple cert request ids to poll */
    ASN1_INTEGER_set(preq->certReqId, reqId);
    if (!(msg->body->value.pollReq = sk_CMP_POLLREQ_new_null()))
        goto err;

    sk_CMP_POLLREQ_push(msg->body->value.pollReq, preq);

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;

    return msg;
 err:
    CMPerr(CMP_F_CMP_POLLREQ_NEW, CMP_R_ERROR_CREATING_POLLREQ);
    if (msg)
        CMP_PKIMESSAGE_free(msg);
    return NULL;
}

static X509_EXTENSIONS *exts_dup(X509_EXTENSIONS *extin) {
    X509_EXTENSIONS *exts = NULL;
    if (extin) {
        int i;
        if (!(exts = sk_X509_EXTENSION_new_null()))
            goto err;
        for (i = 0; i < sk_X509_EXTENSION_num(extin); i++)
            if (!sk_X509_EXTENSION_push(exts, X509_EXTENSION_dup(
                            sk_X509_EXTENSION_value(extin, i))))
                goto err;
    }
    return exts;
 err:
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return NULL;
}

static X509_NAME* determine_subj(CMP_CTX *ctx, X509 *oldcert, int bodytype) {
    if (ctx->subjectName)
        return ctx->subjectName;
    else if (oldcert && (bodytype == V_CMP_PKIBODY_KUR ||
                sk_GENERAL_NAME_num(ctx->subjectAltNames) <= 0))
    /* For KUR, copy subjectName from previous certificate.
     * For IR or CR, get subject name from previous certificate, but only
     * if there's no subjectAltName. */
        return X509_get_subject_name(oldcert);
    return NULL;
}

/* ########################################################################## *
 * Create certificate request PKIMessage for IR/CR/KUR/P10CR
 * returns a pointer to the PKIMessage on success, NULL on error
 * ########################################################################## */
CMP_PKIMESSAGE *CMP_certreq_new(CMP_CTX *ctx, int bodytype, int err_code)
{
    CMP_PKIMESSAGE *msg = NULL;
    CRMF_CERTREQMSG *cr0 = NULL;
    X509_EXTENSIONS *exts = NULL;

    if (!ctx ||
        (bodytype != V_CMP_PKIBODY_P10CR && !ctx->pkey && !ctx->newPkey)) {
        CMPerr(CMP_F_CMP_CERTREQ_NEW, CMP_R_INVALID_ARGS);
        return NULL;
    }

    if (!(msg = CMP_PKIMESSAGE_new()))
        goto err;

    /* header */
    (void)CMP_CTX_set1_transactionID(ctx, NULL); /* start new transaction */
    if (!CMP_PKIHEADER_init(ctx, msg->header))
        goto err;
    if (ctx->implicitConfirm)
        if (!CMP_PKIMESSAGE_set_implicitConfirm(msg))
            goto err;

    if (ctx->geninfo_itavs)
        if (!CMP_PKIMESSAGE_generalInfo_items_push1(msg, ctx->geninfo_itavs))
            goto err;

    /* body */
    if (!CMP_PKIMESSAGE_set_bodytype(msg, bodytype))
        goto err;
    if (bodytype == V_CMP_PKIBODY_P10CR) {
        if (!(msg->body->value.p10cr = X509_REQ_dup(ctx->p10CSR)))
            goto err;
    } else {
        X509_NAME *subject = NULL;
        EVP_PKEY *rkey = NULL;
        X509 *oldcert = NULL;

        /* for KUR, oldcert defaults to current client cert */
        oldcert = ctx->oldClCert ? ctx->oldClCert : ctx->clCert;
        subject = determine_subj(ctx, oldcert, bodytype);
        rkey = ctx->newPkey ? ctx->newPkey : ctx->pkey; /* dflt curr clnt key */

        if (!(msg->body->value.ir = sk_CRMF_CERTREQMSG_new_null()))
            goto err; /* value.ir is same for cr and kur */

        if (!(cr0 = CRMF_CERTREQMSG_new()))
            goto err;
#if 0
        if (!CRMF_CERTREQMSG_set_version2(cr0)) /* RFC4211: SHOULD be omitted */
            goto err;
#endif
        if (!CRMF_CERTREQMSG_set_certReqId(cr0, CERTREQID))
            goto err;
        /* rekey cannot be NULL so far - but it can be when centralized key
           creation is supported --> Feature Request #14 */
        if (!CRMF_CERTREQMSG_set1_publicKey(cr0, rkey))
            goto err;
        if (subject)
            if (!CRMF_CERTREQMSG_set1_subject(cr0, subject))
                goto err;
        if (ctx->issuer)
            if (!CRMF_CERTREQMSG_set1_issuer(cr0, ctx->issuer))
                goto err;
        if (ctx->days) {
            time_t notBefore, notAfter;
            notBefore = time(NULL);
            notAfter = notBefore + 60 * 60 * 24 * ctx->days;
            if (!CRMF_CERTREQMSG_set_validity(cr0, notBefore, notAfter))
                goto err;
        }

        /* extensions */ /* exts are copied from ctx to allow reuse */
        if (ctx->reqExtensions && !(exts = exts_dup(ctx->reqExtensions)))
            goto err;
        if (sk_GENERAL_NAME_num(ctx->subjectAltNames) > 0)
            /* TODO: for KUR, if <= 0, maybe copy any existing SANs from
                     oldcert --> Feature Reqest #39  */
            /* RFC5280: subjectAltName MUST be critical if subject is null */
            if (!add_altname_extensions(&exts, ctx->subjectAltNames,
                                        ctx->setSubjectAltNameCritical
                                        || subject == NULL))
                goto err;
        if (ctx->policies)
            if (add_policy_extensions(&exts, ctx->policies))
                goto err;
        if (!CRMF_CERTREQMSG_set0_extensions(cr0, exts))
            goto err;
        exts = NULL;

        /* sets the id-regCtrl-regToken to regInfo (not described in RFC, but
           EJBCA in CA mode might insist on that) */
        if (bodytype == V_CMP_PKIBODY_IR && ctx->regToken)
            if (!CRMF_CERTREQMSG_set1_regInfo_regToken(cr0, ctx->regToken))
                goto err;

        /* for KUR, setting OldCertId according to D.6 */
        if (bodytype == V_CMP_PKIBODY_KUR)
            if (!CRMF_CERTREQMSG_set1_regCtrl_oldCertID_from_cert(cr0, oldcert))
                goto err;

        if (!CRMF_CERTREQMSG_create_popo(cr0, rkey, ctx->digest,
                                         ctx->popoMethod))
            goto err;

        if (!sk_CRMF_CERTREQMSG_push(msg->body->value.ir, cr0))
            goto err;
        cr0 = NULL;
        /* TODO: here optional 2nd certreqmsg could be pushed to the stack */
    }

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(CMP_F_CMP_CERTREQ_NEW, err_code);
    if (exts)
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    if (cr0)
        CRMF_CERTREQMSG_free(cr0);
    if (msg)
        CMP_PKIMESSAGE_free(msg);
    return NULL;
}

/* ########################################################################## *
 * Creates a new Revocation Request PKIMessage for ctx->oldClCert based on
 * the settings in ctx.
 * returns a pointer to the PKIMessage on success, NULL on error
 * ########################################################################## */
CMP_PKIMESSAGE *CMP_rr_new(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *msg = NULL;
    CRMF_CERTTEMPLATE *certTpl = NULL;
    X509_NAME *subject = NULL;
    EVP_PKEY *pubkey = NULL;
    CMP_REVDETAILS *rd = NULL;

    if (!ctx || !ctx->oldClCert) {
        CMPerr(CMP_F_CMP_RR_NEW, CMP_R_INVALID_ARGS);
        return NULL;
    }

    (void)CMP_CTX_set1_transactionID(ctx, NULL); /* start new transaction */
    if (!(msg = CMP_PKIMESSAGE_new()))
        goto err;
    if (!CMP_PKIHEADER_init(ctx, msg->header))
        goto err;
    if (!CMP_PKIMESSAGE_set_bodytype(msg, V_CMP_PKIBODY_RR))
        goto err;

    if (ctx->geninfo_itavs)
        if (!CMP_PKIMESSAGE_generalInfo_items_push1(msg, ctx->geninfo_itavs))
            goto err;

    if (!(msg->body->value.rr = sk_CMP_REVDETAILS_new_null()))
        goto err;
    if (!(rd = CMP_REVDETAILS_new()))
        goto err;
    sk_CMP_REVDETAILS_push(msg->body->value.rr, rd);

    /* Fill the template from the contents of the certificate to be revoked;
     * TODO: maybe add further fields */
    certTpl = rd->certDetails;
    if (!(subject = X509_get_subject_name(ctx->oldClCert)))
        goto err;
    X509_NAME_set(&certTpl->subject, subject);

    if (!(pubkey = X509_get_pubkey(ctx->oldClCert)))
        goto err;
    X509_PUBKEY_set(&certTpl->publicKey, pubkey);
    EVP_PKEY_free(pubkey);

    if (!(certTpl->serialNumber =
          ASN1_INTEGER_dup(X509_get_serialNumber(ctx->oldClCert))))
        goto err;
    X509_NAME_set(&certTpl->issuer, X509_get_issuer_name(ctx->oldClCert));

    /* revocation reason code is optional */
    if (ctx->revocationReason != CRL_REASON_NONE) {
        ASN1_ENUMERATED *val;
        X509_EXTENSION *ext;
        val = ASN1_ENUMERATED_new();
        if (!val || !ASN1_ENUMERATED_set(val, ctx->revocationReason))
            goto err;
        ext = X509_EXTENSION_create_by_NID(NULL, NID_crl_reason, 0, val);
        if (!ext || !X509v3_add_ext(&rd->crlEntryDetails, ext, -1))
            goto err;
        X509_EXTENSION_free(ext);
        ASN1_ENUMERATED_free(val);
    }

    /* TODO: the Revocation Passphrase according to section 5.3.19.9 could be
     *       set here if set in ctx */

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(CMP_F_CMP_RR_NEW, CMP_R_ERROR_CREATING_RR);
    if (msg)
        CMP_PKIMESSAGE_free(msg);

    return NULL;
}

/* ########################################################################## *
 * Creates a new Certificate Confirmation PKIMessage
 * returns a pointer to the PKIMessage on success, NULL on error
 * TODO: handle both possible certificates when signing and encrypting
 * certificates have been requested/received
 * ########################################################################## */
CMP_PKIMESSAGE *CMP_certConf_new(CMP_CTX *ctx, int failure, const char *text)
{
    CMP_PKIMESSAGE *msg = NULL;
    CMP_CERTSTATUS *certStatus = NULL;

    if (!ctx || !ctx->newClCert) {
        CMPerr(CMP_F_CMP_CERTCONF_NEW, CMP_R_INVALID_ARGS);
        return NULL;
    }

    if (!(msg = CMP_PKIMESSAGE_new()))
        goto err;
    if (!CMP_PKIHEADER_init(ctx, msg->header))
        goto err;
    if (!CMP_PKIMESSAGE_set_bodytype(msg, V_CMP_PKIBODY_CERTCONF))
        goto err;
    if (!(msg->body->value.certConf = sk_CMP_CERTSTATUS_new_null()))
        goto err;

    if (!(certStatus = CMP_CERTSTATUS_new()))
        goto err;
    if (!sk_CMP_CERTSTATUS_push(msg->body->value.certConf, certStatus))
        goto err;
    /* set the # of the certReq */
    ASN1_INTEGER_set(certStatus->certReqId, CERTREQID);
    /* -- the hash of the certificate, using the same hash algorithm
     * -- as is used to create and verify the certificate signature */
    if (!CMP_CERTSTATUS_set_certHash(certStatus, ctx->newClCert))
        goto err;
    /*
       For any particular CertStatus, omission of the statusInfo field
       indicates ACCEPTANCE of the specified certificate.  Alternatively,
       explicit status details (with respect to acceptance or rejection) MAY
       be provided in the statusInfo field, perhaps for auditing purposes at
       the CA/RA.
    */
    if (failure >= 0) {
        CMP_PKISTATUSINFO *sinfo;
        sinfo = CMP_statusInfo_new(CMP_PKISTATUS_rejection, failure, text);
        if (sinfo == NULL)
            goto err;
        certStatus->statusInfo = sinfo;
        CMP_printf(ctx, "INFO: rejecting certificate.");
    }

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(CMP_F_CMP_CERTCONF_NEW, CMP_R_ERROR_CREATING_CERTCONF);
    if (msg)
        CMP_PKIMESSAGE_free(msg);

    return NULL;
}

/* ########################################################################## *
 * Creates a new General Message with an empty itav stack
 * returns a pointer to the PKIMessage on success, NULL on error
 * ########################################################################## */
CMP_PKIMESSAGE *CMP_genm_new(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *msg = NULL;

    if (!ctx) {
        CMPerr(CMP_F_CMP_GENM_NEW, CMP_R_INVALID_ARGS);
        return NULL;
    }

    (void)CMP_CTX_set1_transactionID(ctx, NULL); /* start new transaction */
    if (!(msg = CMP_PKIMESSAGE_new()))
        goto err;
    if (!CMP_PKIHEADER_init(ctx, msg->header))
        goto err;
    if (!CMP_PKIMESSAGE_set_bodytype(msg, V_CMP_PKIBODY_GENM))
        goto err;

    if (ctx->geninfo_itavs)
        if (!CMP_PKIMESSAGE_generalInfo_items_push1(msg, ctx->geninfo_itavs))
            goto err;

    if (!(msg->body->value.genm = sk_CMP_INFOTYPEANDVALUE_new_null()))
        goto err;

    if (ctx->genm_itavs)
        if (!CMP_PKIMESSAGE_genm_items_push1(msg, ctx->genm_itavs))
            goto err;

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(CMP_F_CMP_GENM_NEW, CMP_R_ERROR_CREATING_GENM);
    if (msg)
        CMP_PKIMESSAGE_free(msg);
    return NULL;
}

/* ########################################################################## *
 * Creates a new Error Message with the given contents
 * returns a pointer to the PKIMessage on success, NULL on error
 * ########################################################################## */
CMP_PKIMESSAGE *CMP_error_new(CMP_CTX *ctx, CMP_PKISTATUSINFO *si,
                              int errorCode, CMP_PKIFREETEXT *errorDetails)
{
    CMP_PKIMESSAGE *msg = NULL;

    if (!ctx || !si) {
        CMPerr(CMP_F_CMP_ERROR_NEW, CMP_R_INVALID_ARGS);
        return NULL;
    }

    if (!(msg = CMP_PKIMESSAGE_new()))
        goto err;
    if (!CMP_PKIHEADER_init(ctx, msg->header))
        goto err;
    if (!CMP_PKIMESSAGE_set_bodytype(msg, V_CMP_PKIBODY_ERROR))
        goto err;
    if (!(msg->body->value.error = CMP_ERRORMSGCONTENT_new()))
        goto err;

    CMP_PKISTATUSINFO_free(msg->body->value.error->pKIStatusInfo);
    msg->body->value.error->pKIStatusInfo = si;
    if (errorCode >= 0) {
        msg->body->value.error->errorCode = ASN1_INTEGER_new();
        if (!ASN1_INTEGER_set(msg->body->value.error->errorCode, errorCode))
            goto err;
    }
    msg->body->value.error->errorDetails = errorDetails;

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;
    return msg;

 err:
    CMPerr(CMP_F_CMP_ERROR_NEW, CMP_R_ERROR_CREATING_ERROR);
    CMP_PKIMESSAGE_free(msg);
    return NULL;
}
