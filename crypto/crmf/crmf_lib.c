/* crypto/crmf/crmf_lib.c
 * CRMF (RFC 4211) library functions for OpenSSL
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
 *
 */
/* ====================================================================
 * Copyright 2007-2014 Nokia Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by
 * Nokia for contribution to the OpenSSL project.
 */
/* NAMING
 * The 0 version uses the supplied structure pointer directly in the parent and
 * it will be freed up when the parent is freed. In the above example crl would
 * be freed but rev would not.
 *
 * The 1 function uses a copy of the supplied structure pointer (or in some
 * cases increases its link count) in the parent and so both (x and obj above)
 * should be freed up.
 */
/* ########################################################################## *
 * In this file are the functions which set the individual items inside       *
 * the CRMF structures                                                        *
 * ########################################################################## */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crmf_int.h"

/* atyp = Attribute Type
 * valt = Value Type
 * ctrlinf = "regCtrl" or "regInfo" */
#define IMPLEMENT_CRMF_CTRL_FUNC(atyp, valt, ctrlinf)                     \
int CRMF_CERTREQMSG_set1_##ctrlinf##_##atyp(CRMF_CERTREQMSG *msg,         \
                                         valt *in)                        \
{                                                                         \
    CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;                              \
    if (!msg || !in) goto err;                                            \
    if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;             \
    if (!(atav->type = OBJ_nid2obj(NID_id_##ctrlinf##_##atyp))) goto err; \
    if (!(atav->value.atyp = valt##_dup(in))) goto err;                   \
    if (!CRMF_CERTREQMSG_push0_##ctrlinf(msg, atav)) goto err;            \
    return 1;                                                             \
 err:                                                                     \
    if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free(atav);                      \
    return 0;                                                             \
}


/* ########################################################################## *
 * Pushes the given control attribute into the controls stack of a CertRequest
 * (section 6)
 * returns 1 on success, 0 on error
 * ########################################################################## */
static int CRMF_CERTREQMSG_push0_regCtrl(CRMF_CERTREQMSG *crm,
                                  CRMF_ATTRIBUTETYPEANDVALUE *ctrl)
{
    int new = 0;

    if (!crm || !crm->certReq || !ctrl)
        goto err;

    if (!(crm->certReq->controls)) {
        if (!(crm->certReq->controls =
                                      sk_CRMF_ATTRIBUTETYPEANDVALUE_new_null()))
            goto err;
        new = 1;
    }
    if (!sk_CRMF_ATTRIBUTETYPEANDVALUE_push(crm->certReq->controls, ctrl))
        goto err;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_PUSH0_REGCTRL, CRMF_R_ERROR);

    if (new) {
        sk_CRMF_ATTRIBUTETYPEANDVALUE_free(crm->certReq->controls);
        crm->certReq->controls = NULL;
    }
    return 0;
}

 /* id-regCtrl-regToken Control (section 6.1) */
IMPLEMENT_CRMF_CTRL_FUNC(regToken, ASN1_STRING, regCtrl)

 /* id-regCtrl-authenticator Control (section 6.2) */
#define ASN1_UTF8STRING_dup ASN1_STRING_dup
IMPLEMENT_CRMF_CTRL_FUNC(authenticator, ASN1_UTF8STRING, regCtrl)

 /* id-regCtrl-pkiPublicationInfo Control (section 6.3) */
IMPLEMENT_CRMF_CTRL_FUNC(pkiPublicationInfo, CRMF_PKIPUBLICATIONINFO, regCtrl)

 /* id-regCtrl-pkiArchiveOptions Control (section 6.4) */
IMPLEMENT_CRMF_CTRL_FUNC(pkiArchiveOptions, CRMF_PKIARCHIVEOPTIONS, regCtrl)

 /* id-regCtrl-oldCertID Control (section 6.5) from the given */
IMPLEMENT_CRMF_CTRL_FUNC(oldCertID, CRMF_CERTID, regCtrl)

/* TODO should that be done elsewhere? */
int CRMF_CERTREQMSG_set1_regCtrl_oldCertID_from_cert(CRMF_CERTREQMSG *crm,
                                                     X509 *oldc) {
    int ret;
    CRMF_CERTID *cid = NULL;

    if (!crm || !oldc)
        goto err;

    if (!(cid = CRMF_CERTID_new()))
        goto err;

    if (!X509_NAME_set(&cid->issuer->d.directoryName,
                X509_get_issuer_name(oldc)))
        goto err;
    cid->issuer->type = GEN_DIRNAME;

    ASN1_INTEGER_free(cid->serialNumber);
    if (!(cid->serialNumber = ASN1_INTEGER_dup(X509_get_serialNumber(oldc))))
        goto err;

    ret = CRMF_CERTREQMSG_set1_regCtrl_oldCertID(crm, cid);
    CRMF_CERTID_free(cid);
    return ret;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_REGCTRL_OLDCERTID_FROM_CERT,
            CRMF_R_ERROR);
    if (cid) {
        CRMF_CERTID_free(cid);
    }
    return 0;
}


 /* id-regCtrl-protocolEncrKey Control (section 6.6) */
 /* For some reason X509_PUBKEY_dup() is not implemented in OpenSSL X509
  * TODO: check whether that should go elsewhere */
static IMPLEMENT_ASN1_DUP_FUNCTION(X509_PUBKEY)
IMPLEMENT_CRMF_CTRL_FUNC(protocolEncrKey, X509_PUBKEY, regCtrl)

/* ########################################################################## *
 * Pushes the attribute given in regInfo in to the CertReqMsg->regInfo stack.
 * (section 7)
 * returns 1 on success, 0 on error
 * ########################################################################## */
static int CRMF_CERTREQMSG_push0_regInfo(CRMF_CERTREQMSG *crm,
                                  CRMF_ATTRIBUTETYPEANDVALUE *ri)
{
    int new = 0;

    if (!crm || !ri)
        goto err;

    if (!(crm->regInfo)) {
        if (!(crm->regInfo = sk_CRMF_ATTRIBUTETYPEANDVALUE_new_null()))
            goto err;
        new = 1;
    }
    if (!sk_CRMF_ATTRIBUTETYPEANDVALUE_push(crm->regInfo, ri))
        goto err;
    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_PUSH0_REGINFO, CRMF_R_ERROR);

    if (new) {
        sk_CRMF_ATTRIBUTETYPEANDVALUE_free(crm->regInfo);
        crm->regInfo = NULL;
    }
    return 0;
}

 /* id-regInfo-utf8Pairs to regInfo (section 7.1) */
IMPLEMENT_CRMF_CTRL_FUNC(utf8Pairs, ASN1_UTF8STRING, regInfo)

 /* id-regInfo-certReq to regInfo (section 7.2) */
IMPLEMENT_CRMF_CTRL_FUNC(certReq, CRMF_CERTREQUEST, regInfo)

 /* id-regCtrl-regToken to regInfo (not described in RFC, only by EJBCA) */
 /* TODO: evaluate whether that is needed --> bug#35 */
int CRMF_CERTREQMSG_set1_regInfo_regToken(CRMF_CERTREQMSG *msg,
                                          ASN1_UTF8STRING *tok)
{
    CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;

    if (!msg || !tok)
        goto err;

    if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new()))
        goto err;

    if (!(atav->type = OBJ_nid2obj(NID_id_regCtrl_regToken)))
        goto err;
    if (!(atav->value.regToken = ASN1_STRING_dup(tok)))
        goto err;

    if (!CRMF_CERTREQMSG_push0_regInfo(msg, atav))
        goto err;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_REGINFO_REGTOKEN, CRMF_R_ERROR);
    if (atav)
        CRMF_ATTRIBUTETYPEANDVALUE_free(atav);
    return 0;
}


static CRMF_CERTTEMPLATE *tmpl(CRMF_CERTREQMSG *crm) {
    if (!crm->certReq)
        return NULL;
    return crm->certReq->certTemplate;
}


int CRMF_CERTREQMSG_set_version2(CRMF_CERTREQMSG *crm)
{
    if (!crm || !tmpl(crm))
        goto err;

    if (!(tmpl(crm)->version))
        tmpl(crm)->version = ASN1_INTEGER_new();
    ASN1_INTEGER_set(tmpl(crm)->version, 2L);
    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET_VERSION2, CRMF_R_ERROR);
    return 0;
}


int CRMF_CERTREQMSG_set_validity(CRMF_CERTREQMSG *crm, time_t from, time_t to)
{
    CRMF_OPTIONALVALIDITY *vld = NULL;
    ASN1_TIME *from_asn = NULL;
    ASN1_TIME *to_asn = NULL;

    if (!crm || !tmpl(crm))
        goto err;

    if (from && (!(from_asn = ASN1_TIME_set(NULL, from))))
        goto err;
    if (to && (!(to_asn = ASN1_TIME_set(NULL, to))))
        goto err;
    if (!(vld = CRMF_OPTIONALVALIDITY_new()))
        goto err;

    vld->notBefore = from_asn;
    vld->notAfter = to_asn;

    tmpl(crm)->validity = vld;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET_VALIDITY, CRMF_R_ERROR);
    if (from_asn)
        ASN1_TIME_free(from_asn);
    if (to_asn)
        ASN1_TIME_free(to_asn);
    return 0;
}


int CRMF_CERTREQMSG_set_certReqId(CRMF_CERTREQMSG *crm, long rid)
{
    if (!crm || !crm->certReq)
        goto err;

    return ASN1_INTEGER_set(crm->certReq->certReqId, rid);
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET_CERTREQID, CRMF_R_ERROR);
    return 0;
}


int CRMF_CERTREQMSG_set1_publicKey(CRMF_CERTREQMSG *crm, const EVP_PKEY *pkey)
{
    if (!crm || !tmpl(crm) || !pkey)
        goto err;

    return X509_PUBKEY_set(&(tmpl(crm)->publicKey), (EVP_PKEY *)pkey);
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_PUBLICKEY, CRMF_R_ERROR);
    return 0;
}


int CRMF_CERTREQMSG_set1_subject(CRMF_CERTREQMSG *crm, const X509_NAME *subj)
{
    if (!crm || !tmpl(crm) || !subj)
        goto err;

    return X509_NAME_set(&(tmpl(crm)->subject), (X509_NAME *)subj);
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_SUBJECT, CRMF_R_ERROR);
    return 0;
}


int CRMF_CERTREQMSG_set1_issuer( CRMF_CERTREQMSG *crm, const X509_NAME *is)
{
    if (!crm || !tmpl(crm) || !is)
        goto err;

    return X509_NAME_set(&(tmpl(crm)->issuer), (X509_NAME*) is);
err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_ISSUER, CRMF_R_ERROR);
    return 0;
}


int CRMF_CERTREQMSG_set0_extensions( CRMF_CERTREQMSG *crm,
                                     X509_EXTENSIONS *exts)
{
    if (!crm || !tmpl(crm))
        goto err;

    tmpl(crm)->extensions = exts;
    return 1;
err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET0_EXTENSIONS, CRMF_R_ERROR);
    return 0;
}


int CRMF_CERTREQMSG_push0_extension(CRMF_CERTREQMSG *crm,
                                    const X509_EXTENSION *ext)
{
    int new = 0;

    if (!crm || !tmpl(crm) || !ext)
        goto err;

    if (!tmpl(crm)->extensions) {
        if (!(tmpl(crm)->extensions = sk_X509_EXTENSION_new_null()))
            goto err;
        new = 1;
    }

    if (!sk_X509_EXTENSION_push(tmpl(crm)->extensions, (X509_EXTENSION *)ext))
        goto err;
    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_PUSH0_EXTENSION, CRMF_R_ERROR);

    if (new) {
        sk_X509_EXTENSION_free(tmpl(crm)->extensions);
        tmpl(crm)->extensions = NULL;
    }
    return 0;
}

/* ########################################################################## *
 * TODO: also support cases 1+2 defined in RFC4211, section 4.1.
 * returns pointer to created CRMF_POPOSIGNINGKEY on success, NULL on error
 * ########################################################################## */
static CRMF_POPOSIGNINGKEY *poposigkey_new(CRMF_CERTREQUEST *cr,
                                             const EVP_PKEY *pkey, int dgst)
{
    CRMF_POPOSIGNINGKEY *ps = NULL;
    size_t crlen, max_sig_size;
    unsigned int siglen;
    unsigned char *crder = NULL, *sig = NULL;
    int alg_nid=0, md_nid=0;
    const EVP_MD *alg = NULL;

    EVP_MD_CTX *ctx = NULL;

    if (!(ps = CRMF_POPOSIGNINGKEY_new()))
        goto err;

    /* OpenSSL defaults all bitstrings to be encoded as ASN.1 NamedBitList */
    ps->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    ps->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    crlen = i2d_CRMF_CERTREQUEST(cr, &crder);

    max_sig_size = EVP_PKEY_size((EVP_PKEY *)pkey);
    sig = OPENSSL_malloc(max_sig_size);
    if (!sig)
        goto err;

    if (!OBJ_find_sigid_by_algs(&alg_nid, dgst, EVP_PKEY_id(pkey))) {
        CRMFerr(CRMF_F_POPOSIGKEY_NEW,
                CRMF_R_UNSUPPORTED_ALG_FOR_POPSIGNINGKEY);
        goto err;
    }
    if (!(OBJ_find_sigid_algs(alg_nid, &md_nid, NULL) &&
                (alg = EVP_get_digestbynid(md_nid)))) {
        CRMFerr(CRMF_F_POPOSIGKEY_NEW,
                CRMF_R_UNSUPPORTED_ALG_FOR_POPSIGNINGKEY);
        goto err;
    }
    X509_ALGOR_set0(ps->algorithmIdentifier, OBJ_nid2obj(alg_nid),
                    V_ASN1_NULL, NULL);

    ctx = EVP_MD_CTX_create();
    if (!(EVP_SignInit_ex(ctx, alg, NULL)))
        goto err;
    if (!(EVP_SignUpdate(ctx, crder, crlen)))
        goto err;
    if (!(EVP_SignFinal(ctx, sig, &siglen, (EVP_PKEY *)pkey)))
        goto err;

    if (!(ASN1_BIT_STRING_set(ps->signature, sig, siglen)))
        goto err;

    /* cleanup */
    OPENSSL_free(crder);
    EVP_MD_CTX_destroy(ctx);
    OPENSSL_free(sig);
    return ps;
 err:
    CRMFerr(CRMF_F_POPOSIGKEY_NEW, CRMF_R_ERROR);
    if (ps)
        CRMF_POPOSIGNINGKEY_free(ps);
    if (crder)
        OPENSSL_free(crder);
    if (ctx)
        EVP_MD_CTX_destroy(ctx);
    if (sig)
        OPENSSL_free(sig);
    return NULL;
}


int CRMF_CERTREQMSG_create_popo(CRMF_CERTREQMSG *crm, const EVP_PKEY *pkey,
                                int dgst, int ppmtd)
{
    CRMF_PROOFOFPOSSESION *pp = NULL;

    if (ppmtd == CRMF_POPO_NONE)
        return 1;

    if (!crm)
        goto err;
    if (ppmtd == CRMF_POPO_SIGNATURE && !pkey)
        goto err;

    if (!(pp = CRMF_PROOFOFPOSSESION_new()))
        goto err;

    switch (ppmtd) {
    case CRMF_POPO_RAVERIFIED:
        pp->type = CRMF_PROOFOFPOSESSION_RAVERIFIED;
        pp->value.raVerified = ASN1_NULL_new();
        break;

    case CRMF_POPO_SIGNATURE:
        if (!(pp->value.signature = poposigkey_new(crm->certReq, pkey, dgst)))
            goto err;
        pp->type = CRMF_PROOFOFPOSESSION_SIGNATURE;
        break;

    case CRMF_POPO_ENCRCERT:
        pp->type = CRMF_PROOFOFPOSESSION_KEYENCIPHERMENT;
        pp->value.keyEncipherment = CRMF_POPOPRIVKEY_new();
        pp->value.keyEncipherment->type = CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE;
        pp->value.keyEncipherment->value.subsequentMessage = ASN1_INTEGER_new();
        ASN1_INTEGER_set(pp->value.keyEncipherment->value.subsequentMessage,
                         CRMF_SUBSEQUENTMESSAGE_ENCRCERT);
        break;

    default:
        CRMFerr(CRMF_F_CRMF_CERTREQMSG_CREATE_POPO,
                CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO);
        goto err;
    }

    if (crm->popo)
        CRMF_PROOFOFPOSSESION_free(crm->popo);
    crm->popo = pp;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_CREATE_POPO, CRMF_R_ERROR);
    if (pp)
        CRMF_PROOFOFPOSSESION_free(pp);
    return 0;
}
