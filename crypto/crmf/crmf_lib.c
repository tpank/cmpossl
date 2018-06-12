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

/* NAMING
 * The 0 version uses the supplied structure pointer directly in the parent and
 * it will be freed up when the parent is freed. In the above example crl would
 * be freed but rev would not.
 *
 * The 1 function uses a copy of the supplied structure pointer (or in some
 * cases increases its link count) in the parent and so both (x and obj above)
 * should be freed up.
 */

/*
 * This file contains the functions which set the individual items inside
 * the CRMF structures
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crmf_int.h"

/*
 * atyp = Attribute Type
 * valt = Value Type
 * ctrlinf = "regCtrl" or "regInfo"
 */
#define IMPLEMENT_CRMF_CTRL_FUNC(atyp, valt, ctrlinf)                     \
int OSSL_CRMF_CERTREQMSG_set1_##ctrlinf##_##atyp(OSSL_CRMF_CERTREQMSG *msg,         \
                                         valt *in)                        \
{                                                                         \
    CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;                              \
    if (msg == NULL || in  == NULL)                                       \
        goto err;                                                         \
    if ((atav = CRMF_ATTRIBUTETYPEANDVALUE_new()) == NULL)                \
        goto err;                                                         \
    if ((atav->type = OBJ_nid2obj(NID_id_##ctrlinf##_##atyp)) == NULL)    \
        goto err;                                                         \
    if ((atav->value.atyp = valt##_dup(in)) == NULL)                      \
        goto err;                                                         \
    if (!OSSL_CRMF_CERTREQMSG_push0_##ctrlinf(msg, atav))                      \
        goto err;                                                         \
    return 1;                                                             \
 err:                                                                     \
    if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free(atav);                      \
    return 0;                                                             \
}


/*
 * Pushes the given control attribute into the controls stack of a CertRequest
 * (section 6)
 * returns 1 on success, 0 on error
 */
static int OSSL_CRMF_CERTREQMSG_push0_regCtrl(OSSL_CRMF_CERTREQMSG *crm,
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
    CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_PUSH0_REGCTRL, CRMF_R_ERROR);

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
IMPLEMENT_CRMF_CTRL_FUNC(pkiPublicationInfo, OSSL_CRMF_PKIPUBLICATIONINFO, regCtrl)

 /* id-regCtrl-pkiArchiveOptions Control (section 6.4) */
IMPLEMENT_CRMF_CTRL_FUNC(pkiArchiveOptions, OSSL_CRMF_PKIARCHIVEOPTIONS, regCtrl)

 /* id-regCtrl-oldCertID Control (section 6.5) from the given */
IMPLEMENT_CRMF_CTRL_FUNC(oldCertID, OSSL_CRMF_CERTID, regCtrl)

/* TODO should that be done elsewhere? */
int OSSL_CRMF_CERTREQMSG_set1_regCtrl_oldCertID_from_cert(OSSL_CRMF_CERTREQMSG *crm,
                                                     X509 *oldc) {
    int ret;
    OSSL_CRMF_CERTID *cid = NULL;

    if (crm == NULL || oldc == NULL)
        goto err;

    if ((cid = OSSL_CRMF_CERTID_new()) == NULL)
        goto err;

    if (!X509_NAME_set(&cid->issuer->d.directoryName,
                       X509_get_issuer_name(oldc)))
        goto err;
    cid->issuer->type = GEN_DIRNAME;

    ASN1_INTEGER_free(cid->serialNumber);
    if ((cid->serialNumber =
         ASN1_INTEGER_dup(X509_get_serialNumber(oldc))) == NULL)
        goto err;

    ret = OSSL_CRMF_CERTREQMSG_set1_regCtrl_oldCertID(crm, cid);
    OSSL_CRMF_CERTID_free(cid);
    return ret;
 err:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_SET1_REGCTRL_OLDCERTID_FROM_CERT,
            CRMF_R_ERROR);
    if (cid)
        OSSL_CRMF_CERTID_free(cid);
    return 0;
}


 /*
  * id-regCtrl-protocolEncrKey Control (section 6.6) */
 /*
  * For some reason X509_PUBKEY_dup() is not implemented in OpenSSL X509
  * TODO: check whether that should go elsewhere
  */
static IMPLEMENT_ASN1_DUP_FUNCTION(X509_PUBKEY)
IMPLEMENT_CRMF_CTRL_FUNC(protocolEncrKey, X509_PUBKEY, regCtrl)

/*
 * Pushes the attribute given in regInfo in to the CertReqMsg->regInfo stack.
 * (section 7)
 * returns 1 on success, 0 on error
 */
static int OSSL_CRMF_CERTREQMSG_push0_regInfo(OSSL_CRMF_CERTREQMSG *crm,
                                  CRMF_ATTRIBUTETYPEANDVALUE *ri)
{
    int new = 0;

    if (crm == NULL || ri == NULL)
        goto err;

    if ((crm->regInfo) == NULL) {
        if ((crm->regInfo = sk_CRMF_ATTRIBUTETYPEANDVALUE_new_null()) == NULL)
            goto err;
        new = 1;
    }
    if (!sk_CRMF_ATTRIBUTETYPEANDVALUE_push(crm->regInfo, ri))
        goto err;
    return 1;
 err:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_PUSH0_REGINFO, CRMF_R_ERROR);

    if (new) {
        sk_CRMF_ATTRIBUTETYPEANDVALUE_free(crm->regInfo);
        crm->regInfo = NULL;
    }
    return 0;
}

 /* id-regInfo-utf8Pairs to regInfo (section 7.1) */
IMPLEMENT_CRMF_CTRL_FUNC(utf8Pairs, ASN1_UTF8STRING, regInfo)

 /* id-regInfo-certReq to regInfo (section 7.2) */
IMPLEMENT_CRMF_CTRL_FUNC(certReq, OSSL_CRMF_CERTREQUEST, regInfo)


static OSSL_CRMF_CERTTEMPLATE *tmpl(OSSL_CRMF_CERTREQMSG *crm) {
    if (crm->certReq == NULL)
        return NULL;
    return crm->certReq->certTemplate;
}


int OSSL_CRMF_CERTREQMSG_set_version2(OSSL_CRMF_CERTREQMSG *crm)
{
    if (crm  == NULL || tmpl(crm) == NULL)
        goto err;

    if ((tmpl(crm)->version) == NULL)
        tmpl(crm)->version = ASN1_INTEGER_new();
    ASN1_INTEGER_set(tmpl(crm)->version, 2L);
    return 1;
 err:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_SET_VERSION2, CRMF_R_ERROR);
    return 0;
}


int OSSL_CRMF_CERTREQMSG_set_validity(OSSL_CRMF_CERTREQMSG *crm, time_t from, time_t to)
{
    CRMF_OPTIONALVALIDITY *vld = NULL;
    ASN1_TIME *from_asn = NULL;
    ASN1_TIME *to_asn = NULL;

    if (crm == NULL || tmpl(crm) == NULL)
        goto err;

    if (from && ((from_asn = ASN1_TIME_set(NULL, from)) == NULL))
        goto err;
    if (to && ((to_asn = ASN1_TIME_set(NULL, to)) == NULL))
        goto err;
    if ((vld = CRMF_OPTIONALVALIDITY_new()) == NULL)
        goto err;

    vld->notBefore = from_asn;
    vld->notAfter = to_asn;

    tmpl(crm)->validity = vld;

    return 1;
 err:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_SET_VALIDITY, CRMF_R_ERROR);
    if (from_asn)
        ASN1_TIME_free(from_asn);
    if (to_asn)
        ASN1_TIME_free(to_asn);
    return 0;
}


int OSSL_CRMF_CERTREQMSG_set_certReqId(OSSL_CRMF_CERTREQMSG *crm, long rid)
{
    if (crm == NULL || crm->certReq == NULL)
        goto err;

    return ASN1_INTEGER_set(crm->certReq->certReqId, rid);
 err:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_SET_CERTREQID, CRMF_R_ERROR);
    return 0;
}


int OSSL_CRMF_CERTREQMSG_set1_publicKey(OSSL_CRMF_CERTREQMSG *crm, const EVP_PKEY *pkey)
{
    if (crm == NULL || tmpl(crm) == NULL || pkey == NULL)
        goto err;

    return X509_PUBKEY_set(&(tmpl(crm)->publicKey), (EVP_PKEY *)pkey);
 err:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_SET1_PUBLICKEY, CRMF_R_ERROR);
    return 0;
}


int OSSL_CRMF_CERTREQMSG_set1_subject(OSSL_CRMF_CERTREQMSG *crm, const X509_NAME *subj)
{
    if (crm == NULL || tmpl(crm) == NULL || subj == NULL)
        goto err;

    return X509_NAME_set(&(tmpl(crm)->subject), (X509_NAME *)subj);
 err:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_SET1_SUBJECT, CRMF_R_ERROR);
    return 0;
}


int OSSL_CRMF_CERTREQMSG_set1_issuer(OSSL_CRMF_CERTREQMSG *crm, const X509_NAME *is)
{
    if (crm == NULL || tmpl(crm) == NULL || is == NULL)
        goto err;

    return X509_NAME_set(&(tmpl(crm)->issuer), (X509_NAME*) is);
err:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_SET1_ISSUER, CRMF_R_ERROR);
    return 0;
}


int OSSL_CRMF_CERTREQMSG_set0_extensions(OSSL_CRMF_CERTREQMSG *crm,
                                     X509_EXTENSIONS *exts)
{
    if (crm == NULL || tmpl(crm) == NULL)
        goto err;

    if (sk_X509_EXTENSION_num(exts) <= 0) {
        sk_X509_EXTENSION_free(exts);
        exts = NULL; /* do not include empty extensions list */
    }

    tmpl(crm)->extensions = exts;
    return 1;
err:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_SET0_EXTENSIONS, CRMF_R_ERROR);
    return 0;
}


int OSSL_CRMF_CERTREQMSG_push0_extension(OSSL_CRMF_CERTREQMSG *crm,
                                    const X509_EXTENSION *ext)
{
    int new = 0;

    if (crm == NULL || tmpl(crm) == NULL || ext == NULL)
        goto err;

    if ((tmpl(crm)->extensions) == NULL) {
        if ((tmpl(crm)->extensions = sk_X509_EXTENSION_new_null()) == NULL)
            goto err;
        new = 1;
    }

    if (!sk_X509_EXTENSION_push(tmpl(crm)->extensions, (X509_EXTENSION *)ext))
        goto err;
    return 1;
 err:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_PUSH0_EXTENSION, CRMF_R_ERROR);

    if (new) {
        sk_X509_EXTENSION_free(tmpl(crm)->extensions);
        tmpl(crm)->extensions = NULL;
    }
    return 0;
}

/*
 * TODO: also support cases 1+2 defined in RFC4211, section 4.1.
 * returns pointer to created OSSL_CRMF_POPOSIGNINGKEY on success, NULL on error
 */
static OSSL_CRMF_POPOSIGNINGKEY *poposigkey_new(OSSL_CRMF_CERTREQUEST *cr,
                                             const EVP_PKEY *pkey, int dgst)
{
    OSSL_CRMF_POPOSIGNINGKEY *ps = NULL;
    int l;
    size_t crlen, max_sig_size;
    unsigned int siglen;
    unsigned char *crder = NULL, *sig = NULL;
    int alg_nid=0, md_nid=0;
    const EVP_MD *alg = NULL;

    EVP_MD_CTX *ctx = NULL;

    if ((ps = OSSL_CRMF_POPOSIGNINGKEY_new()) == NULL)
        goto err;

    /* OpenSSL defaults all bit strings to be encoded as ASN.1 NamedBitList */
    ps->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    ps->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    l = i2d_OSSL_CRMF_CERTREQUEST(cr, &crder);
    if (l < 0 || crder == NULL)
        goto err;
    crlen = (size_t) l;

    max_sig_size = EVP_PKEY_size((EVP_PKEY *)pkey);
    sig = OPENSSL_malloc(max_sig_size);
    if (sig == NULL)
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
        OSSL_CRMF_POPOSIGNINGKEY_free(ps);
    if (crder)
        OPENSSL_free(crder);
    if (ctx)
        EVP_MD_CTX_destroy(ctx);
    if (sig)
        OPENSSL_free(sig);
    return NULL;
}


int OSSL_CRMF_CERTREQMSG_create_popo(OSSL_CRMF_CERTREQMSG *crm, const EVP_PKEY *pkey,
                                int dgst, int ppmtd)
{
    CRMF_PROOFOFPOSSESION *pp = NULL;

    if (ppmtd == CRMF_POPO_NONE)
        return 1;

    if (crm == NULL)
        goto err;
    if (ppmtd == OSSL_CRMF_POPO_SIGNATURE && (pkey == NULL))
        goto err;

    if ((pp = CRMF_PROOFOFPOSSESION_new()) == NULL)
        goto err;

    switch (ppmtd) {
    case CRMF_POPO_RAVERIFIED:
        pp->type = CRMF_PROOFOFPOSESSION_RAVERIFIED;
        pp->value.raVerified = ASN1_NULL_new();
        break;

    case OSSL_CRMF_POPO_SIGNATURE:
        if ((pp->value.signature = poposigkey_new(crm->certReq, pkey, dgst))
            == NULL)
            goto err;
        pp->type = CRMF_PROOFOFPOSESSION_SIGNATURE;
        break;

    case CRMF_POPO_ENCRCERT:
        pp->type = CRMF_PROOFOFPOSESSION_KEYENCIPHERMENT;
        pp->value.keyEncipherment = CRMF_POPOPRIVKEY_new();
        pp->value.keyEncipherment->type = OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE;
        pp->value.keyEncipherment->value.subsequentMessage = ASN1_INTEGER_new();
        ASN1_INTEGER_set(pp->value.keyEncipherment->value.subsequentMessage,
                         OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT);
        break;

    default:
        CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_CREATE_POPO,
                CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO);
        goto err;
    }

    if (crm->popo)
        CRMF_PROOFOFPOSSESION_free(crm->popo);
    crm->popo = pp;

    return 1;
 err:
    CRMFerr(CRMF_F_OSSL_CRMF_CERTREQMSG_CREATE_POPO, CRMF_R_ERROR);
    if (pp)
        CRMF_PROOFOFPOSSESION_free(pp);
    return 0;
}

/*
 * Decrypts the certificate in the given encryptedValue
 * this is needed for the indirect PoP method as in section 5.2.8.2
 *
 * returns a pointer to the decrypted certificate
 * returns NULL on error or if no certificate available
 */
X509 *OSSL_CRMF_ENCRYPTEDVALUE_encCert_get1(OSSL_CRMF_ENCRYPTEDVALUE *ecert,
                                       EVP_PKEY *pkey)
{
    X509 *cert = NULL; /* decrypted certificate */
    EVP_CIPHER_CTX *evp_ctx = NULL; /* context for symmetric encryption */
    unsigned char *ek = NULL; /* decrypted symmetric encryption key */
    const EVP_CIPHER *cipher = NULL; /* used cipher */
    unsigned char *iv = NULL; /* initial vector for symmetric encryption */
    unsigned char *outbuf = NULL; /* decryption output buffer */
    const unsigned char *p = NULL; /* needed for decoding ASN1 */
    int symmAlg = 0; /* NIDs for symmetric algorithm */
    int n, outlen = 0;
    EVP_PKEY_CTX *pkctx = NULL; /* private key context */

    if (ecert == NULL)
        goto err;
    if (ecert->symmAlg == NULL)
        goto err;
    if (!(symmAlg = OBJ_obj2nid(ecert->symmAlg->algorithm)))
        goto err;

    /* first the symmetric key needs to be decrypted */
    if ((pkctx = EVP_PKEY_CTX_new(pkey, NULL)) && EVP_PKEY_decrypt_init(pkctx)){
        ASN1_BIT_STRING *encKey = ecert->encSymmKey;
        size_t eksize = 0;

        if (encKey == NULL)
            goto err;

        if (EVP_PKEY_decrypt(pkctx, NULL, &eksize, encKey->data, encKey->length)
                <= 0
            || (ek = OPENSSL_malloc(eksize)) == NULL
            || EVP_PKEY_decrypt(pkctx, ek, &eksize, encKey->data,
                                encKey->length) <= 0) {
            CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_ENCCERT_GET1,
                    CRMF_R_ERROR_DECRYPTING_SYMMETRIC_KEY);
            goto err;
        }
    } else {
        CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_ENCCERT_GET1,
                CRMF_R_ERROR_DECRYPTING_KEY);
        goto err;
    }

    /* select symmetric cipher based on algorithm given in message */
    if ((cipher = EVP_get_cipherbynid(symmAlg)) == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_ENCCERT_GET1,
                CRMF_R_UNSUPPORTED_CIPHER);
        goto err;
    }
    if ((iv = OPENSSL_malloc(EVP_CIPHER_iv_length(cipher))) == NULL)
        goto err;
    ASN1_TYPE_get_octetstring(ecert->symmAlg->parameter, iv,
                              EVP_CIPHER_iv_length(cipher));

    /*
     * d2i_X509 changes the given pointer, so use p for decoding the message and
     * keep the original pointer in outbuf so the memory can be freed later
     */
    if (ecert->encValue == NULL)
        goto err;
    if ((p = outbuf = OPENSSL_malloc(ecert->encValue->length +
                                     EVP_CIPHER_block_size(cipher))) == NULL)
        goto err;
    evp_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(evp_ctx, 0);

    if (!EVP_DecryptInit(evp_ctx, cipher, ek, iv)
        || !EVP_DecryptUpdate(evp_ctx, outbuf, &outlen,
                              ecert->encValue->data,
                              ecert->encValue->length)
        || !EVP_DecryptFinal(evp_ctx, outbuf + outlen, &n)) {
        CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_ENCCERT_GET1,
                CRMF_R_ERROR_DECRYPTING_CERTIFICATE);
        goto err;
    }
    outlen += n;

    /* convert decrypted certificate from DER to internal ASN.1 structure */
    if ((cert = d2i_X509(NULL, &p, outlen)) == NULL) {
        CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_ENCCERT_GET1,
                CRMF_R_ERROR_DECODING_CERTIFICATE);
        goto err;
    }

    EVP_PKEY_CTX_free(pkctx);
    OPENSSL_free(outbuf);
    EVP_CIPHER_CTX_free(evp_ctx);
    OPENSSL_free(ek);
    OPENSSL_free(iv);
    return cert;
 err:
    CRMFerr(CRMF_F_OSSL_CRMF_ENCRYPTEDVALUE_ENCCERT_GET1,
            CRMF_R_ERROR_DECRYPTING_ENCCERT);
    EVP_PKEY_CTX_free(pkctx);
    OPENSSL_free(outbuf);
    EVP_CIPHER_CTX_free(evp_ctx);
    OPENSSL_free(ek);
    OPENSSL_free(iv);
    return NULL;
}
