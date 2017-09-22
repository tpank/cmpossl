/* crypto/cmp/cmp_lib.c
 * CMP (RFC 4210) library functions for OpenSSL
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
 * In this file are the functions which set the individual items inside
 * the CMP structures
 * ########################################################################## */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/safestack.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
/* for bio_err */
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_STORE_CTX_get0_chain X509_STORE_CTX_get_chain
#endif

#include <time.h>
#include <string.h>

#include "cmp_int.h"

/* ########################################################################## *
 * Adds text to the extra error data field of the last error in openssl's error
 * queue. ERR_add_error_data() simply overwrites the previous contents of the
 * error data, while this function can be used to add a string to the end of it.
 * ########################################################################## */
void CMP_add_error_data(const char *txt)
{
    const char *current_error = NULL;
    ERR_peek_last_error_line_data(NULL, NULL, &current_error, NULL);
    ERR_add_error_data(3, current_error, ":", txt);
}

/* ########################################################################## *
 * Sets the protocol version number in PKIHeader.
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIHEADER_set_version(CMP_PKIHEADER *hdr, int version)
{
    if (!hdr)
        goto err;

    if (!ASN1_INTEGER_set(hdr->pvno, version))
        goto err;

    return 1;
 err:
    return 0;
}


static int cpy_gname(GENERAL_NAME **tgt, const X509_NAME *src) {
    GENERAL_NAME *gen = NULL;

    if (!(gen = GENERAL_NAME_new()))
        goto err;

    gen->type = GEN_DIRNAME;

    if (src == NULL) {
        gen->d.directoryName = X509_NAME_new();
    } else if (!(X509_NAME_set(&gen->d.directoryName, (X509_NAME *)src))) {
        goto err;
    }

    if (*tgt)
        GENERAL_NAME_free(*tgt);

    *tgt = gen;

    return 1;
 err:
    if (gen)
        GENERAL_NAME_free(gen);
    return 0;
}

/* ########################################################################## *
 * Set the recipient name of PKIHeader.
 * when nm is NULL, recipient is set to an empty string
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIHEADER_set1_recipient(CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
    if (!hdr)
        return 0;

    return cpy_gname(&hdr->recipient, nm);
}

/* ########################################################################## *
 * Set the sender name in PKIHeader.
 * when nm is NULL, sender is set to an empty string
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIHEADER_set1_sender(CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
    if (!hdr)
        return 0;

    return cpy_gname(&hdr->sender, nm);
}

/* ########################################################################## *
 * (re-)set given transaction ID in CMP header
 * if given *transactionID is NULL, a random one is created with 128 bit
 * according to section 5.1.1:
 *
 * It is RECOMMENDED that the clients fill the transactionID field with
 * 128 bits of (pseudo-) random data for the start of a transaction to
 * reduce the probability of having the transactionID in use at the
 * server.
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIHEADER_set1_transactionID(CMP_PKIHEADER *hdr,
                                     const ASN1_OCTET_STRING *transactionID)
{
#define TRANSACTIONID_LENGTH 16
    unsigned char *transactionIDuchar = NULL;

    if (!hdr)
        goto err;

    if (transactionID) {
        if (!(hdr->transactionID =
              ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)transactionID)))
            goto err;
    } else {
        /* generate a random value if none was given */
        if (!(transactionIDuchar =
              (unsigned char *)OPENSSL_malloc(TRANSACTIONID_LENGTH)))
            goto err;
        RAND_bytes(transactionIDuchar, TRANSACTIONID_LENGTH);

        if (hdr->transactionID == NULL) {
            hdr->transactionID = ASN1_OCTET_STRING_new();
        }
        if (!(ASN1_OCTET_STRING_set
              (hdr->transactionID, transactionIDuchar, TRANSACTIONID_LENGTH)))
            goto err;

        OPENSSL_free(transactionIDuchar);
    }

    return 1;
 err:
    if (transactionIDuchar)
        OPENSSL_free(transactionIDuchar);
    return 0;
}

/* ########################################################################## *
 * (re-)set random senderNonce to given header
 * as in 5.1.1:
 *
 * senderNonce                  present
 *         -- 128 (pseudo-)random bits
 * The senderNonce and recipNonce fields protect the PKIMessage against
 * replay attacks.      The senderNonce will typically be 128 bits of
 * (pseudo-) random data generated by the sender, whereas the recipNonce
 * is copied from the senderNonce of the previous message in the
 * transaction.
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIHEADER_new_senderNonce(CMP_PKIHEADER *hdr)
{
#define SENDERNONCE_LENGTH 16
    unsigned char senderNonce[SENDERNONCE_LENGTH];

    if (!hdr)
        goto err;

    RAND_bytes(senderNonce, SENDERNONCE_LENGTH);

    if (hdr->senderNonce == NULL) {
        hdr->senderNonce = ASN1_OCTET_STRING_new();
    }

    if (!(ASN1_OCTET_STRING_set
          (hdr->senderNonce, senderNonce, SENDERNONCE_LENGTH)))
        goto err;

    return 1;
 err:
    return 0;
}

/* ########################################################################## *
 * (re-)sets given recipient nonce to given header
 * as per 5.1.1 used to mirror the nonce back to the other side
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIHEADER_set1_recipNonce(CMP_PKIHEADER *hdr,
                                  const ASN1_OCTET_STRING *recipNonce)
{
    if (!hdr)
        goto err;
    if (!recipNonce)
        goto err;

    if (hdr->recipNonce)
        ASN1_OCTET_STRING_free(hdr->recipNonce);

    if (!(hdr->recipNonce =
          ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)recipNonce)))
        goto err;

    return 1;
 err:
    return 0;
}

/* ########################################################################## *
 * (re-)set given senderKID to given header
 *
 * senderKID: keyIdentifier of the sender's certificate or PBMAC reference value
 *       -- the reference number which the CA has previously issued
 *       -- to the end entity (together with the MACing key)
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIHEADER_set1_senderKID(CMP_PKIHEADER *hdr,
                                 const ASN1_OCTET_STRING *senderKID)
{
    if (!hdr)
        goto err;
    if (!senderKID)
        goto err;

    if (hdr->senderKID)
        ASN1_OCTET_STRING_free(hdr->senderKID);

    if (!(hdr->senderKID =
          ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)senderKID)))
        goto err;

    return 1;
 err:
    return 0;
}

/* ########################################################################## *
 * (re-)set the messageTime to the current system time
 *
 * as in 5.1.1:
 *
 * The messageTime field contains the time at which the sender created
 * the message.  This may be useful to allow end entities to
 * correct/check their local time for consistency with the time on a
 * central system.
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIHEADER_set_messageTime(CMP_PKIHEADER *hdr)
{
    if (!hdr)
        goto err;

    if (!hdr->messageTime)
        hdr->messageTime = ASN1_GENERALIZEDTIME_new();

    if (!ASN1_GENERALIZEDTIME_set(hdr->messageTime, time(NULL)))
        goto err;
    return 1;
 err:
    return 0;
}

/* ########################################################################## *
 * push given ASN1_UTF8STRING to hdr->freeText and consume the given pointer
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIHEADER_push0_freeText(CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text)
{
    if (!hdr)
        goto err;
    if (!text)
        goto err;

    if (!hdr->freeText)
        if (!(hdr->freeText = sk_ASN1_UTF8STRING_new_null()))
            goto err;

    if (!(sk_ASN1_UTF8STRING_push(hdr->freeText, text)))
        goto err;

    return 1;
 err:
    return 0;
}

/* ########################################################################## *
 * push an ASN1_UTF8STRING to hdr->freeText and don't consume the given pointer
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIHEADER_push1_freeText(CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text)
{
    ASN1_UTF8STRING *textDup = NULL;

    if (!hdr)
        goto err;
    if (!text)
        goto err;

    if (!(textDup = ASN1_UTF8STRING_new()))
        goto err;
    if (!ASN1_STRING_set(textDup, text->data, text->length))
        goto err;

    return CMP_PKIHEADER_push0_freeText(hdr, textDup);
 err:
    if (textDup)
        ASN1_UTF8STRING_free(textDup);
    return 0;
}

/* ########################################################################## *
 * Initialize the given PkiHeader structure with values set in the CMP_CTX
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIHEADER_init(CMP_CTX *ctx, CMP_PKIHEADER *hdr)
{
    X509_NAME *recipient = NULL;

    if (!ctx || !hdr)
        goto err;

    /* set the CMP version */
    CMP_PKIHEADER_set_version(hdr, CMP_VERSION);

    /* in case there is no OLD client cert the sender name is not set
     * (e.g. for IR) */
    if (ctx->clCert) {
        if (!CMP_PKIHEADER_set1_sender
            (hdr, X509_get_subject_name((X509 *)ctx->clCert)))
            goto err;
    } else {
        if (!CMP_PKIHEADER_set1_sender(hdr, NULL))
            goto err;
    }

    /* set recipient name either from known server certificate or recipient
       or ctx->issuer or issuer of ctx->oldClCert or issuer of ctx->clCert */
    if (ctx->srvCert)
        recipient = X509_get_subject_name(ctx->srvCert);
    else if (ctx->recipient)
        recipient = ctx->recipient;
    else if (ctx->issuer)
        recipient = ctx->issuer;
    else if (ctx->oldClCert)
        recipient = X509_get_issuer_name(ctx->oldClCert);
    else if (ctx->clCert)
        recipient = X509_get_issuer_name(ctx->clCert);
    if (!CMP_PKIHEADER_set1_recipient(hdr, recipient))
        goto err;

    /* set current time as message time */
    if (!CMP_PKIHEADER_set_messageTime(hdr))
        goto err;

    if (ctx->recipNonce)
        if (!CMP_PKIHEADER_set1_recipNonce(hdr, ctx->recipNonce))
            goto err;

    if (ctx->transactionID) {
        if (!CMP_PKIHEADER_set1_transactionID(hdr, ctx->transactionID))
            goto err;
    } else {
        /* create new transaction ID */
        if (!CMP_PKIHEADER_set1_transactionID(hdr, NULL))
            goto err;
        if (!CMP_CTX_set1_transactionID(ctx, hdr->transactionID))
            goto err;
    }

    if (!CMP_PKIHEADER_new_senderNonce(hdr))
        goto err;

#if 0
    /*
       freeText                [7] PKIFreeText                         OPTIONAL,
       -- this may be used to indicate context-specific instructions
       -- (this field is intended for human consumption)
     */
    if (ctx->freeText)
        if (!CMP_PKIHEADER_push1_freeText(hdr, ctx->freeText))
            goto err;
#endif

    return 1;
 err:
    return 0;
}

/* ########################################################################## *
 * also used for verification from cmp_vfy
 *
 * calculate PBMAC protection for given PKImessage utilizing the given secret
 * and the pbm-parameters set inside the message header's protectionAlg
 *
 * returns pointer to ASN1_BIT_STRING containing protection on success, NULL on
 * error
 * ########################################################################## */
ASN1_BIT_STRING *CMP_calc_protection_pbmac(const CMP_PKIMESSAGE *pkimessage,
                                           const ASN1_OCTET_STRING *secret)
{
    ASN1_BIT_STRING *prot = NULL;
    CMP_PROTECTEDPART protPart;
    ASN1_STRING *pbmStr = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x1010001fL
    const
#endif
    ASN1_OBJECT *algorOID = NULL;

    CRMF_PBMPARAMETER *pbm = NULL;

    size_t protPartDerLen;
    unsigned int macLen;
    unsigned char *protPartDer = NULL;
    unsigned char *mac = NULL;
    const unsigned char *pbmStrUchar = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x1010001fL
    const
#endif
    void *ppval = NULL;
    int pptype = 0;

    if (!secret) {
        CMPerr(CMP_F_CMP_CALC_PROTECTION_PBMAC,
               CMP_R_NO_SECRET_VALUE_GIVEN_FOR_PBMAC);
        goto err;
    }

    protPart.header = pkimessage->header;
    protPart.body = pkimessage->body;
    protPartDerLen = i2d_CMP_PROTECTEDPART(&protPart, &protPartDer);

    X509_ALGOR_get0(&algorOID, &pptype, &ppval,
                    pkimessage->header->protectionAlg);

    if (NID_id_PasswordBasedMAC == OBJ_obj2nid(algorOID)) {
        /* there is no pbm set in this message */
        if (!ppval)
            goto err;

        pbmStr = (ASN1_STRING *)ppval;
        pbmStrUchar = (unsigned char *)pbmStr->data;
        pbm = d2i_CRMF_PBMPARAMETER(NULL, &pbmStrUchar, pbmStr->length);

        if (!(CRMF_passwordBasedMac_new
              (pbm, protPartDer, protPartDerLen, secret->data, secret->length,
               &mac, &macLen)))
            goto err;
    } else {
        CMPerr(CMP_F_CMP_CALC_PROTECTION_PBMAC, CMP_R_WRONG_ALGORITHM_OID);
        goto err;
    }

    if (!(prot = ASN1_BIT_STRING_new()))
        goto err;
    /* OpenSSL defaults all bitstrings to be encoded as ASN.1 NamedBitList */
    prot->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    prot->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    ASN1_BIT_STRING_set(prot, mac, macLen);

    /* cleanup */
    OPENSSL_free(protPartDer);
    CRMF_PBMPARAMETER_free(pbm);
    OPENSSL_free(mac);
    return prot;

 err:
    CMPerr(CMP_F_CMP_CALC_PROTECTION_PBMAC,
           CMP_R_ERROR_CALCULATING_PROTECTION);
    if (pbm)
        CRMF_PBMPARAMETER_free(pbm);
    if (mac)
        OPENSSL_free(mac);
    if (protPartDer)
        OPENSSL_free(protPartDer);
    return NULL;
}

/* ########################################################################## *
 * only used internally
 *
 * calculate signature protection for given PKImessage utilizing the given
 * secret key and the algorithm parameters set inside the message header's
 * protectionAlg
 *
 * returns pointer to ASN1_BIT_STRING containing protection on success, NULL on
 * error
 * ########################################################################## */
/* TODO factor out similarities with CMP_calc_protection_pbmac */
ASN1_BIT_STRING *CMP_calc_protection_sig(CMP_PKIMESSAGE *pkimessage,
                                         EVP_PKEY *pkey)
{
    ASN1_BIT_STRING *prot = NULL;
    CMP_PROTECTEDPART protPart;
#if OPENSSL_VERSION_NUMBER >= 0x1010001fL
    const
#endif
    ASN1_OBJECT *algorOID = NULL;

    size_t protPartDerLen;
    unsigned int macLen;
    size_t maxMacLen;
    unsigned char *protPartDer = NULL;
    unsigned char *mac = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x1010001fL
    const
#endif
    void *ppval = NULL;
    int pptype = 0;

    EVP_MD_CTX *evp_ctx = NULL;
    int md_NID;
    const EVP_MD *md = NULL;

    /* EVP_SignFinal() will check that pkey type is correct for the algorithm */
    if (!pkey) {
        CMPerr(CMP_F_CMP_CALC_PROTECTION_SIG, CMP_R_INVALID_KEY);
        goto err;
    }

    /* construct data to be signed */
    protPart.header = pkimessage->header;
    protPart.body = pkimessage->body;
    protPartDerLen = i2d_CMP_PROTECTEDPART(&protPart, &protPartDer);
    /* TODO: should here be caught if protPardDer is NULL? */

    X509_ALGOR_get0(&algorOID, &pptype, &ppval,
                    pkimessage->header->protectionAlg);

    if (OBJ_find_sigid_algs(OBJ_obj2nid(algorOID), &md_NID, NULL)
        && (md = EVP_get_digestbynid(md_NID))) {
        maxMacLen = EVP_PKEY_size(pkey);
        mac = OPENSSL_malloc(maxMacLen);
        if (!mac)
            goto err;

        /* calculate signature */
        evp_ctx = EVP_MD_CTX_create();
        if (!evp_ctx)
            goto err;
        if (!(EVP_SignInit_ex(evp_ctx, md, NULL)))
            goto err;
        if (!(EVP_SignUpdate(evp_ctx, protPartDer, protPartDerLen)))
            goto err;
        if (!(EVP_SignFinal(evp_ctx, mac, &macLen, pkey)))
            goto err;
    } else {
        CMPerr(CMP_F_CMP_CALC_PROTECTION_SIG, CMP_R_UNKNOWN_ALGORITHM_ID);
        goto err;
    }

    if (!(prot = ASN1_BIT_STRING_new()))
        goto err;
    /* OpenSSL defaults all bitstrings to be encoded as ASN.1 NamedBitList */
    prot->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    prot->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    ASN1_BIT_STRING_set(prot, mac, macLen);

    /* cleanup */
    EVP_MD_CTX_destroy(evp_ctx);
    OPENSSL_free(mac);
    if (protPartDer)
        OPENSSL_free(protPartDer);
    return prot;

 err:
    if (evp_ctx)
        EVP_MD_CTX_destroy(evp_ctx);
    if (mac)
        OPENSSL_free(mac);
    if (protPartDer)
        OPENSSL_free(protPartDer);

    CMPerr(CMP_F_CMP_CALC_PROTECTION_SIG, CMP_R_ERROR_CALCULATING_PROTECTION);
    return NULL;
}

/* ########################################################################## *
 * internal function
 * Create an X509_ALGOR structure for PasswordBasedMAC protection based on
 * the pbm settings in the context
 * returns pointer to X509_ALGOR on success, NULL on error
 * ########################################################################## */
static X509_ALGOR *CMP_create_pbmac_algor(CMP_CTX *ctx)
{
    X509_ALGOR *alg = NULL;
    CRMF_PBMPARAMETER *pbm = NULL;
    unsigned char *pbmDer = NULL;
    int pbmDerLen;
    ASN1_STRING *pbmStr = NULL;

    if (!(alg = X509_ALGOR_new()))
        goto err;
    if (!(pbm = CRMF_pbmp_new(ctx->pbm_slen, ctx->pbm_owf,
                              ctx->pbm_itercnt, ctx->pbm_mac)))
        goto err;
    if (!(pbmStr = ASN1_STRING_new()))
        goto err;

    pbmDerLen = i2d_CRMF_PBMPARAMETER(pbm, &pbmDer);

    ASN1_STRING_set(pbmStr, pbmDer, pbmDerLen);
    OPENSSL_free(pbmDer);

    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_id_PasswordBasedMAC),
                    V_ASN1_SEQUENCE, pbmStr);

    CRMF_PBMPARAMETER_free(pbm);
    return alg;
 err:
    if (alg)
        X509_ALGOR_free(alg);
    if (pbm)
        CRMF_PBMPARAMETER_free(pbm);
    return NULL;
}

/* ########################################################################## *
 * Determines which kind of protection should be created, based on the ctx.
 * Sets this into the protectionAlg field in the message header.
 * Calculates the protection and sets it in the protection field.
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIMESSAGE_protect(CMP_CTX *ctx, CMP_PKIMESSAGE *msg)
{
    if (!ctx)
        goto err;
    if (!msg)
        goto err;
    if (ctx->unprotectedRequests)
        return 1;

    /* use PasswordBasedMac according to 5.1.3.1 if secretValue is given */
    if (ctx->secretValue) {
        if (!(msg->header->protectionAlg = CMP_create_pbmac_algor(ctx)))
            goto err;
        CMP_PKIHEADER_set1_senderKID(msg->header, ctx->referenceValue);

        /* add any additional certificates from ctx->extraCertsOut
         * while not needed to validate the signing cert, the option to do
         * this might be handy for certain use cases */
        CMP_PKIMESSAGE_add_extraCerts(ctx, msg);

        if (!(msg->protection =
              CMP_calc_protection_pbmac(msg, ctx->secretValue)))
            goto err;
    } else {
        /* use MSG_SIG_ALG according to 5.1.3.3 if client Certificate and
         * private key is given */
        if (ctx->clCert && ctx->pkey) {
            ASN1_OCTET_STRING *subjKeyIDStr = NULL;
            int algNID = 0;
            ASN1_OBJECT *alg = NULL;

            /* make sure that key and certificate match */
            if (!X509_check_private_key(ctx->clCert, ctx->pkey)) {
                CMPerr(CMP_F_CMP_PKIMESSAGE_PROTECT,
                        CMP_R_CERT_AND_KEY_DO_NOT_MATCH);
                goto err;
            }

            if (!msg->header->protectionAlg)
                msg->header->protectionAlg = X509_ALGOR_new();

            if (!OBJ_find_sigid_by_algs(&algNID, ctx->digest,
                        EVP_PKEY_id(ctx->pkey))) {
                CMPerr(CMP_F_CMP_PKIMESSAGE_PROTECT,
                        CMP_R_UNSUPPORTED_KEY_TYPE);
                goto err;
            }
            alg = OBJ_nid2obj(algNID);
            X509_ALGOR_set0(msg->header->protectionAlg, alg, V_ASN1_UNDEF,NULL);

            /* set senderKID to  keyIdentifier of the used certificate according
             * to section 5.1.1 */
            subjKeyIDStr = CMP_get_cert_subject_key_id(ctx->clCert);
            if (subjKeyIDStr) {
                CMP_PKIHEADER_set1_senderKID(msg->header, subjKeyIDStr);
            }

            /* Add ctx->extraCertsOut, the ctx->clCert,
             * and the chain upwards build up from ctx->untrusted_store */
            CMP_PKIMESSAGE_add_extraCerts(ctx, msg);

            if (!(msg->protection = CMP_calc_protection_sig(msg, ctx->pkey)))
                goto err;
        } else {
            CMPerr(CMP_F_CMP_PKIMESSAGE_PROTECT,
                   CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION);
            goto err;
        }
    }

    return 1;
 err:
    CMPerr(CMP_F_CMP_PKIMESSAGE_PROTECT, CMP_R_ERROR_PROTECTING_MESSAGE);
    return 0;
}

/* ##########################################################################
 * Adds the certificates to the extraCerts field in the given message.  For
 * this it tries to build the certificate chain of our client cert (ctx->clCert)
 * by using certificates in ctx->untrusted_store. If no untrusted store is set,
 * it will at least place the client certificate into extraCerts.
 * Additionally all the certificates explicitly specified to be sent out
 * (i.e. ctx->extraCertsOut) are added to the stack.
 *
 * Note: it will NOT put the trust anchor in the extraCerts - unless it would be
 * in the untrusted store.
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIMESSAGE_add_extraCerts(CMP_CTX *ctx, CMP_PKIMESSAGE *msg)
{
    int i;

    if (!ctx)
        goto err;
    if (!msg)
        goto err;
    if (!msg->extraCerts && !(msg->extraCerts = sk_X509_new_null()))
        goto err;

    if (ctx->clCert) {
        /* if we have untrusted store, try to add all the intermediate certs and
         * our own */
        if (ctx->untrusted_store) {
            STACK_OF (X509) * chain =
                CMP_build_cert_chain(ctx->untrusted_store, ctx->clCert);
            /* Our own cert will be sent first */
            for (i = 0; i < sk_X509_num(chain); i++) {
                X509 *cert = sk_X509_value(chain, i);
                sk_X509_push(msg->extraCerts, cert);
            }
            sk_X509_free(chain); /* only frees the stack, not the content */
        } else {
            /* Make sure that at least our own cert gets sent */
            X509_up_ref(ctx->clCert);
            sk_X509_push(msg->extraCerts, ctx->clCert);
        }
    }

    /* add any additional certificates from ctx->extraCertsOut */
    for (i = 0; i < sk_X509_num(ctx->extraCertsOut); i++)
        sk_X509_push(msg->extraCerts,
                     X509_dup(sk_X509_value(ctx->extraCertsOut, i)));

    return 1;

 err:
    return 0;
}

/* ########################################################################## *
 * set certificate Hash in certStatus of certConf messages according to 5.3.18.
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_CERTSTATUS_set_certHash(CMP_CERTSTATUS *certStatus, const X509 *cert)
{
    unsigned int hashLen;
    unsigned char hash[EVP_MAX_MD_SIZE];
    int md_NID;
    const EVP_MD *md = NULL;

    if (!certStatus)
        goto err;
    if (!cert)
        goto err;

    /*  select hash algorithm, as stated in Appendix F.  Compilable ASN.1
     *  Definitions:
     *  -- the hash of the certificate, using the same hash algorithm
     *  -- as is used to create and verify the certificate signature */
    if (OBJ_find_sigid_algs(X509_get_signature_nid(cert), &md_NID, NULL)
        && (md = EVP_get_digestbynid(md_NID))) {
        if (!X509_digest(cert, md, hash, &hashLen))
            goto err;
        if (!certStatus->certHash)
            if (!(certStatus->certHash = ASN1_OCTET_STRING_new()))
                goto err;
        if (!ASN1_OCTET_STRING_set(certStatus->certHash, hash, hashLen))
            goto err;
    } else {
        CMPerr(CMP_F_CMP_CERTSTATUS_SET_CERTHASH,
               CMP_R_UNSUPPORTED_ALGORITHM);
        goto err;
    }

    return 1;
 err:
    CMPerr(CMP_F_CMP_CERTSTATUS_SET_CERTHASH, CMP_R_ERROR_SETTING_CERTHASH);
    return 0;
}

/* ########################################################################## *
 * sets implicitConfirm in the generalInfo field of the PKIMessage header
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIMESSAGE_set_implicitConfirm(CMP_PKIMESSAGE *msg)
{
    CMP_INFOTYPEANDVALUE *itav = NULL;

    if (!msg)
        goto err;

    if (!(itav = CMP_ITAV_new(OBJ_nid2obj(NID_id_it_implicitConfirm),
                              (const ASN1_TYPE *)ASN1_NULL_new())))
        goto err;
    if (!CMP_PKIHEADER_generalInfo_item_push0(msg->header, itav))
        goto err;
    return 1;
 err:
    if (itav)
        CMP_INFOTYPEANDVALUE_free(itav);
    return 0;
}

/* ########################################################################## *
 * checks if implicitConfirm in the generalInfo field of the header is set
 *
 * returns 1 if it is set, 0 if not
 * ########################################################################## */
int CMP_PKIMESSAGE_check_implicitConfirm(CMP_PKIMESSAGE *msg)
{
    int itavCount;
    int i;
    CMP_INFOTYPEANDVALUE *itav = NULL;

    if (!msg)
        return 0;

    itavCount = sk_CMP_INFOTYPEANDVALUE_num(msg->header->generalInfo);

    for (i = 0; i < itavCount; i++) {
        itav = sk_CMP_INFOTYPEANDVALUE_value(msg->header->generalInfo, i);
        if (OBJ_obj2nid(itav->infoType) == NID_id_it_implicitConfirm)
            return 1;
    }

    return 0;
}

/* ########################################################################## *
 * push given itav to message header
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIHEADER_generalInfo_item_push0(CMP_PKIHEADER *hdr,
                                         const CMP_INFOTYPEANDVALUE *itav)
{
    if (!hdr)
        goto err;

    if (!CMP_INFOTYPEANDVALUE_stack_item_push0(&hdr->generalInfo, itav))
        goto err;
    return 1;
 err:
    CMPerr(CMP_F_CMP_PKIHEADER_GENERALINFO_ITEM_PUSH0,
           CMP_R_ERROR_PUSHING_GENERALINFO_ITEM);
    return 0;
}

/* ########################################################################## */
int CMP_PKIMESSAGE_generalInfo_items_push1(CMP_PKIMESSAGE *msg,
                                          STACK_OF(CMP_INFOTYPEANDVALUE) *itavs)
{
    int i;
    CMP_INFOTYPEANDVALUE *itav = NULL;

    if (!msg)
        goto err;

    for (i = 0; i < sk_CMP_INFOTYPEANDVALUE_num(itavs); i++) {
        itav = CMP_INFOTYPEANDVALUE_dup(sk_CMP_INFOTYPEANDVALUE_value(itavs,i));
        if (!CMP_PKIHEADER_generalInfo_item_push0(msg->header, itav)) {
            CMP_INFOTYPEANDVALUE_free(itav);
            goto err;
        }
    }

    return 1;
 err:
    CMPerr(CMP_F_CMP_PKIMESSAGE_GENERALINFO_ITEMS_PUSH1,
           CMP_R_ERROR_PUSHING_GENERALINFO_ITEMS);
    return 0;
}

/* ########################################################################## *
 * push given InfoTypeAndValue item to the stack in a general message (GenMsg).
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIMESSAGE_genm_item_push0(CMP_PKIMESSAGE *msg,
                                   const CMP_INFOTYPEANDVALUE *itav)
{
    if (!msg)
        goto err;

    if (CMP_PKIMESSAGE_get_bodytype(msg) != V_CMP_PKIBODY_GENM)
        goto err;

    if (!CMP_INFOTYPEANDVALUE_stack_item_push0(&msg->body->value.genm, itav))
        goto err;
    return 1;
 err:
    CMPerr(CMP_F_CMP_PKIMESSAGE_GENM_ITEM_PUSH0,
           CMP_R_ERROR_PUSHING_GENERALINFO_ITEM);
    return 0;
}

/* ########################################################################## *
 * push a copy of the given itav stack the body of a general message (GenMsg).
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_PKIMESSAGE_genm_items_push1(CMP_PKIMESSAGE *msg,
                                          STACK_OF(CMP_INFOTYPEANDVALUE) *itavs)
{
    int i;
    CMP_INFOTYPEANDVALUE *itav = NULL;

    if (!msg)
        goto err;

    for (i = 0; i < sk_CMP_INFOTYPEANDVALUE_num(itavs); i++) {
        itav = CMP_INFOTYPEANDVALUE_dup(sk_CMP_INFOTYPEANDVALUE_value(itavs,i));
        if (!CMP_PKIMESSAGE_genm_item_push0(msg, itav)) {
            CMP_INFOTYPEANDVALUE_free(itav);
            goto err;
        }
    }
    return 1;
 err:
    CMPerr(CMP_F_CMP_PKIMESSAGE_GENM_ITEMS_PUSH1,
           CMP_R_ERROR_PUSHING_GENM_ITEMS);
    return 0;
}

/* ########################################################################## *
 * push given itav to given stack, creating a new stack if not yet done.
 *
 * @itav: a pointer to the infoTypeAndValue item to push on the stack.
 *                If NULL it will only made sure the stack exists, that might be
 *                needed for creating an empty general message
 *
 * returns 1 on success, 0 on error
 * ########################################################################## */
int CMP_ITAV_stack_item_push0(STACK_OF (CMP_INFOTYPEANDVALUE) ** itav_sk_p,
                              const CMP_INFOTYPEANDVALUE *itav)
{
    int created = 0;

    if (!itav_sk_p)
        goto err;

    if (!*itav_sk_p) {
        /* not yet created */
        if (!(*itav_sk_p = sk_CMP_INFOTYPEANDVALUE_new_null()))
            goto err;
        created = 1;
    }
    if (itav) {
        if (!sk_CMP_INFOTYPEANDVALUE_push(*itav_sk_p,
                    (CMP_INFOTYPEANDVALUE *)itav))
            goto err;
    }
    return 1;
 err:
    if (created) {
        sk_CMP_INFOTYPEANDVALUE_pop_free(*itav_sk_p, CMP_INFOTYPEANDVALUE_free);
        *itav_sk_p = NULL;
    }
    return 0;
}


/* ########################################################################## *
 * Creates a new CMP_INFOTYPEANDVALUE structure and fills it in
 * returns a pointer to the structure on success, NULL on error
 * ########################################################################## */
CMP_INFOTYPEANDVALUE *CMP_ITAV_new(const ASN1_OBJECT *type,
                                   const ASN1_TYPE *value)
{
    CMP_INFOTYPEANDVALUE *itav;
    if (!type || !(itav = CMP_INFOTYPEANDVALUE_new()))
        return NULL;
    CMP_INFOTYPEANDVALUE_set(itav, type, value);
    return itav;
}

/* ########################################################################## *
 * Creates a new PKIStatusInfo structure and fills it in
 * returns a pointer to the structure on success, NULL on error
 * note: strongly overlaps with TS_RESP_CTX_set_status_info()
 *       and TS_RESP_CTX_add_failure_info() in ../ts/ts_rsp_sign.c
 * ########################################################################## */
CMP_PKISTATUSINFO *CMP_statusInfo_new(int status, int failure, const char *text)
{
    CMP_PKISTATUSINFO *si = NULL;
    ASN1_UTF8STRING *utf8_text = NULL;

    if ((si = CMP_PKISTATUSINFO_new()) == NULL)
        goto err;
    if (!ASN1_INTEGER_set(si->status, status))
        goto err;

    if (text) {
        if ((utf8_text = ASN1_UTF8STRING_new()) == NULL ||
            !ASN1_STRING_set(utf8_text, text, strlen(text)))
            goto err;
        if (si->statusString == NULL &&
            (si->statusString = sk_ASN1_UTF8STRING_new_null()) == NULL)
            goto err;
        if (!sk_ASN1_UTF8STRING_push(si->statusString, utf8_text))
            goto err;
        utf8_text = NULL;       /* Ownership is lost. */
    }

    if (0 <= failure && failure <= CMP_PKIFAILUREINFO_MAX) {
        if (si->failInfo == NULL &&
            (si->failInfo = ASN1_BIT_STRING_new()) == NULL)
            goto err;
        if (!ASN1_BIT_STRING_set_bit(si->failInfo, failure, 1))
            goto err;
    }
    return si;

 err:
    CMP_PKISTATUSINFO_free(si);
    ASN1_UTF8STRING_free(utf8_text);
    return NULL;
}

/* ########################################################################## *
 * returns the PKIStatus of the given PKIStatusInfo
 * returns -1 on error
 * ########################################################################## */
long CMP_PKISTATUSINFO_PKIStatus_get(CMP_PKISTATUSINFO *si)
{
    if (!si || !si->status) {
        CMPerr(CMP_F_CMP_PKISTATUSINFO_PKISTATUS_GET,
               CMP_R_ERROR_PARSING_PKISTATUS);
        return -1;
    }
    return ASN1_INTEGER_get(si->status);
}

/* ########################################################################## *
 * internal function
 *
 * convert PKIStatus to human-readable string
 *
 * returns pointer to character array containing a sting representing the
 * PKIStatus of the given PKIStatusInfo
 * returns NULL on error
 * ########################################################################## */
static char *CMP_PKISTATUSINFO_PKIStatus_get_string(CMP_PKISTATUSINFO *si)
{
    long PKIStatus;

    if ((PKIStatus = CMP_PKISTATUSINFO_PKIStatus_get(si)) < 0)
        return NULL;
    switch (PKIStatus) {
    case CMP_PKISTATUS_accepted:
        return "PKIStatus: accepted";
    case CMP_PKISTATUS_grantedWithMods:
        return "PKIStatus: granded with mods";
    case CMP_PKISTATUS_rejection:
        return "PKIStatus: rejection";
    case CMP_PKISTATUS_waiting:
        return "PKIStatus: waiting";
    case CMP_PKISTATUS_revocationWarning:
        return "PKIStatus: revocation warning";
    case CMP_PKISTATUS_revocationNotification:
        return "PKIStatus: revocation notification";
    case CMP_PKISTATUS_keyUpdateWarning:
        return "PKIStatus: key update warning";
    default:
        CMPerr(CMP_F_CMP_PKISTATUSINFO_PKISTATUS_GET_STRING,
               CMP_R_ERROR_PARSING_PKISTATUS);
    }
    return NULL;
}

/* ########################################################################## *
 * internal function
 *
 * convert PKIStatus to human-readable string
 * Limitation: in case more than one bit is set, only one is considered.
 *
 * returns pointer to string containing the the PKIFailureInfo
 * returns NULL on error
 * ########################################################################## */
static char *CMP_PKISTATUSINFO_PKIFailureInfo_get_string(CMP_PKISTATUSINFO *si)
{
    int i;

    if (!si)
        return NULL;
    for (i = 0; i <= CMP_PKIFAILUREINFO_MAX; i++) {
        if (ASN1_BIT_STRING_get_bit(si->failInfo, i)) {
            switch (i) {
            case CMP_PKIFAILUREINFO_badAlg:
                return "PKIFailureInfo: badAlg";
            case CMP_PKIFAILUREINFO_badMessageCheck:
                return "PKIFailureInfo: badMessageCheck";
            case CMP_PKIFAILUREINFO_badRequest:
                return "PKIFailureInfo: badRequest";
            case CMP_PKIFAILUREINFO_badTime:
                return "PKIFailureInfo: badTime";
            case CMP_PKIFAILUREINFO_badCertId:
                return "PKIFailureInfo: badCertId";
            case CMP_PKIFAILUREINFO_badDataFormat:
                return "PKIFailureInfo: badDataFormat";
            case CMP_PKIFAILUREINFO_wrongAuthority:
                return "PKIFailureInfo: wrongAuthority";
            case CMP_PKIFAILUREINFO_incorrectData:
                return "PKIFailureInfo: incorrectData";
            case CMP_PKIFAILUREINFO_missingTimeStamp:
                return "PKIFailureInfo: missingTimeStamp";
            case CMP_PKIFAILUREINFO_badPOP:
                return "PKIFailureInfo: badPOP";
            case CMP_PKIFAILUREINFO_certRevoked:
                return "PKIFailureInfo: certRevoked";
            case CMP_PKIFAILUREINFO_certConfirmed:
                return "PKIFailureInfo: certConfirmed";
            case CMP_PKIFAILUREINFO_wrongIntegrity:
                return "PKIFailureInfo: wrongIntegrity";
            case CMP_PKIFAILUREINFO_badRecipientNonce:
                return "PKIFailureInfo: badRecipientNonce";
            case CMP_PKIFAILUREINFO_timeNotAvailable:
                return "PKIFailureInfo: timeNotAvailable";
            case CMP_PKIFAILUREINFO_unacceptedPolicy:
                return "PKIFailureInfo: unacceptedPolicy";
            case CMP_PKIFAILUREINFO_unacceptedExtension:
                return "PKIFailureInfo: unacceptedExtension";
            case CMP_PKIFAILUREINFO_addInfoNotAvailable:
                return "PKIFailureInfo: addInfoNotAvailable";
            case CMP_PKIFAILUREINFO_badSenderNonce:
                return "PKIFailureInfo: badSenderNonce";
            case CMP_PKIFAILUREINFO_badCertTemplate:
                return "PKIFailureInfo: badCertTemplate";
            case CMP_PKIFAILUREINFO_signerNotTrusted:
                return "PKIFailureInfo: signerNotTrusted";
            case CMP_PKIFAILUREINFO_transactionIdInUse:
                return "PKIFailureInfo: transactionIdInUse";
            case CMP_PKIFAILUREINFO_unsupportedVersion:
                return "PKIFailureInfo: unsupportedVersion";
            case CMP_PKIFAILUREINFO_notAuthorized:
                return "PKIFailureInfo: notAuthorized";
            case CMP_PKIFAILUREINFO_systemUnavail:
                return "PKIFailureInfo: systemUnavail";
            case CMP_PKIFAILUREINFO_systemFailure:
                return "PKIFailureInfo: systemFailure";
            case CMP_PKIFAILUREINFO_duplicateCertReq:
                return "PKIFailureInfo: duplicateCertReq";
            }
        }
    }
    return 0;
}

/* ########################################################################## *
 * returns the status field of the RevRepContent with the given 
 * request/sequence id inside a revocation response.
 * RevRepContent has the revocation statuses in same order as they were sent in
 * RevReqContent.
 * returns NULL on error
 * ########################################################################## */
CMP_PKISTATUSINFO *CMP_REVREPCONTENT_PKIStatusInfo_get(CMP_REVREPCONTENT *rrep,
                                                long rsid)
{
    CMP_PKISTATUSINFO *status = NULL;
    if (!rrep)
        return NULL;

    if ((status = sk_CMP_PKISTATUSINFO_value(rrep->status, rsid))) {
        return status;
    }

    CMPerr(CMP_F_CMP_REVREPCONTENT_PKISTATUSINFO_GET,
           CMP_R_ERROR_STATUS_NOT_FOUND);
    return NULL;
}

/* ########################################################################## *
 * checks bits in given PKIFailureInfo
 * returns 1 if a given bit is set in a PKIFailureInfo, 0 if not, -1 on error
 * PKIFailureInfo ::= ASN1_BIT_STRING
 * ########################################################################## */
int CMP_PKIFAILUREINFO_check(ASN1_BIT_STRING *failInfo, int codeBit)
{
    if (!failInfo)
        return -1;
    if ((codeBit < 0) || (codeBit > CMP_PKIFAILUREINFO_MAX))
        return -1;

    return ASN1_BIT_STRING_get_bit(failInfo, codeBit);
}

/* ########################################################################## *
 * returns a pointer to the PollResponse with the given CertReqId
 * (or the first one in case -1) inside a pollRep PKIMessage
 * returns NULL on error or if no PollResponse available
 * ########################################################################## */
CMP_POLLREP *CMP_PKIMESSAGE_pollResponse_get0(CMP_PKIMESSAGE *prep, long rid)
{
    CMP_POLLREP *pollRep = NULL;
    int i;

    if (!prep || prep->body->type != V_CMP_PKIBODY_POLLREP ||
        !prep->body->value.pollRep)
        goto err;

    for (i = 0; i < sk_CMP_POLLREP_num(prep->body->value.pollRep); i++) {
        pollRep = sk_CMP_POLLREP_value(prep->body->value.pollRep, i);
        /* is it the right CertReqId? */
        if (rid == -1 || rid == ASN1_INTEGER_get(pollRep->certReqId))
            return pollRep;
    }

 err:
    CMPerr(CMP_F_CMP_PKIMESSAGE_POLLRESPONSE_GET0,
           CMP_R_CERTRESPONSE_NOT_FOUND);
    return NULL;
}

/* ########################################################################## *
 * returns a pointer to the CertResponse with the given CertReqId
 * (or the first one in case -1) inside a CertRepMessage
 * returns NULL on error or if no CertResponse available
 * ########################################################################## */
CMP_CERTRESPONSE *CMP_CERTREPMESSAGE_certResponse_get0(CMP_CERTREPMESSAGE
                                                       *crepmsg, long rid)
{
    CMP_CERTRESPONSE *crep = NULL;
    int i;

    if (!crepmsg)
        goto err;

    for (i = 0; i < sk_CMP_CERTRESPONSE_num(crepmsg->response); i++) {
        crep = sk_CMP_CERTRESPONSE_value(crepmsg->response, i);
        /* is it the right CertReqId? */
        if (rid == -1 || rid == ASN1_INTEGER_get(crep->certReqId))
            return crep;
    }

 err:
    CMPerr(CMP_F_CMP_CERTREPMESSAGE_CERTRESPONSE_GET0,
           CMP_R_CERTRESPONSE_NOT_FOUND);
    return NULL;
}

/* ########################################################################## *
 * internal function
 *
 * Decrypts the certificate in the given CertOrEncCert
 * this is needed for the indirect PoP method as in section 5.2.8.2
 *
 * returns a pointer to the decrypted certificate
 * returns NULL on error or if no Certificate available
 * ########################################################################## */
static X509 *CMP_CERTORENCCERT_encCert_get1(CMP_CERTORENCCERT *coec,
                                            EVP_PKEY *pkey)
{
    CRMF_ENCRYPTEDVALUE *ecert;
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

    if (!coec)
        goto err;
    if (!(ecert = coec->value.encryptedCert))
        goto err;
    if (!ecert->symmAlg)
        goto err;
    if (!(symmAlg = OBJ_obj2nid(ecert->symmAlg->algorithm)))
        goto err;

    /* first the symmetric key needs to be decrypted */
    if ((pkctx = EVP_PKEY_CTX_new(pkey, NULL)) && EVP_PKEY_decrypt_init(pkctx)){
        ASN1_BIT_STRING *encKey = ecert->encSymmKey;
        size_t eksize = 0;

        if (!encKey)
            goto err;

        if (EVP_PKEY_decrypt
            (pkctx, NULL, &eksize, encKey->data, encKey->length) <= 0
            || !(ek = OPENSSL_malloc(eksize))
            || EVP_PKEY_decrypt(pkctx, ek, &eksize, encKey->data,
                                encKey->length) <= 0) {
            CMPerr(CMP_F_CMP_CERTORENCCERT_ENCCERT_GET1,
                   CMP_R_ERROR_DECRYPTING_SYMMETRIC_KEY);
            goto err;
        }
        EVP_PKEY_CTX_free(pkctx);
    } else {
        CMPerr(CMP_F_CMP_CERTORENCCERT_ENCCERT_GET1,
               CMP_R_ERROR_DECRYPTING_KEY);
        goto err;
    }

    /* select symmetric cipher based on algorithm given in message */
    if (!(cipher = EVP_get_cipherbynid(symmAlg))) {
        CMPerr(CMP_F_CMP_CERTORENCCERT_ENCCERT_GET1,
               CMP_R_UNSUPPORTED_CIPHER);
        goto err;
    }
    if (!(iv = OPENSSL_malloc(EVP_CIPHER_iv_length(cipher))))
        goto err;
    ASN1_TYPE_get_octetstring(ecert->symmAlg->parameter, iv,
                              EVP_CIPHER_iv_length(cipher));

    /* d2i_X509 changes the given pointer, so use p for decoding the message and
     * keep the original pointer in outbuf so the memory can be freed later */
    if (!ecert->encValue)
        goto err;
    if (!(p = outbuf = OPENSSL_malloc(ecert->encValue->length +
                                      EVP_CIPHER_block_size(cipher))))
        goto err;
    evp_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(evp_ctx, 0);

    if (!EVP_DecryptInit(evp_ctx, cipher, ek, iv)
        || !EVP_DecryptUpdate(evp_ctx, outbuf, &outlen,
                              ecert->encValue->data,
                              ecert->encValue->length)
        || !EVP_DecryptFinal(evp_ctx, outbuf + outlen, &n)) {
        CMPerr(CMP_F_CMP_CERTORENCCERT_ENCCERT_GET1,
               CMP_R_ERROR_DECRYPTING_CERTIFICATE);
        goto err;
    }
    outlen += n;

    /* convert decrypted certificate from DER to internal ASN.1 structure */
    if (!(cert = d2i_X509(NULL, &p, outlen))) {
        CMPerr(CMP_F_CMP_CERTORENCCERT_ENCCERT_GET1,
               CMP_R_ERROR_DECODING_CERTIFICATE);
        goto err;
    }

    OPENSSL_free(outbuf);
    EVP_CIPHER_CTX_free(evp_ctx);
    OPENSSL_free(ek);
    OPENSSL_free(iv);
    return cert;
 err:
    CMPerr(CMP_F_CMP_CERTORENCCERT_ENCCERT_GET1,
           CMP_R_ERROR_DECRYPTING_ENCCERT);
    if (outbuf)
        OPENSSL_free(outbuf);
    if (evp_ctx)
        EVP_CIPHER_CTX_free(evp_ctx);
    if (ek)
        OPENSSL_free(ek);
    if (iv)
        OPENSSL_free(iv);
    return NULL;
}

/* ########################################################################## *
 * returns 1 on success
 * returns 0 on error
 * ########################################################################## */
int CMP_PKIMESSAGE_set_bodytype(CMP_PKIMESSAGE *msg, int type)
{
    if (!msg || !msg->body)
        return 0;

    msg->body->type = type;

    return 1;
}

/* ########################################################################## *
 * returns the body type of the given CMP message
 * returns -1 on error
 * ########################################################################## */
int CMP_PKIMESSAGE_get_bodytype(const CMP_PKIMESSAGE *msg)
{
    if (!msg || !msg->body)
        return -1;

    return msg->body->type;
}

/* ########################################################################## *
 * place human-readable error string created from PKIStatusInfo in given buffer
 * returns pointer to the same buffer containing the string, or NULL on error
 * ########################################################################## */
char *CMP_PKISTATUSINFO_snprint(CMP_PKISTATUSINFO *si, char *buf, int bufsize)
{
    const char *status, *failureinfo;
    int i, n;

    if (!si || !(status = CMP_PKISTATUSINFO_PKIStatus_get_string(si)))
        return NULL;

    failureinfo = CMP_PKISTATUSINFO_PKIFailureInfo_get_string(si);
    /* PKIFailureInfo is optional */
    n = sk_ASN1_UTF8STRING_num(si->statusString);
    /* StatusString sequence is optional and may be empty */
    BIO_snprintf(buf, bufsize, "%s; %s%s", status,
                 failureinfo ? failureinfo : "<no failure info>",
                 n > 0 ? "; StatusString(s): " : "");

    for (i = 0; i < n; i++) {
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
#define ASN1_STRING_get0_data(x) ((x)->data)
#endif
        ASN1_UTF8STRING *text = sk_ASN1_UTF8STRING_value(si->statusString, i);
        BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf), "\"%s\"%s",
                     ASN1_STRING_get0_data(text), i < n-1 ? ", " : "");
    }
    return buf;
}

/* ########################################################################## *
 * Retrieve a copy of the certificate, if any, from the given CertResponse.
 * returns NULL if not found or on error
 * ########################################################################## */
X509 *CMP_CERTRESPONSE_get_certificate(CMP_CTX *ctx, CMP_CERTRESPONSE *crep)
{
    CMP_CERTORENCCERT *coec;
    X509 *crt = NULL;

    if (!ctx || !crep) {
        CMPerr(CMP_F_CMP_CERTRESPONSE_GET_CERTIFICATE,
               CMP_R_INVALID_ARGS);
        goto err;
    }
    if (crep->certifiedKeyPair &&
        (coec = crep->certifiedKeyPair->certOrEncCert)) {
        switch (coec->type) {
        case CMP_CERTORENCCERT_CERTIFICATE:
            crt = X509_dup(coec->value.certificate);
            break;
        case CMP_CERTORENCCERT_ENCRYPTEDCERT:
        /* cert encrypted for indirect PoP; RFC 4210, 5.2.8.2 */
            crt = CMP_CERTORENCCERT_encCert_get1(coec, ctx->newPkey);
            break;
        default:
            CMPerr(CMP_F_CMP_CERTRESPONSE_GET_CERTIFICATE,
                   CMP_R_UNKNOWN_CERTTYPE);
            goto err;
        }
        if (!crt) {
            CMPerr(CMP_F_CMP_CERTRESPONSE_GET_CERTIFICATE,
                   CMP_R_CERTIFICATE_NOT_FOUND);
            goto err;
        }
    }
    return crt;

 err:
    return NULL;
}

/* ########################################################################## *
 * Builds up the certificate chain of cert as high up as possible using
 * the given X509_STORE containing all possible intermediate certificates and
 * optionally the (possible) trust anchor(s). See also ssl_add_cert_chain().
 *
 * Intended use of this function is to find all the certificates above the trust
 * anchor needed to verify an EE's own certificate.  Those are supposed to be
 * included in the ExtraCerts field of every first sent message of a transaction
 * when MSG_SIG_ALG is utilized.
 *
 * NOTE: This allocates a stack and increments the reference count of each cert,
 * so when not needed any more the stack and all its elements should be freed.
 * NOTE: in case there is more than one possibility for the chain,
 * OpenSSL seems to take the first one, check X509_verify_cert() for details.
 *
 * returns a pointer to a stack of (duplicated) X509 certificates containing:
 *      - the EE certificate given in the function arguments (cert)
 *      - all intermediate certificates up the chain towards the trust anchor
 *      - the (self-signed) trust anchor is not included
 *      returns NULL on error
 * ########################################################################## */
STACK_OF (X509) *CMP_build_cert_chain(X509_STORE *store, const X509 *cert)
{
    STACK_OF (X509) * chain = NULL, *chain_dup = NULL;
    X509_STORE_CTX *csc = NULL;
    int i = 0;

    if (!store || !cert)
        goto err;

    csc = X509_STORE_CTX_new();
    if (!csc)
        goto err;

    /* chain_dup to store the duplicated certificates */
    chain_dup = sk_X509_new_null();
    if (!chain_dup)
        goto err;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_STORE_get0_param(store) (store->param)
#endif
    /* clear all flags, thus do not check CRLs */
    X509_VERIFY_PARAM_clear_flags(X509_STORE_get0_param(store), ~0);
    if (!X509_STORE_CTX_init(csc, store, (X509 *)cert, NULL))
        goto err;

    (void)X509_verify_cert(csc); /* ignore return value as it would fail
                                    without trust anchor given in store */
    ERR_clear_error();           /* don't leave any errors in the queue */

    chain = X509_STORE_CTX_get0_chain(csc);
    for (i = 0; i < sk_X509_num(chain); i++) {
        X509 *cert_dup = sk_X509_value(chain, i);
        if (X509_check_issued(cert_dup, cert_dup) != X509_V_OK) {
            X509_up_ref(cert_dup);
            sk_X509_push(chain_dup, cert_dup);
        }
    }

    X509_STORE_CTX_free(csc);

    return chain_dup;

 err:
    X509_STORE_CTX_free(csc);
    sk_X509_free(chain_dup);
    return NULL;
}

STACK_OF(X509) *X509_STORE_get1_certs(const X509_STORE *store) {
    int i;
    STACK_OF(X509) *sk;
    STACK_OF(X509_OBJECT) *objs;

    if (!store)
        return NULL;
    if (!(sk = sk_X509_new_null()))
        return NULL;
    objs = X509_STORE_get0_objects((X509_STORE *)store);
    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        X509 *cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));
        if (cert) {
            X509_up_ref(cert);
            if (!sk_X509_push(sk, cert)) {
                X509_free(cert);
                sk_X509_pop_free(sk, X509_free);
                return NULL;
            }
        }
    }
    return sk;
}

/* ############################################################################
 * this function is intended to be used only within the CMP library although it
 * is included in cmp.h
 *
 * Returns the subject key identifier of the given certificate
 * returns NULL on error, respecively when none was found.
 * ########################################################################## */
ASN1_OCTET_STRING *CMP_get_cert_subject_key_id(const X509 *cert)
{
    X509_EXTENSION *ex = NULL;
    int subjKeyIDLoc = -1;

    if (!cert)
        goto err;

    subjKeyIDLoc =
        X509_get_ext_by_NID((X509 *)cert, NID_subject_key_identifier, -1);
    if (subjKeyIDLoc == -1)
        goto err;

    /* found a subject key ID */
    if (!(ex = X509_get_ext((X509 *)cert, subjKeyIDLoc)))
        goto err;

    return X509_EXTENSION_get_data(ex);

 err:
    return NULL;
}
