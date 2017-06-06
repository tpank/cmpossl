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

/* ############################################################################ *
 * In this file are the functions which set the individual items inside                 *
 * the CMP structures                                                                                                                   *
 * ############################################################################ */

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

/* ############################################################################ *
 * Sets the protocol version number in PKIHeader.
 * returns 1 on success, 0 on error
 * ############################################################################ */
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

/* ############################################################################ *
 * Set the recipient name of PKIHeader.
 * when nm is NULL, recipient is set to an empty string
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_set1_recipient(CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
    if (!hdr)
        return 0;

    return cpy_gname(&hdr->recipient, nm);
}

/* ############################################################################ *
 * Set the sender name in PKIHeader.
 * when nm is NULL, sender is set to an empty string
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_set1_sender(CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
    if (!hdr)
        return 0;

    return cpy_gname(&hdr->sender, nm);
}

/* ############################################################################ *
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
 * ############################################################################ */
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

/* ############################################################################ *
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
 * ############################################################################ */
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

/* ############################################################################ *
 * (re-)sets given recipient nonce to given header
 * as per 5.1.1 used to mirror the nonce back to the other side
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
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

/* ############################################################################ * 
 * (re-)set given senderKID to given header
 *
 * senderKID: keyIdentifier of the sender's certificate, or PBMAC reference value
 *       -- the reference number which the CA has previously issued
 *       -- to the end entity (together with the MACing key)
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
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

/* ############################################################################
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
 * ############################################################################ */
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

/* ############################################################################ *
 * push given ASN1_UTF8STRING to hdr->freeText and consume the given pointer
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
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

/* ############################################################################ *
 * push an ASN1_UTF8STRING to hdr->freeText and don't consume the given pointer
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
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

/* ############################################################################ *
 * Initialize the given PkiHeader structure with values set in the CMP_CTX structure.
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_init(CMP_CTX *ctx, CMP_PKIHEADER *hdr)
{
    X509_NAME *recipient = NULL;

    if (!hdr)
        goto err;
    if (!ctx)
        goto err;

    /* set the CMP version */
    CMP_PKIHEADER_set_version(hdr, CMP_VERSION);

    /* in case there is no OLD client cert the sender name is not set (e.g. for IR) */
    if (ctx->clCert) {
        if (!CMP_PKIHEADER_set1_sender
            (hdr, X509_get_subject_name((X509 *)ctx->clCert)))
            goto err;
    } else {
        if (!CMP_PKIHEADER_set1_sender(hdr, NULL))
            goto err;
    }

    /* set recipient name either from known server certificate or 
       recipient or issuer name in ctx, leave empty if not set in ctx */
    if (ctx->srvCert)
        recipient = X509_get_subject_name((X509 *)ctx->srvCert);
    else if (ctx->recipient)
        recipient = ctx->recipient;
    else if (ctx->issuer)
        recipient = ctx->issuer;
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
        CMP_CTX_set1_transactionID(ctx, hdr->transactionID);
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

/* ############################################################################ * 
 * also used for verification from cmp_vfy
 *
 * calculate PBMAC protection for given PKImessage utilizing the given secret and the
 * pbm-parameters set inside the message header's protectionAlg
 *
 * returns pointer to ASN1_BIT_STRING containing protection on success, NULL on
 * error
 * ############################################################################ */
ASN1_BIT_STRING *CMP_calc_protection_pbmac(CMP_PKIMESSAGE *pkimessage,
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
    OPENSSL_free(protPartDer);

    if (!(prot = ASN1_BIT_STRING_new()))
        goto err;
    ASN1_BIT_STRING_set(prot, mac, macLen);

    /* Actually this should not be needed but OpenSSL defaults all bitstrings to be a NamedBitList */
    prot->flags &= ~0x07;
    prot->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    /* cleanup */
    if (mac)
        OPENSSL_free(mac);
    return prot;

 err:
    if (mac)
        OPENSSL_free(mac);

    CMPerr(CMP_F_CMP_CALC_PROTECTION_PBMAC,
           CMP_R_ERROR_CALCULATING_PROTECTION);
    if (prot)
        ASN1_BIT_STRING_free(prot);
    if (protPartDer)
        OPENSSL_free(protPartDer);
    return NULL;
}

/* ############################################################################ * 
 * only used internally
 *
 * calculate signature protection for given PKImessage utilizing the given secret key 
 * and the algorithm parameters set inside the message header's protectionAlg
 *
 * returns pointer to ASN1_BIT_STRING containing protection on success, NULL on
 * error
 * ############################################################################ */
// TODO factor out similarities with CMP_calc_protection_pbmac
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

    if (!pkey) {                /* EVP_SignFinal() will check that pkey type is correct for the algorithm */
        CMPerr(CMP_F_CMP_CALC_PROTECTION_SIG, CMP_R_INVALID_KEY);
        ERR_add_error_data(1,
                           "pkey was NULL although it is supposed to be used for generating protection");
        goto err;
    }

    /* construct data to be signed */
    protPart.header = pkimessage->header;
    protPart.body = pkimessage->body;
    protPartDerLen = i2d_CMP_PROTECTEDPART(&protPart, &protPartDer);

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
    ASN1_BIT_STRING_set(prot, mac, macLen);

    /* Actually this should not be needed but OpenSSL defaults all bitstrings to be a NamedBitList */
    prot->flags &= ~0x07;
    prot->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    /* cleanup */
    if (evp_ctx)
        EVP_MD_CTX_destroy(evp_ctx);
    if (mac)
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
    if (prot)
        ASN1_BIT_STRING_free(prot);
    return NULL;
}

/* ############################################################################ *
 * internal function
 * Create an X509_ALGOR structure for PasswordBasedMAC protection based on
 * the pbm settings in the context
 * returns pointer to X509_ALGOR on success, NULL on error
 * ############################################################################ */
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
    pbmDer = NULL;              /* to avoid double free in case there would be a "goto err" inserted behind this point later in development */

    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_id_PasswordBasedMAC),
                    V_ASN1_SEQUENCE, pbmStr);
    pbmStr = NULL;              /* pbmStr is not freed explicityly because the pointer was consumed by X509_ALGOR_set0() */

    CRMF_PBMPARAMETER_free(pbm);
    return alg;
 err:
    if (alg)
        X509_ALGOR_free(alg);
    if (pbm)
        CRMF_PBMPARAMETER_free(pbm);
    if (pbmDer)
        OPENSSL_free(pbmDer);
    return NULL;
}

/* ############################################################################ *
 * Determines which kind of protection should be created, based on the ctx.
 * Sets this into the protectionAlg field in the message header.
 * Calculates the protection and sets it in the protection field.
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIMESSAGE_protect(CMP_CTX *ctx, CMP_PKIMESSAGE *msg)
{
    if (!ctx)
        goto err;
    if (!msg)
        goto err;

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
        /* use MSG_SIG_ALG according to 5.1.3.3 if client Certificate and private key is given */
        if (ctx->clCert && ctx->pkey) {
            ASN1_OCTET_STRING *subjKeyIDStr = NULL;
            int algNID = 0;
            ASN1_OBJECT *alg = NULL;

            /* make sure that key and certificate match */
            if (!X509_check_private_key(ctx->clCert, ctx->pkey)) {
                CMPerr(CMP_F_CMP_PKIMESSAGE_PROTECT, CMP_R_INVALID_KEY);
                goto err;
            }

            if (!msg->header->protectionAlg)
                msg->header->protectionAlg = X509_ALGOR_new();

            if (!OBJ_find_sigid_by_algs(&algNID, ctx->digest, EVP_PKEY_id(ctx->pkey))) {
                CMPerr(CMP_F_CMP_PKIMESSAGE_PROTECT, CMP_R_UNSUPPORTED_KEY_TYPE);
                goto err;
            }
            alg = OBJ_nid2obj(algNID);
            X509_ALGOR_set0(msg->header->protectionAlg, alg, V_ASN1_UNDEF, NULL);

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
        } else if (msg->body->type != V_CMP_PKIBODY_IR) {
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

/* ############################################################################
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
 * ############################################################################ */
int CMP_PKIMESSAGE_add_extraCerts(CMP_CTX *ctx, CMP_PKIMESSAGE *msg)
{
    int i;

    if (!ctx)
        goto err;
    if (!msg)
        goto err;
    if (!msg->extraCerts && !(msg->extraCerts = sk_X509_new_null()))
        goto err;

    /* add any additional certificates from ctx->extraCertsOut */
    for (i = 0; i < sk_X509_num(ctx->extraCertsOut); i++)
        sk_X509_push(msg->extraCerts,
                     X509_dup(sk_X509_value(ctx->extraCertsOut, i)));

    if (ctx->clCert) {
        /* if we have untrusted store, try to add all the intermediate certs and our own */
        if (ctx->untrusted_store) {
            STACK_OF (X509) * chain =
                CMP_build_cert_chain(ctx->untrusted_store, ctx->clCert);
            for (i = 0; i < sk_X509_num(chain); i++) {
                X509 *cert = sk_X509_value(chain, i);
                sk_X509_push(msg->extraCerts, cert);
            }
            sk_X509_free(chain); /* only frees the stack, not the content */
        } else {
            /* Make sure that at least our own cert gets sent */
            sk_X509_push(msg->extraCerts, X509_dup(ctx->clCert));
        }
    }

    return 1;

 err:
    return 0;
}

/* ############################################################################ * 
 * set certificate Hash in certStatus of certConf messages according to 5.3.18.
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
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

    /*  select hash algorithm, as stated in Appendix F.  Compilable ASN.1 Definitions:
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

/* ############################################################################ *
 * sets implicitConfirm in the generalInfo field of the PKIMessage header
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIMESSAGE_set_implicitConfirm(CMP_PKIMESSAGE *msg)
{
    CMP_INFOTYPEANDVALUE *itav = NULL;

    if (!msg)
        goto err;

    if (!(itav = CMP_INFOTYPEANDVALUE_new()))
        goto err;
    itav->infoType = OBJ_nid2obj(NID_id_it_implicitConfirm);
    itav->infoValue.implicitConfirm = ASN1_NULL_new();
    if (!CMP_PKIHEADER_generalInfo_item_push0(msg->header, itav))
        goto err;
    return 1;
 err:
    if (itav)
        CMP_INFOTYPEANDVALUE_free(itav);
    return 0;
}

/* ############################################################################
 * checks if implicitConfirm in the generalInfo field of the header is set
 *
 * returns 1 if it is set, 0 if not
 * ############################################################################ */
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

/* ############################################################################ * 
 * push given itav to message header
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_generalInfo_item_push0(CMP_PKIHEADER *hdr,
                                         const CMP_INFOTYPEANDVALUE *itav)
{
    if (!hdr)
        goto err;

    if (!CMP_ITAV_stack_item_push0(&hdr->generalInfo, itav))
        goto err;
    return 1;
 err:
    return 0;
}

/* ############################################################################ * 
 * push the given InfoTypeAndValue item to the stack in a general message (GenMsg).
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIMESSAGE_genm_item_push0(CMP_PKIMESSAGE *msg,
                                   const CMP_INFOTYPEANDVALUE *itav)
{
    if (!msg)
        goto err;

    if (CMP_PKIMESSAGE_get_bodytype(msg) != V_CMP_PKIBODY_GENM)
        goto err;

    if (!CMP_ITAV_stack_item_push0(&msg->body->value.genm, itav))
        goto err;
    return 1;
 err:
    return 0;
}

/* ############################################################################ * 
 * push given itav to given stack, creating a new stack if not yet done.
 *
 * @itav: a pointer to the infoTypeAndValue item to push on the stack.
 *                If NULL it will only made sure the stack exists, that might be
 *                needed for creating an empty general message
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
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
        if (!sk_CMP_INFOTYPEANDVALUE_push(*itav_sk_p, (CMP_INFOTYPEANDVALUE *)itav))
            goto err;
    }
    return 1;
 err:
    if (created) {
        sk_CMP_INFOTYPEANDVALUE_pop_free(*itav_sk_p,
                                         CMP_INFOTYPEANDVALUE_free);
        *itav_sk_p = NULL;
    }
    return 0;
}

/* ############################################################################ * 
 * returns the PKIStatus of the given PKIStatusInfo
 * returns -1 on error
 * ############################################################################ */
long CMP_PKISTATUSINFO_PKIstatus_get(CMP_PKISTATUSINFO *statusInfo)
{
    if (!statusInfo)
        return -1;
    if (!statusInfo->status)
        return -1;
    return ASN1_INTEGER_get(statusInfo->status);
}

/* ############################################################################ * 
 * internal function
 *
 * convert PKIstatus to human readable string
 *
 * returns pointer to character array containing a sting representing the 
 * PKIStatus of the given PKIStatusInfo
 * returns NULL on error
 * ############################################################################ */
static char *CMP_PKISTATUSINFO_PKIstatus_get_string(CMP_PKISTATUSINFO
                                                    *statusInfo)
{
    long PKIstatus;

    if (!statusInfo)
        return 0;

    PKIstatus = CMP_PKISTATUSINFO_PKIstatus_get(statusInfo);
    switch (PKIstatus) {
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
    case -1:
    default:
        CMPerr(CMP_F_CMP_PKISTATUSINFO_PKISTATUS_GET_STRING,
               CMP_R_ERROR_PARSING_PKISTATUS);
        return 0;
    }
    return 0;
}

/* ############################################################################ * 
 * internal function
 *
 * convert PKIstatus to human readable string
 *
 * returns pointer to string containing the the PKIFailureInfo
 * returns NULL on error
 * ############################################################################ */
static char *CMP_PKISTATUSINFO_PKIFailureInfo_get_string(CMP_PKISTATUSINFO
                                                         *statusInfo)
{
    int i;

    if (!statusInfo)
        return 0;
    for (i = 0; i <= CMP_PKIFAILUREINFO_MAX; i++) {
        if (ASN1_BIT_STRING_get_bit(statusInfo->failInfo, i)) {
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

/* ############################################################################ *
 * returns the PKIStatus of the given certReqId inside a Rev
 * returns -1 on error
 * ############################################################################ */
long CMP_REVREPCONTENT_PKIStatus_get(CMP_REVREPCONTENT *revRep, long reqId)
{
    CMP_PKISTATUSINFO *status = NULL;
    if (!revRep)
        return -1;

    if ((status = sk_CMP_PKISTATUSINFO_value(revRep->status, reqId))) {
        return CMP_PKISTATUSINFO_PKIstatus_get(status);
    }

    CMPerr(CMP_F_CMP_REVREPCONTENT_PKISTATUS_GET,
           CMP_R_ERROR_REQID_NOT_FOUND);
    return -1;
}

/* ############################################################################ *
 * returns the PKIStatus of the given certReqId inside a CertRepMessage
 * returns -1 on error
 * ############################################################################ */
long CMP_CERTREPMESSAGE_PKIStatus_get(CMP_CERTREPMESSAGE *certRep,
                                      long certReqId)
{
    CMP_CERTRESPONSE *certResponse = NULL;
    if (!certRep)
        return -1;

    if ((certResponse =
         CMP_CERTREPMESSAGE_certResponse_get0(certRep, certReqId))) {
        return CMP_PKISTATUSINFO_PKIstatus_get(certResponse->status);
    }

    CMPerr(CMP_F_CMP_CERTREPMESSAGE_PKISTATUS_GET,
           CMP_R_ERROR_REQID_NOT_FOUND);
    return -1;
}

/* ############################################################################ * 
 * returns pointer to PKIFailureInfo of given certRep message
 * returns NULL on error or if no matching failInfo was found
 * ############################################################################ */
CMP_PKIFAILUREINFO *CMP_CERTREPMESSAGE_PKIFailureInfo_get0(CMP_CERTREPMESSAGE
                                                           *certRep,
                                                           long certReqId)
{
    CMP_CERTRESPONSE *certResponse = NULL;
    if (!certRep)
        return NULL;

    if ((certResponse =
         CMP_CERTREPMESSAGE_certResponse_get0(certRep, certReqId))) {
        if (certResponse->status)
            return certResponse->status->failInfo;
    }

    CMPerr(CMP_F_CMP_CERTREPMESSAGE_PKIFAILUREINFO_GET0,
           CMP_R_ERROR_REQID_NOT_FOUND);
    return NULL;
}

/* ############################################################################ * 
 * returns pointer to PKIFailureInfoString character array of given certRep message
 * returns NULL on error or if no matching failInfo was found
 * ############################################################################ */
char *CMP_CERTREPMESSAGE_PKIFailureInfoString_get0(CMP_CERTREPMESSAGE
                                                   *certRep, long certReqId)
{
    CMP_CERTRESPONSE *certResponse = NULL;
    if (!certRep)
        return NULL;

    if ((certResponse =
         CMP_CERTREPMESSAGE_certResponse_get0(certRep, certReqId))) {
        if (certResponse->status)
            return
                CMP_PKISTATUSINFO_PKIFailureInfo_get_string
                (certResponse->status);
    }

    CMPerr(CMP_F_CMP_CERTREPMESSAGE_PKIFAILUREINFOSTRING_GET0,
           CMP_R_ERROR_REQID_NOT_FOUND);
    return NULL;
}

/* ############################################################################ *
 * returns the status string of the given certReqId inside a CertRepMessage
 * returns NULL on error
 * ############################################################################ */
STACK_OF (ASN1_UTF8STRING) *
CMP_CERTREPMESSAGE_PKIStatusString_get0(CMP_CERTREPMESSAGE *certRep,
                                        long certReqId)
{
    CMP_CERTRESPONSE *certResponse = NULL;
    if (!certRep)
        return NULL;

    if ((certResponse =
         CMP_CERTREPMESSAGE_certResponse_get0(certRep, certReqId))) {
        return certResponse->status->statusString;
    }

    CMPerr(CMP_F_CMP_CERTREPMESSAGE_PKISTATUSSTRING_GET0,
           CMP_R_ERROR_REQID_NOT_FOUND);
    return NULL;
}

/* ############################################################################ *
 * checks bits in given PKIFailureInfo
 * returns 1 if a given bit is set in a PKIFailureInfo
 *                              0 if                    not set
 *                         -1 on error
 * PKIFailureInfo ::= ASN1_BIT_STRING
 * ############################################################################ */
int CMP_PKIFAILUREINFO_check(ASN1_BIT_STRING *failInfo, int codeBit)
{
    if (!failInfo)
        return -1;
    if ((codeBit < 0) || (codeBit > CMP_PKIFAILUREINFO_MAX))
        return -1;

    return ASN1_BIT_STRING_get_bit(failInfo, codeBit);
}

/* ############################################################################ *
 * returns a pointer to the CertResponse with the given certReqId inside a CertRepMessage
 * returns NULL on error or if no CertResponse available
 * ############################################################################ */
CMP_CERTRESPONSE *CMP_CERTREPMESSAGE_certResponse_get0(CMP_CERTREPMESSAGE
                                                       *certRep,
                                                       long certReqId)
{
    CMP_CERTRESPONSE *certResponse = NULL;
    int certRespCount;
    int i;

    if (!certRep)
        return NULL;

    certRespCount = sk_CMP_CERTRESPONSE_num(certRep->response);

    for (i = 0; i < certRespCount; i++) {
        /* is it the right certReqId */
        if (certReqId ==
            ASN1_INTEGER_get(sk_CMP_CERTRESPONSE_value
                             (certRep->response, i)->certReqId)) {
            certResponse = sk_CMP_CERTRESPONSE_value(certRep->response, i);
            break;
        }
    }

    return certResponse;
}

/* ############################################################################ *
 * internal function
 *
 * returns a pointer to a copy of the Certificate with the given certReqId inside a CertRepMessage
 * returns NULL on error or if no Certificate available
 * ############################################################################ */
static X509 *CMP_CERTREPMESSAGE_cert_get1(CMP_CERTREPMESSAGE *certRep,
                                          long certReqId)
{
    X509 *certCopy = NULL;
    CMP_CERTRESPONSE *certResponse = NULL;

    if (!certRep)
        return NULL;

    if ((certResponse =
         CMP_CERTREPMESSAGE_certResponse_get0(certRep, certReqId))) {
        certCopy =
            X509_dup(certResponse->certifiedKeyPair->certOrEncCert->
                     value.certificate);
    }

    return certCopy;
}

/* ############################################################################# *
 * internal function
 *
 * Decrypts the certificate with the given certReqId inside a CertRepMessage and
 * this is needed for the indirect PoP method as in section 5.2.8.2
 *
 * returns a pointer to the decrypted certificate
 * returns NULL on error or if no Certificate available
 * ############################################################################# */
static X509 *CMP_CERTREPMESSAGE_encCert_get1(CMP_CERTREPMESSAGE *certRep,
                                             long certReqId, EVP_PKEY *pkey)
{
    CRMF_ENCRYPTEDVALUE *encCert = NULL;
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
    CMP_CERTRESPONSE *certResponse = NULL;

    if (!(certResponse =
          CMP_CERTREPMESSAGE_certResponse_get0(certRep, certReqId)))
        goto err;

    if (!(encCert =
          certResponse->certifiedKeyPair->certOrEncCert->value.encryptedCert))
        goto err;

    if (!(symmAlg = OBJ_obj2nid(encCert->symmAlg->algorithm)))
        goto err;

    /* first the symmetric key needs to be decrypted */
    if ((pkctx = EVP_PKEY_CTX_new(pkey, NULL))
        && EVP_PKEY_decrypt_init(pkctx)) {
        ASN1_BIT_STRING *encKey = encCert->encSymmKey;
        size_t eksize = 0;

        if (EVP_PKEY_decrypt
            (pkctx, NULL, &eksize, encKey->data, encKey->length) <= 0
            || !(ek = OPENSSL_malloc(eksize))
            || EVP_PKEY_decrypt(pkctx, ek, &eksize, encKey->data,
                                encKey->length) <= 0) {
            CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1,
                   CMP_R_ERROR_DECRYPTING_SYMMETRIC_KEY);
            goto err;
        }
        EVP_PKEY_CTX_free(pkctx);
    } else {
        CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1,
               CMP_R_ERROR_DECRYPTING_KEY);
        goto err;
    }

    /* select symmetric cipher based on algorithm given in message */
    if (!(cipher = EVP_get_cipherbynid(symmAlg))) {
        CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1,
               CMP_R_UNSUPPORTED_CIPHER);
        goto err;
    }
    if (!(iv = OPENSSL_malloc(EVP_CIPHER_iv_length(cipher))))
        goto err;
    ASN1_TYPE_get_octetstring(encCert->symmAlg->parameter, iv,
                              EVP_CIPHER_iv_length(cipher));

    /* d2i_X509 changes the given pointer, so use p for decoding the message and keep the 
     * original pointer in outbuf so that the memory can be freed later */
    if (!(p = outbuf =
          OPENSSL_malloc(encCert->encValue->length + EVP_CIPHER_block_size(cipher))))
        goto err;
    evp_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(evp_ctx, 0);

    if (!EVP_DecryptInit(evp_ctx, cipher, ek, iv)
        || !EVP_DecryptUpdate(evp_ctx, outbuf, &outlen,
                              encCert->encValue->data,
                              encCert->encValue->length)
        || !EVP_DecryptFinal(evp_ctx, outbuf + outlen, &n)) {
        CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1,
               CMP_R_ERROR_DECRYPTING_CERTIFICATE);
        goto err;
    }
    outlen += n;

    /* convert decrypted certificate from DER to internal ASN.1 structure */
    if (!(cert = d2i_X509(NULL, &p, outlen))) {
        CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1,
               CMP_R_ERROR_DECODING_CERTIFICATE);
        goto err;
    }

    OPENSSL_free(outbuf);
    EVP_CIPHER_CTX_free(evp_ctx);
    OPENSSL_free(ek);
    OPENSSL_free(iv);
    return cert;
 err:
    CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1,
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

/* ############################################################################ *
 * returns the type of the certificate contained in the certificate response
 * returns -1 on errror
 * ############################################################################ */
int CMP_CERTREPMESSAGE_certType_get(CMP_CERTREPMESSAGE *certRep,
                                    long certReqId)
{
    CMP_CERTRESPONSE *certResponse = NULL;

    if (!certRep)
        return -1;
    if (!(certResponse =
          CMP_CERTREPMESSAGE_certResponse_get0(certRep, certReqId)))
        return -1;

    return certResponse->certifiedKeyPair->certOrEncCert->type;
}

/* ############################################################################ *
 * returns 1 on success
 * returns 0 on error
 * ############################################################################ */
int CMP_PKIMESSAGE_set_bodytype(CMP_PKIMESSAGE *msg, int type)
{
    if (!msg)
        return 0;

    msg->body->type = type;

    return 1;
}

/* ############################################################################ *
 * returns the body type of the given CMP message
 * returns -1 on error
 * ############################################################################ */
int CMP_PKIMESSAGE_get_bodytype(CMP_PKIMESSAGE *msg)
{
    if (!msg)
        return -1;

    return msg->body->type;
}

/* ############################################################################ *
 * return pointer to human readable error message string created out of the
 * information extracted from given error message
 * returns NULL on error
 * ############################################################################ */
char *CMP_PKIMESSAGE_parse_error_msg(CMP_PKIMESSAGE *msg, char *errormsg,
                                     int bufsize)
{
    char *status, *failureinfo;

    if (!msg)
        return NULL;
    if (CMP_PKIMESSAGE_get_bodytype(msg) != V_CMP_PKIBODY_ERROR)
        return NULL;

    status =
        CMP_PKISTATUSINFO_PKIstatus_get_string(msg->body->value.
                                               error->pKIStatusInfo);
    if (!status) {
        CMPerr(CMP_F_CMP_PKIMESSAGE_PARSE_ERROR_MSG,
               CMP_R_ERROR_PARSING_ERROR_MESSAGE);
        return NULL;
    }

    /* PKIFailureInfo is optional */
    failureinfo =
        CMP_PKISTATUSINFO_PKIFailureInfo_get_string(msg->body->value.
                                                    error->pKIStatusInfo);

    STACK_OF (ASN1_UTF8STRING) * details =
        msg->body->value.error->pKIStatusInfo->statusString;
    ASN1_UTF8STRING *str = 0;
    if (details && sk_ASN1_UTF8STRING_num(details) > 0)
        str = sk_ASN1_UTF8STRING_value(details, 0);

    if (failureinfo && str && str->data) {
        BIO_snprintf(errormsg, bufsize, "%s, %s: %s", status, failureinfo,
                     str->data);
    } else if (failureinfo)
        BIO_snprintf(errormsg, bufsize, "%s, %s", status, failureinfo);
    else
        BIO_snprintf(errormsg, bufsize, "%s", status);

    return errormsg;
}

/* ############################################################################ *
 * Retrieve the returned certificate from the given certrepmessage.
 * returns NULL if not found
 * TODO: create another function handing multiple certreps when 2 certificates
 * had been requested
 * ############################################################################ */
X509 *CMP_CERTREPMESSAGE_get_certificate(CMP_CTX *ctx,
                                         CMP_CERTREPMESSAGE *certrep)
{
    X509 *newClCert = NULL;
    int repNum = 0;

    /* Get the certReqId of the first certresponse. Need to do it this way instead
     * of just using certReqId==0, because in error cases the server might reply with a certReqId
     * of -1... */
    if (sk_CMP_CERTRESPONSE_num(certrep->response) > 0)
        repNum =
            ASN1_INTEGER_get(sk_CMP_CERTRESPONSE_value
                             (certrep->response, 0)->certReqId);

    CMP_CTX_set_failInfoCode(ctx,
                             CMP_CERTREPMESSAGE_PKIFailureInfo_get0(certrep,
                                                                    repNum));

    ctx->lastPKIStatus = CMP_CERTREPMESSAGE_PKIStatus_get(certrep, repNum);
    switch (ctx->lastPKIStatus) {
    case CMP_PKISTATUS_waiting:
        goto err;
        break;

    case CMP_PKISTATUS_grantedWithMods:
        CMP_printf(ctx, "WARNING: got \"grantedWithMods\"");

    case CMP_PKISTATUS_accepted:
        /* if we received a certificate then place it to ctx->newClCert and return,
         * if the cert is encrypted then we first decrypt it. */
        switch (CMP_CERTREPMESSAGE_certType_get(certrep, repNum)) {
        case CMP_CERTORENCCERT_CERTIFICATE:
            if (!(newClCert = CMP_CERTREPMESSAGE_cert_get1(certrep, repNum))) {
                CMPerr(CMP_F_CMP_CERTREPMESSAGE_GET_CERTIFICATE,
                       CMP_R_CERTIFICATE_NOT_FOUND);
                goto err;
            }
            break;
            /* certificate encrypted for PoP using indirect method according to section 5.2.8.2 */
        case CMP_CERTORENCCERT_ENCRYPTEDCERT:
            if (!(newClCert =
                  CMP_CERTREPMESSAGE_encCert_get1(certrep, repNum,
                                                  ctx->newPkey))) {
                CMPerr(CMP_F_CMP_CERTREPMESSAGE_GET_CERTIFICATE,
                       CMP_R_CERTIFICATE_NOT_FOUND);
                goto err;
            }
            break;
        default:
            CMPerr(CMP_F_CMP_CERTREPMESSAGE_GET_CERTIFICATE,
                   CMP_R_UNKNOWN_CERTTYPE);
            goto err;
        }
        break;

        /* get all information in case of a rejection before going to error */
    case CMP_PKISTATUS_rejection:{
            char *failInfoString = NULL;
            char *statusString = NULL;
            int statusLen = 0;
            ASN1_UTF8STRING *status = NULL;
            STACK_OF (ASN1_UTF8STRING) * strstack =
                CMP_CERTREPMESSAGE_PKIStatusString_get0(certrep, repNum);

            CMPerr(CMP_F_CMP_CERTREPMESSAGE_GET_CERTIFICATE,
                   CMP_R_REQUEST_REJECTED_BY_CA);

            failInfoString =
                CMP_CERTREPMESSAGE_PKIFailureInfoString_get0(certrep, repNum);
            if (failInfoString)
                /* initialize status string with human readable failure info */
                statusString = OPENSSL_strdup(failInfoString);
            else
                statusString = OPENSSL_strdup("<no failure info received>");

            statusLen = strlen(statusString) + 18;
            statusString = OPENSSL_realloc(statusString, statusLen);
            if (!statusString)
                goto err;
            strcat(statusString, ", statusString: \""); /* length = 17 */

            while ((status = sk_ASN1_UTF8STRING_pop(strstack))) {
                statusLen += strlen((char *)status->data) + 1;
                statusString = OPENSSL_realloc(statusString, statusLen);
                if (!statusString)
                    goto err;
                strcat(statusString, (char *)status->data);
                strcat(statusString, " ");
            }

            strcat(statusString, "\"");
            ERR_add_error_data(1, statusString);

            goto err;
            break;
        }

    case CMP_PKISTATUS_revocationWarning:
    case CMP_PKISTATUS_revocationNotification:
    case CMP_PKISTATUS_keyUpdateWarning:
        CMPerr(CMP_F_CMP_CERTREPMESSAGE_GET_CERTIFICATE,
               CMP_R_NO_CERTIFICATE_RECEIVED);
        goto err;
        break;

    default:{
            STACK_OF (ASN1_UTF8STRING) * strstack =
                CMP_CERTREPMESSAGE_PKIStatusString_get0(certrep, 0);
            ASN1_UTF8STRING *status = NULL;

            CMPerr(CMP_F_CMP_CERTREPMESSAGE_GET_CERTIFICATE,
                   CMP_R_UNKNOWN_PKISTATUS);
            while ((status = sk_ASN1_UTF8STRING_pop(strstack)))
                ERR_add_error_data(3, "statusString=\"", status->data, "\"");

            CMP_printf(ctx, "ERROR: unknown pkistatus %ld",
                       CMP_CERTREPMESSAGE_PKIStatus_get(certrep, repNum));
            goto err;
            break;
        }
    }

    return newClCert;
 err:
    return NULL;
}

/* ################################################################ *
 * Builds up the certificate chain of cert as high up as possible using
 * the given X509_STORE containing all possible intermediate certificates and
 * optionally the (possible) trust anchor(s).
 *
 * Intended use of this function is to find all the certificates below the trust
 * anchor needed to verify an EE's own certificate.  Those are supposed to be
 * included in the ExtraCerts field of every first sent message of an tansaction 
 * when MSG_SIG_ALG is utilized.
 * 
 * NOTE: This creates duplicates of each certificate,
 * so when the stack is no longer needed it should be freed with
 * sk_X509_pop_free()
 * NOTE: in case there are more than one possibilities for certificates up the
 * chain, OpenSSL seems to take the first one, check X509_verify_cert() for
 * details.
 *
 * returns a pointer to a stack of (duplicated) X509 certificates containing:
 *      - the EE certificate given in the function arguments (cert)
 *      - all intermediate certificates up the chain towards the trust anchor
 *      - the trust anchor if it was included in the store
 *      returns NULL on error
 * ################################################################ */
STACK_OF (X509) * CMP_build_cert_chain(X509_STORE *store, X509 *cert)
{
    STACK_OF (X509) * chain = NULL, *chainDup = NULL;
    X509_STORE_CTX *csc = NULL;
    int i = 0;

    if (!store || !cert)
        goto err;

    csc = X509_STORE_CTX_new();
    if (!csc)
        goto err;

    /* chainDup to store the duplicated certificates */
    chainDup = sk_X509_new_null();
    if (!chainDup)
        goto err;

    X509_STORE_set_flags(store, 0); /* clear all flags, e.g. do not check CRLs */
    if (!X509_STORE_CTX_init(csc, store, cert, NULL))
        goto err;

    X509_verify_cert(csc);      /* ignore return value as it would fail without trust anchor given in store */

    chain = X509_STORE_CTX_get0_chain(csc);
    for (i = 0; i < sk_X509_num(chain); i++) {
        X509 *certDup = X509_dup(sk_X509_value(chain, i));
        sk_X509_push(chainDup, certDup);
    }

    X509_STORE_CTX_free(csc);

    return chainDup;

 err:
    if (csc)
        X509_STORE_CTX_free(csc);
    if (chainDup)
        sk_X509_free(chainDup);
    return NULL;
}

/* ############################################################################ 
 * this function is intended to be used only within the CMP library although it is
 * included in cmp.h
 *
 * Returns the subject key identifier of the given certificate
 * returns NULL on error, respecively when none was found.
 * ############################################################################ */
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
    // if (!(ex = sk_X509_EXTENSION_value(cert->cert_info->extensions, subjKeyIDLoc)))
    if (!(ex = X509_get_ext((X509 *)cert, subjKeyIDLoc)))
        goto err;

    return X509_EXTENSION_get_data(ex);

 err:
    return NULL;
}
