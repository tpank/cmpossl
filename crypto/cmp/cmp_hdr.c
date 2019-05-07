/*
 * Copyright 2007-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

/* CMP functions for PKIHeader handling */

#include "cmp_int.h"

#include <openssl/rand.h>

/* explicit #includes not strictly needed since implied by the above: */
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/err.h>

OSSL_CMP_PKIHEADER *OSSL_CMP_MSG_get0_header(const OSSL_CMP_MSG *msg)
{
    return msg != NULL ? msg->header : NULL;
}

/*
 * Sets the protocol version number in PKIHeader.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_set_pvno(OSSL_CMP_PKIHEADER *hdr, int pvno)
{
    if (hdr == NULL) {
        CMPerr(CMP_F_OSSL_CMP_HDR_SET_PVNO, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    if (!ASN1_INTEGER_set(hdr->pvno, pvno)) {
        CMPerr(CMP_F_OSSL_CMP_HDR_SET_PVNO, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    return 1;

 err:
    return 0;
}

/* returns the pvno of the given PKIHeader or -1 on error */
int OSSL_CMP_HDR_get_pvno(const OSSL_CMP_PKIHEADER *hdr)
{
    int64_t pvno;

    if (hdr == NULL) {
        CMPerr(CMP_F_OSSL_CMP_HDR_GET_PVNO, CMP_R_NULL_ARGUMENT);
        return -1;
    }
    if (!ASN1_INTEGER_get_int64(&pvno, hdr->pvno) || pvno < 0 || pvno > INT_MAX)
        return -1;
    return (int)pvno;
}

ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_transactionID(const OSSL_CMP_PKIHEADER *hdr)
{
    return hdr != NULL ? hdr->transactionID : NULL;
}

ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_senderNonce(const OSSL_CMP_PKIHEADER *hdr)
{
    return hdr != NULL ? hdr->senderNonce : NULL;
}

ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_recipNonce(const OSSL_CMP_PKIHEADER *hdr)
{
    return hdr != NULL ? hdr->recipNonce : NULL;
}

static int set1_general_name(GENERAL_NAME **tgt, const X509_NAME *src)
{
    GENERAL_NAME *gen = NULL;

    if (tgt == NULL) {
        CMPerr(CMP_F_SET1_GENERAL_NAME, CMP_R_NULL_ARGUMENT);
        goto err;
    }
    if ((gen = GENERAL_NAME_new()) == NULL)
        goto oom;

    gen->type = GEN_DIRNAME;

    if (src == NULL) { /* NULL DN */
        if ((gen->d.directoryName = X509_NAME_new()) == NULL)
            goto oom;
    } else if (!(X509_NAME_set(&gen->d.directoryName, src))) {
    oom:
        CMPerr(CMP_F_SET1_GENERAL_NAME, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    GENERAL_NAME_free(*tgt);
    *tgt = gen;

    return 1;

 err:
    GENERAL_NAME_free(gen);
    return 0;
}

/*
 * Set the sender name in PKIHeader.
 * when nm is NULL, sender is set to an empty string
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_set1_sender(OSSL_CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
    if (hdr == NULL)
        return 0;

    return set1_general_name(&hdr->sender, nm);
}

/*
 * Set the recipient name of PKIHeader.
 * when nm is NULL, recipient is set to an empty string
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_set1_recipient(OSSL_CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
    if (hdr == NULL)
        return 0;

    return set1_general_name(&hdr->recipient, nm);
}

/*
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
 */
int OSSL_CMP_HDR_update_messageTime(OSSL_CMP_PKIHEADER *hdr)
{
    if (hdr == NULL)
        goto err;

    if (hdr->messageTime == NULL)
        if ((hdr->messageTime = ASN1_GENERALIZEDTIME_new()) == NULL)
            goto err;

    if (ASN1_GENERALIZEDTIME_set(hdr->messageTime, time(NULL)) == NULL)
        goto err;
    return 1;

 err:
    CMPerr(CMP_F_OSSL_CMP_HDR_UPDATE_MESSAGETIME, ERR_R_MALLOC_FAILURE);
    return 0;
}

static int set1_aostr_else_random(ASN1_OCTET_STRING **tgt,
                                  const ASN1_OCTET_STRING *src, int len)
{
    unsigned char *bytes = NULL;
    int res = 0;

    if (src == NULL) { /* generate a random value if src == NULL */
        if ((bytes = (unsigned char *)OPENSSL_malloc(len)) == NULL) {
            CMPerr(CMP_F_SET1_AOSTR_ELSE_RANDOM, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (RAND_bytes(bytes, len) <= 0) {
            CMPerr(CMP_F_SET1_AOSTR_ELSE_RANDOM,CMP_R_FAILURE_OBTAINING_RANDOM);
            goto err;
        }
        res = OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(tgt, bytes, len);
    } else {
        res = OSSL_CMP_ASN1_OCTET_STRING_set1(tgt, src);
    }

 err:
    OPENSSL_free(bytes);
    return res;
}

/*
 * (re-)set given senderKID to given header
 *
 * senderKID: keyIdentifier of the sender's certificate or PBMAC reference value
 *       -- the reference number which the CA has previously issued
 *       -- to the end entity (together with the MACing key)
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_set1_senderKID(OSSL_CMP_PKIHEADER *hdr,
                                const ASN1_OCTET_STRING *senderKID)
{
    if (hdr == NULL)
        return 0;
    return OSSL_CMP_ASN1_OCTET_STRING_set1(&hdr->senderKID, senderKID);
}

/* push given ASN1_UTF8STRING to hdr->freeText and consume the given pointer */
int OSSL_CMP_HDR_push0_freeText(OSSL_CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text)
{
    if (hdr == NULL)
        goto err;
    if (text == NULL)
        goto err;

    if (hdr->freeText == NULL)
        if ((hdr->freeText = sk_ASN1_UTF8STRING_new_null()) == NULL)
            goto err;

    if (!(sk_ASN1_UTF8STRING_push(hdr->freeText, text)))
        goto err;

    return 1;

 err:
    CMPerr(CMP_F_OSSL_CMP_HDR_PUSH0_FREETEXT, ERR_R_MALLOC_FAILURE);
    return 0;
}

/* push an ASN1_UTF8STRING to hdr->freeText not consuming the given pointer */
int OSSL_CMP_HDR_push1_freeText(OSSL_CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text)
{
    if (hdr == NULL || text == NULL) {
        CMPerr(CMP_F_OSSL_CMP_HDR_PUSH1_FREETEXT, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    hdr->freeText = CMP_PKIFREETEXT_push_str(hdr->freeText, (char *)text->data);
    return hdr->freeText != NULL;
}

/*
CMP_PKIFREETEXT_push_str() pushes the given text string (unless it is NULL)
to the given PKIFREETEXT ft or to a newly allocated freeText if ft is NULL.
It returns the new/updated freeText. On error it frees ft and returns NULL.
*/
OSSL_CMP_PKIFREETEXT *CMP_PKIFREETEXT_push_str(OSSL_CMP_PKIFREETEXT *ft,
                                               const char *text)
{
    ASN1_UTF8STRING *utf8string = NULL;

    if (text == NULL) {
        return ft;
    }

    if (ft == NULL && (ft = sk_ASN1_UTF8STRING_new_null()) == NULL)
        goto oom;
    if ((utf8string = ASN1_UTF8STRING_new()) == NULL)
        goto oom;
    if (!ASN1_STRING_set(utf8string, text, (int)strlen(text)))
        goto oom;
    if (!(sk_ASN1_UTF8STRING_push(ft, utf8string)))
        goto oom;
    return ft;

 oom:
    CMPerr(CMP_F_CMP_PKIFREETEXT_PUSH_STR, ERR_R_MALLOC_FAILURE);
    sk_ASN1_UTF8STRING_pop_free(ft, ASN1_UTF8STRING_free);
    ASN1_UTF8STRING_free(utf8string);
    return NULL;
}

/*
 * push given itav to message header
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_generalInfo_item_push0(OSSL_CMP_PKIHEADER *hdr, OSSL_CMP_ITAV *itav)
{
    if (hdr == NULL)
        goto err;

    if (!OSSL_CMP_ITAV_stack_item_push0(&hdr->generalInfo, itav))
        goto err;
    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_HDR_GENERALINFO_ITEM_PUSH0,
           CMP_R_ERROR_PUSHING_GENERALINFO_ITEM);
    return 0;
}

int OSSL_CMP_MSG_generalInfo_items_push1(OSSL_CMP_MSG *msg,
                                         STACK_OF(OSSL_CMP_ITAV) *itavs)
{
    int i;
    OSSL_CMP_ITAV *itav = NULL;

    if (msg == NULL)
        goto err;

    for (i = 0; i < sk_OSSL_CMP_ITAV_num(itavs); i++) {
        itav = OSSL_CMP_ITAV_dup(sk_OSSL_CMP_ITAV_value(itavs,i));
        if (!OSSL_CMP_HDR_generalInfo_item_push0(msg->header, itav)) {
            OSSL_CMP_ITAV_free(itav);
            goto err;
        }
    }

    return 1;
 err:
    CMPerr(CMP_F_OSSL_CMP_MSG_GENERALINFO_ITEMS_PUSH1,
           CMP_R_ERROR_PUSHING_GENERALINFO_ITEMS);
    return 0;
}

/*
 * sets implicitConfirm in the generalInfo field of the PKIMessage header
 *
 * returns 1 on success, 0 on error
 */
int CMP_MSG_set_implicitConfirm(OSSL_CMP_MSG *msg)
{
    OSSL_CMP_ITAV *itav = NULL;

    if (msg == NULL)
        goto err;

    if ((itav = OSSL_CMP_ITAV_create(OBJ_nid2obj(NID_id_it_implicitConfirm),
                                     (ASN1_TYPE *)ASN1_NULL_new())) == NULL)
        goto err;
    if (!OSSL_CMP_HDR_generalInfo_item_push0(msg->header, itav))
        goto err;
    return 1;
 err:
    OSSL_CMP_ITAV_free(itav);
    return 0;
}

/*
 * checks if implicitConfirm in the generalInfo field of the header is set
 *
 * returns 1 if it is set, 0 if not
 */
int OSSL_CMP_MSG_check_implicitConfirm(OSSL_CMP_MSG *msg)
{
    int itavCount;
    int i;
    OSSL_CMP_ITAV *itav = NULL;

    if (msg == NULL)
        return 0;

    itavCount = sk_OSSL_CMP_ITAV_num(msg->header->generalInfo);

    for (i = 0; i < itavCount; i++) {
        itav = sk_OSSL_CMP_ITAV_value(msg->header->generalInfo, i);
        if (OBJ_obj2nid(itav->infoType) == NID_id_it_implicitConfirm)
            return 1;
    }

    return 0;
}

/*
 * Initialize the given PkiHeader structure with values set in the OSSL_CMP_CTX
 * This starts a new transaction in case ctx->transactionID is NULL.
 *
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_HDR_init(OSSL_CMP_CTX *ctx, OSSL_CMP_PKIHEADER *hdr)
{
    X509_NAME *sender;
    X509_NAME *rcp = NULL;

    if (ctx == NULL || hdr == NULL) {
        CMPerr(CMP_F_OSSL_CMP_HDR_INIT, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    /* set the CMP version */
    if (!OSSL_CMP_HDR_set_pvno(hdr, OSSL_CMP_PVNO))
        goto err;

    /*
     * if neither client cert nor subject name given, sender name is not known
     * to the client and in that case set to NULL-DN
     */
    sender = ctx->clCert != NULL ?
        X509_get_subject_name(ctx->clCert) : ctx->subjectName;
    if (sender == NULL && ctx->referenceValue == NULL) {
        CMPerr(CMP_F_OSSL_CMP_HDR_INIT, CMP_R_NO_SENDER_NO_REFERENCE);
        goto err;
    }
    if (!OSSL_CMP_HDR_set1_sender(hdr, sender))
        goto err;

    /* determine recipient entry in PKIHeader */
    if (ctx->srvCert != NULL) {
        rcp = X509_get_subject_name(ctx->srvCert);
        /* set also as expected_sender of responses unless set explicitly */
        if (ctx->expected_sender == NULL && rcp != NULL
                && !OSSL_CMP_CTX_set1_expected_sender(ctx, rcp))
        goto err;
    }
    else if (ctx->recipient != NULL)
        rcp = ctx->recipient;
    else if (ctx->issuer != NULL)
        rcp = ctx->issuer;
    else if (ctx->oldClCert != NULL)
        rcp = X509_get_issuer_name(ctx->oldClCert);
    else if (ctx->clCert != NULL)
        rcp = X509_get_issuer_name(ctx->clCert);
    if (!OSSL_CMP_HDR_set1_recipient(hdr, rcp))
        goto err;

    /* set current time as message time */
    if (!OSSL_CMP_HDR_update_messageTime(hdr))
        goto err;

    if (ctx->recipNonce != NULL)
        if (!OSSL_CMP_ASN1_OCTET_STRING_set1(&hdr->recipNonce, ctx->recipNonce))
            goto err;

    /*
     * set ctx->transactionID in CMP header
     * if ctx->transactionID is NULL, a random one is created with 128 bit
     * according to section 5.1.1:
     *
     * It is RECOMMENDED that the clients fill the transactionID field with
     * 128 bits of (pseudo-) random data for the start of a transaction to
     * reduce the probability of having the transactionID in use at the server.
     */
    if (ctx->transactionID == NULL
            && !set1_aostr_else_random(&ctx->transactionID,NULL,
                                       OSSL_CMP_TRANSACTIONID_LENGTH))
        goto err;
    if (!OSSL_CMP_ASN1_OCTET_STRING_set1(&hdr->transactionID,
                                         ctx->transactionID))
        goto err;

    /*
     * set random senderNonce
     * according to section 5.1.1:
     *
     * senderNonce                  present
     *         -- 128 (pseudo-)random bits
     * The senderNonce and recipNonce fields protect the PKIMessage against
     * replay attacks.      The senderNonce will typically be 128 bits of
     * (pseudo-) random data generated by the sender, whereas the recipNonce
     * is copied from the senderNonce of the previous message in the
     * transaction.
     */
    if (!set1_aostr_else_random(&hdr->senderNonce, NULL,
                                OSSL_CMP_SENDERNONCE_LENGTH))
        goto err;

    /* store senderNonce - for cmp with recipNonce in next outgoing msg */
    OSSL_CMP_CTX_set1_last_senderNonce(ctx, hdr->senderNonce);

#if 0
    /*
       freeText                [7] PKIFreeText                         OPTIONAL,
       -- this may be used to indicate context-specific instructions
       -- (this field is intended for human consumption)
     */
    if (ctx->freeText != NULL)
        if (!OSSL_CMP_HDR_push1_freeText(hdr, ctx->freeText))
            goto err;
#endif

    return 1;

 err:
    return 0;
}
