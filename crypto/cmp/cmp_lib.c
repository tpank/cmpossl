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

/* CMP functions for PKIStatusInfo handling and PKIMessage decomposition */

#include <string.h>

#include "cmp_int.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <time.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/err.h> /* needed in case config no-deprecated */
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

/* get ASN.1 encoded integer, return -1 on error */
int CMP_ASN1_get_int(int func, const ASN1_INTEGER *a)
{
    int64_t res;

    if (!ASN1_INTEGER_get_int64(&res, a)) {
        CMPerr(func, ASN1_R_INVALID_NUMBER);
        return -1;
    }
    if (res < INT_MIN) {
        CMPerr(func, ASN1_R_TOO_SMALL);
        return -1;
    }
    if (res > INT_MAX) {
        CMPerr(func, ASN1_R_TOO_LARGE);
        return -1;
    }
    return (int)res;
}

int OSSL_CMP_PKISI_PKIStatus_get(OSSL_CMP_PKISI *si)
{
    if (si == NULL || si->status == NULL) {
        CMPerr(CMP_F_OSSL_CMP_PKISI_PKISTATUS_GET,
               CMP_R_ERROR_PARSING_PKISTATUS);
        return -1;
    }
    return CMP_ASN1_get_int(CMP_F_OSSL_CMP_PKISI_PKISTATUS_GET, si->status);
}

/*
 * internal function
 *
 * convert PKIStatus to human-readable string
 *
 * returns pointer to character array containing a sting representing the
 * PKIStatus of the given PKIStatusInfo
 * returns NULL on error
 */
static char *CMP_PKISI_PKIStatus_get_string(OSSL_CMP_PKISI *si)
{
    int PKIStatus;

    if ((PKIStatus = OSSL_CMP_PKISI_PKIStatus_get(si)) < 0)
        return NULL;
    switch (PKIStatus) {
    case OSSL_CMP_PKISTATUS_accepted:
        return "PKIStatus: accepted";
    case OSSL_CMP_PKISTATUS_grantedWithMods:
        return "PKIStatus: granted with mods";
    case OSSL_CMP_PKISTATUS_rejection:
        return "PKIStatus: rejection";
    case OSSL_CMP_PKISTATUS_waiting:
        return "PKIStatus: waiting";
    case OSSL_CMP_PKISTATUS_revocationWarning:
        return "PKIStatus: revocation warning";
    case OSSL_CMP_PKISTATUS_revocationNotification:
        return "PKIStatus: revocation notification";
    case OSSL_CMP_PKISTATUS_keyUpdateWarning:
        return "PKIStatus: key update warning";
    default:
        CMPerr(CMP_F_CMP_PKISI_PKISTATUS_GET_STRING,
               CMP_R_ERROR_PARSING_PKISTATUS);
    }
    return NULL;
}

/*
 * returns a pointer to the statusString contained in a PKIStatusInfo
 * returns NULL on error
 */
OSSL_CMP_PKIFREETEXT *OSSL_CMP_PKISI_statusString_get0(const OSSL_CMP_PKISI *si)
{
    return si == NULL ? NULL : si->statusString;
}

/*
 * returns a pointer to the failInfo contained in a PKIStatusInfo
 * returns NULL on error
 */
OSSL_CMP_PKIFAILUREINFO *OSSL_CMP_PKISI_failInfo_get0(const OSSL_CMP_PKISI *si)
{
    return si == NULL ? NULL : si->failInfo;
}

/*
 * returns the FailureInfo bits of the given PKIStatusInfo
 * returns -1 on error
 */
int OSSL_CMP_PKISI_PKIFailureInfo_get(OSSL_CMP_PKISI *si)
{
    int i;
    int res = 0;

    if (si == NULL || si->failInfo == NULL) {
        CMPerr(CMP_F_OSSL_CMP_PKISI_PKIFAILUREINFO_GET,
               CMP_R_ERROR_PARSING_PKISTATUS);
        return -1;
    }
    for (i = 0; i <= OSSL_CMP_PKIFAILUREINFO_MAX; i++)
        if (ASN1_BIT_STRING_get_bit(si->failInfo, i))
            res |= 1 << i;
    return res;
}

/*
 * internal function
 * convert PKIFailureInfo bit to human-readable string or empty string if not set
 *
 * returns pointer to static string
 * returns NULL on error
 */
static char *OSSL_CMP_PKIFAILUREINFO_get_string(OSSL_CMP_PKIFAILUREINFO *fi,
                                                int i)
{
    if (fi == NULL)
        return NULL;
    if (0 <= i && i <= OSSL_CMP_PKIFAILUREINFO_MAX) {
        if (ASN1_BIT_STRING_get_bit(fi, i)) {
            switch (i) {
            case OSSL_CMP_PKIFAILUREINFO_badAlg:
                return "PKIFailureInfo: badAlg";
            case OSSL_CMP_PKIFAILUREINFO_badMessageCheck:
                return "PKIFailureInfo: badMessageCheck";
            case OSSL_CMP_PKIFAILUREINFO_badRequest:
                return "PKIFailureInfo: badRequest";
            case OSSL_CMP_PKIFAILUREINFO_badTime:
                return "PKIFailureInfo: badTime";
            case OSSL_CMP_PKIFAILUREINFO_badCertId:
                return "PKIFailureInfo: badCertId";
            case OSSL_CMP_PKIFAILUREINFO_badDataFormat:
                return "PKIFailureInfo: badDataFormat";
            case OSSL_CMP_PKIFAILUREINFO_wrongAuthority:
                return "PKIFailureInfo: wrongAuthority";
            case OSSL_CMP_PKIFAILUREINFO_incorrectData:
                return "PKIFailureInfo: incorrectData";
            case OSSL_CMP_PKIFAILUREINFO_missingTimeStamp:
                return "PKIFailureInfo: missingTimeStamp";
            case OSSL_CMP_PKIFAILUREINFO_badPOP:
                return "PKIFailureInfo: badPOP";
            case OSSL_CMP_PKIFAILUREINFO_certRevoked:
                return "PKIFailureInfo: certRevoked";
            case OSSL_CMP_PKIFAILUREINFO_certConfirmed:
                return "PKIFailureInfo: certConfirmed";
            case OSSL_CMP_PKIFAILUREINFO_wrongIntegrity:
                return "PKIFailureInfo: wrongIntegrity";
            case OSSL_CMP_PKIFAILUREINFO_badRecipientNonce:
                return "PKIFailureInfo: badRecipientNonce";
            case OSSL_CMP_PKIFAILUREINFO_timeNotAvailable:
                return "PKIFailureInfo: timeNotAvailable";
            case OSSL_CMP_PKIFAILUREINFO_unacceptedPolicy:
                return "PKIFailureInfo: unacceptedPolicy";
            case OSSL_CMP_PKIFAILUREINFO_unacceptedExtension:
                return "PKIFailureInfo: unacceptedExtension";
            case OSSL_CMP_PKIFAILUREINFO_addInfoNotAvailable:
                return "PKIFailureInfo: addInfoNotAvailable";
            case OSSL_CMP_PKIFAILUREINFO_badSenderNonce:
                return "PKIFailureInfo: badSenderNonce";
            case OSSL_CMP_PKIFAILUREINFO_badCertTemplate:
                return "PKIFailureInfo: badCertTemplate";
            case OSSL_CMP_PKIFAILUREINFO_signerNotTrusted:
                return "PKIFailureInfo: signerNotTrusted";
            case OSSL_CMP_PKIFAILUREINFO_transactionIdInUse:
                return "PKIFailureInfo: transactionIdInUse";
            case OSSL_CMP_PKIFAILUREINFO_unsupportedVersion:
                return "PKIFailureInfo: unsupportedVersion";
            case OSSL_CMP_PKIFAILUREINFO_notAuthorized:
                return "PKIFailureInfo: notAuthorized";
            case OSSL_CMP_PKIFAILUREINFO_systemUnavail:
                return "PKIFailureInfo: systemUnavail";
            case OSSL_CMP_PKIFAILUREINFO_systemFailure:
                return "PKIFailureInfo: systemFailure";
            case OSSL_CMP_PKIFAILUREINFO_duplicateCertReq:
                return "PKIFailureInfo: duplicateCertReq";
            }
        } else {
            return ""; /* bit is not set */
        }
    }
    return NULL; /* illegal bit position */
}

/*
 * checks PKIFailureInfo bits in a given PKIStatusInfo
 * returns 1 if a given bit is set, 0 if not, -1 on error
 */
int OSSL_CMP_PKISI_PKIFailureInfo_check(OSSL_CMP_PKISI *si, int bit_index)
{
    ASN1_BIT_STRING *fail_info = OSSL_CMP_PKISI_failInfo_get0(si);

    if (fail_info == NULL) /* this can also indicate si == NULL */
        return -1;
    if (bit_index < 0 || bit_index > OSSL_CMP_PKIFAILUREINFO_MAX)
        return -1;

    return ASN1_BIT_STRING_get_bit(fail_info, bit_index);
}

/*
 * place human-readable error string created from PKIStatusInfo in given buffer
 * returns pointer to the same buffer containing the string, or NULL on error
 */
char *OSSL_CMP_PKISI_snprint(OSSL_CMP_PKISI *si, char *buf, int bufsize)
{
    const char *status, *failure;
    int i;
    int n = 0;

    if (si == NULL
            || (status = CMP_PKISI_PKIStatus_get_string(si)) == NULL)
        return NULL;
    BIO_snprintf(buf, bufsize, "%s; ", status);

    /* PKIFailure is optional and may be empty */
    if (si->failInfo != NULL) {
        for (i = 0; i <= OSSL_CMP_PKIFAILUREINFO_MAX; i++) {
            failure = OSSL_CMP_PKIFAILUREINFO_get_string(si->failInfo, i);
            if (failure == NULL)
                return NULL;
            if (failure[0] != '\0')
                BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf), "%s%s",
                             n > 0 ? ", " : "", failure);
            n += (int)strlen(failure);
        }
    }
    if (n == 0)
        BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf), "<no failure info>");

    /* StatusString sequence is optional and may be empty */
    n = sk_ASN1_UTF8STRING_num(si->statusString);
    if (n > 0) {
        BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf),
                     "; StatusString%s: ", n > 1 ? "s" : "");
        for (i = 0; i < n; i++) {
            ASN1_UTF8STRING *text = sk_ASN1_UTF8STRING_value(si->statusString, i);
            BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf), "\"%s\"%s",
                         ASN1_STRING_get0_data(text), i < n-1 ? ", " : "");
        }
    }
    return buf;
}

/*
 * Creates a new PKIStatusInfo structure and fills it in
 * returns a pointer to the structure on success, NULL on error
 * note: strongly overlaps with TS_RESP_CTX_set_status_info()
 *       and TS_RESP_CTX_add_failure_info() in ../ts/ts_rsp_sign.c
 */
OSSL_CMP_PKISI *OSSL_CMP_statusInfo_new(int status, int fail_info,
                                        const char *text)
{
    OSSL_CMP_PKISI *si = NULL;
    ASN1_UTF8STRING *utf8_text = NULL;
    int failure;

    if ((si = OSSL_CMP_PKISI_new()) == NULL)
        goto err;
    if (!ASN1_INTEGER_set(si->status, status))
        goto err;

    if (text != NULL) {
        if ((utf8_text = ASN1_UTF8STRING_new()) == NULL
                || !ASN1_STRING_set(utf8_text, text, (int)strlen(text)))
            goto err;
        if (si->statusString == NULL
                && (si->statusString = sk_ASN1_UTF8STRING_new_null()) == NULL)
            goto err;
        if (!sk_ASN1_UTF8STRING_push(si->statusString, utf8_text))
            goto err;
        /* Ownership is lost. */
        utf8_text = NULL;
    }

    for (failure = 0; failure <= OSSL_CMP_PKIFAILUREINFO_MAX; failure++) {
        if ((fail_info & (1 << failure)) != 0) {
            if (si->failInfo == NULL
                    && (si->failInfo = ASN1_BIT_STRING_new()) == NULL)
                goto err;
            if (!ASN1_BIT_STRING_set_bit(si->failInfo, failure, 1))
                goto err;
        }
    }
    return si;

 err:
    CMPerr(CMP_F_OSSL_CMP_STATUSINFO_NEW, ERR_R_MALLOC_FAILURE);
    OSSL_CMP_PKISI_free(si);
    ASN1_UTF8STRING_free(utf8_text);
    return NULL;
}

/*-
 * returns the status field of the RevRepContent with the given
 * request/sequence id inside a revocation response.
 * RevRepContent has the revocation statuses in same order as they were sent in
 * RevReqContent.
 * returns NULL on error
 */
OSSL_CMP_PKISI *CMP_REVREPCONTENT_PKIStatusInfo_get(OSSL_CMP_REVREPCONTENT *rrep,
                                                    int rsid)
{
    OSSL_CMP_PKISI *status = NULL;

    if (rrep == NULL)
        return NULL;

    if ((status = sk_OSSL_CMP_PKISI_value(rrep->status, rsid)) != NULL) {
        return status;
    }

    CMPerr(CMP_F_CMP_REVREPCONTENT_PKISTATUSINFO_GET,
           CMP_R_PKISTATUSINFO_NOT_FOUND);
    return NULL;
}

/*
 * returns the CertId field in the revCerts part of the RevRepContent
 * with the given request/sequence id inside a revocation response.
 * RevRepContent has the CertIds in same order as they were sent in
 * RevReqContent.
 * returns NULL on error
 */
OSSL_CRMF_CERTID *CMP_REVREPCONTENT_CertId_get(OSSL_CMP_REVREPCONTENT *rrep,
                                               int rsid)
{
    OSSL_CRMF_CERTID *cid = NULL;

    if (rrep == NULL)
        return NULL;

    if ((cid = sk_OSSL_CRMF_CERTID_value(rrep->revCerts, rsid)) != NULL) {
        return cid;
    }

    CMPerr(CMP_F_CMP_REVREPCONTENT_CERTID_GET, CMP_R_CERTID_NOT_FOUND);
    return NULL;
}

static int suitable_rid(int func, const ASN1_INTEGER *certReqId, int rid)
{
    if (rid == -1) {
        return 1;
    } else {
        int trid = CMP_ASN1_get_int(func, certReqId);
        if (trid == -1) {
            CMPerr(func, CMP_R_BAD_REQUEST_ID);
            return 0;
        }
        return rid == trid;
    }
}

static void add_expected_rid(int rid)
{
    char str[DECIMAL_SIZE(rid)+1];
    BIO_snprintf(str, sizeof(str), "%d", rid);
    ERR_add_error_data(2, "expected certReqId = ", str);
}

/*
 * returns a pointer to the PollResponse with the given CertReqId
 * (or the first one in case -1) inside a PollRepContent
 * returns NULL on error or if no suitable PollResponse available
 */
OSSL_CMP_POLLREP
*CMP_POLLREPCONTENT_pollRep_get0(const OSSL_CMP_POLLREPCONTENT *prc, int rid)
{
    OSSL_CMP_POLLREP *pollRep = NULL;
    int i;

    if (prc == NULL) {
        CMPerr(CMP_F_CMP_POLLREPCONTENT_POLLREP_GET0, CMP_R_INVALID_ARGS);
        return NULL;
    }

    for (i = 0; i < sk_OSSL_CMP_POLLREP_num(prc); i++) {
        pollRep = sk_OSSL_CMP_POLLREP_value(prc, i);
        if (suitable_rid(CMP_F_CMP_POLLREPCONTENT_POLLREP_GET0,
                         pollRep->certReqId, rid))
            return pollRep;
    }

    CMPerr(CMP_F_CMP_POLLREPCONTENT_POLLREP_GET0, CMP_R_CERTRESPONSE_NOT_FOUND);
    add_expected_rid(rid);
    return NULL;
}

/*
 * returns a pointer to the CertResponse with the given CertReqId
 * (or the first one in case -1) inside a CertRepMessage
 * returns NULL on error or if no suitable CertResponse available
 */
OSSL_CMP_CERTRESPONSE
*CMP_CERTREPMESSAGE_certResponse_get0(const OSSL_CMP_CERTREPMESSAGE *crepmsg,
                                      int rid)
{
    OSSL_CMP_CERTRESPONSE *crep = NULL;
    int i;

    if (crepmsg == NULL || crepmsg->response == NULL) {
        CMPerr(CMP_F_CMP_CERTREPMESSAGE_CERTRESPONSE_GET0, CMP_R_INVALID_ARGS);
        return NULL;
    }

    for (i = 0; i < sk_OSSL_CMP_CERTRESPONSE_num(crepmsg->response); i++) {
        crep = sk_OSSL_CMP_CERTRESPONSE_value(crepmsg->response, i);
        if (suitable_rid(CMP_F_CMP_CERTREPMESSAGE_CERTRESPONSE_GET0,
                         crep->certReqId, rid))
            return crep;
    }

    CMPerr(CMP_F_CMP_CERTREPMESSAGE_CERTRESPONSE_GET0,
           CMP_R_CERTRESPONSE_NOT_FOUND);
    add_expected_rid(rid);
    return NULL;
}

/*
CMP_CERTRESPONSE_get_certificate() attempts to retrieve the returned
certificate from the given certResponse B<crep>.
Takes the newKey in case of indirect POP from B<ctx>.
Returns a pointer to a copy of the found certificate, or NULL if not found.
*/
X509 *CMP_CERTRESPONSE_get_certificate(OSSL_CMP_CTX *ctx,
                                       const OSSL_CMP_CERTRESPONSE *crep)
{
    OSSL_CMP_CERTORENCCERT *coec;
    X509 *crt = NULL;

    if (ctx == NULL || crep == NULL) {
        CMPerr(CMP_F_CMP_CERTRESPONSE_GET_CERTIFICATE, CMP_R_INVALID_ARGS);
        goto err;
    }
    if (crep->certifiedKeyPair
            && (coec = crep->certifiedKeyPair->certOrEncCert) != NULL) {
        switch (coec->type) {
        case OSSL_CMP_CERTORENCCERT_CERTIFICATE:
            crt = X509_dup(coec->value.certificate);
            break;
        case OSSL_CMP_CERTORENCCERT_ENCRYPTEDCERT:
        /* cert encrypted for indirect PoP; RFC 4210, 5.2.8.2 */
            crt = OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(coec->value.encryptedCert,
                                                   ctx->newPkey);
            break;
        default:
            CMPerr(CMP_F_CMP_CERTRESPONSE_GET_CERTIFICATE,
                   CMP_R_UNKNOWN_CERT_TYPE);
            goto err;
        }
        if (crt == NULL) {
            CMPerr(CMP_F_CMP_CERTRESPONSE_GET_CERTIFICATE,
                   CMP_R_CERTIFICATE_NOT_FOUND);
            goto err;
        }
    }
    return crt;

 err:
    return NULL;
}
