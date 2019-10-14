/* TODO Akretsch: convert input validation of non-public functions to assertions */
/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#define sleep(x) Sleep((x) * 1000)
#endif

#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <openssl/bio.h>
#include <openssl/cmp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>

#include "openssl/cmp_util.h"

#define IS_CREP(t) (t == OSSL_CMP_PKIBODY_IP || t == OSSL_CMP_PKIBODY_CP \
                        || t == OSSL_CMP_PKIBODY_KUP)

/*
 * Evaluate whether there's an standard-violating exception configured for
 * handling errors without protection or with invalid protection
 */
static int unprotected_exception(const OSSL_CMP_CTX *ctx,
                                 const OSSL_CMP_MSG *rep,
                                 int invalid_protection, int expected_type)
{
    int rcvd_type = ossl_cmp_msg_get_bodytype(rep /* may be NULL */);
    char *msg_type = NULL;

    if (ctx == NULL || rep == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    if (ctx->unprotectedErrors) {
        if (rcvd_type == OSSL_CMP_PKIBODY_ERROR) {
            msg_type = "error response";
        } else if (rcvd_type == OSSL_CMP_PKIBODY_RP
                       && ossl_cmp_pkisi_get_pkistatus(
                           ossl_cmp_revrepcontent_get_pkistatusinfo(
                                                            rep->body->value.rp,
                                                            OSSL_CMP_REVREQSID))
                       == OSSL_CMP_PKISTATUS_rejection) {
            msg_type = "revocation response message with rejection status";
        } else if (rcvd_type == OSSL_CMP_PKIBODY_PKICONF) {
            msg_type = "PKI Confirmation message";
        } else if (rcvd_type == expected_type && IS_CREP(rcvd_type)) {
            OSSL_CMP_CERTREPMESSAGE *crepmsg = rep->body->value.ip;
            OSSL_CMP_CERTRESPONSE *crep =
                ossl_cmp_certrepmessage_get0_certresponse(crepmsg, -1);

            if (sk_OSSL_CMP_CERTRESPONSE_num(crepmsg->response) > 1)
                /* a specific error could be misleading here */
                return 0;
            /*-
             * TODO: handle multiple CertResponses in CertRepMsg, in case
             *       multiple requests have been sent -->  GitHub issue#67
             */
            if (crep == NULL)
                /* a specific error could be misleading here */
                return 0;
            if (ossl_cmp_pkisi_get_pkistatus(crep->status)
                    == OSSL_CMP_PKISTATUS_rejection)
                msg_type = "CertRepMessage with rejection status";
        }
    }
    if (msg_type == NULL)
        return 0;
    OSSL_CMP_log2(WARN, "ignoring %s protection of %s",
                  invalid_protection ? "invalid" : "missing", msg_type);
    return 1;
}


/* Save error info from PKIStatusInfo field of a certresponse into ctx */
static int save_statusInfo(OSSL_CMP_CTX *ctx, OSSL_CMP_PKISI *si)
{
    int i;
    OSSL_CMP_PKIFREETEXT *ss;

    if (ctx == NULL || si == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if ((ctx->status = ossl_cmp_pkisi_get_pkistatus(si)) < 0)
        return 0;

    ctx->failInfoCode = 0;
    if (si->failInfo != NULL) {
        for (i = 0; i <= OSSL_CMP_PKIFAILUREINFO_MAX; i++) {
            if (ASN1_BIT_STRING_get_bit(si->failInfo, i))
                ctx->failInfoCode |= (1 << i);
        }
    }

    if (!ossl_cmp_ctx_set0_statusString(ctx, sk_ASN1_UTF8STRING_new_null())
            || (ctx->statusString == NULL))
        return 0;

    ss = si->statusString; /* may be NULL */
    for (i = 0; i < sk_ASN1_UTF8STRING_num(ss); i++) {
        ASN1_UTF8STRING *str = sk_ASN1_UTF8STRING_value(ss, i);

        if (!sk_ASN1_UTF8STRING_push(ctx->statusString, ASN1_STRING_dup(str)))
            return 0;
    }
    return 1;
}

/*
 * Perform the generic aspects of sending a request and receiving a response
 * returns 1 on success, 0 on error
 * Regardless of success, caller is responsible for freeing *rep (unless NULL).
 */
static int send_receive_check(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req,
                              OSSL_CMP_MSG **rep, int expected_type,
                              int not_received)
{
    const char *req_type_string =
        ossl_cmp_bodytype_to_string(ossl_cmp_msg_get_bodytype(req));
    int msgtimeout;
    int err, bt;
    const char *bt_string;
    OSSL_cmp_transfer_cb_t transfer_cb = ctx->transfer_cb;

    if (transfer_cb == NULL) {
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
        transfer_cb = OSSL_CMP_MSG_http_perform;
#else
        CMPerr(0, CMP_R_ERROR_TRANSFERRING_OUT);
        ossl_cmp_add_error_txt("; ", "HTTP transfer not possible due to OPENSSL_NO_OCSP or OPENSSL_NO_SOCK");
        return 0;
#endif
    }

    msgtimeout = ctx->msgtimeout; /* backup original value */
    if ((IS_CREP(expected_type) || expected_type == OSSL_CMP_PKIBODY_POLLREP)
            && ctx->totaltimeout > 0 /* total timeout is not infinite */) {
        int64_t time_left = (int64_t)(ctx->end_time - time(NULL));

        if (time_left <= 0) {
            CMPerr(0, CMP_R_TOTAL_TIMEOUT);
            return 0;
        }
        if (ctx->msgtimeout == 0 || time_left < ctx->msgtimeout)
            ctx->msgtimeout = (int)time_left;
    }

     /* should print error queue since transfer_cb may call ERR_clear_error() */
#ifndef OPENSSL_NO_STDIO
    OSSL_CMP_CTX_print_errors(ctx);
#endif

    OSSL_CMP_log1(INFO, "sending %s", req_type_string);
    err = (*transfer_cb)(ctx, req, rep);
    ctx->msgtimeout = msgtimeout; /* restore original value */

    if (err != 0) {
        if (err == CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE
                || err == CMP_R_READ_TIMEOUT
                || err == CMP_R_ERROR_DECODING_MESSAGE) {
            CMPerr(0, not_received);
        }
        else {
            CMPerr(0, CMP_R_ERROR_SENDING_REQUEST);
            ossl_cmp_add_error_data(req_type_string);
        }
        *rep = NULL;
        return 0;
    }

    if ((bt = ossl_cmp_msg_check_received(ctx, *rep, unprotected_exception,
                                          expected_type)) < 0)
        return 0;
    bt_string = ossl_cmp_bodytype_to_string(bt);
    OSSL_CMP_log1(INFO, "received %s", bt_string);

    if (bt == expected_type
        /* as an answer to polling, there could be IP/CP/KUP: */
            || (IS_CREP(bt) && expected_type == OSSL_CMP_PKIBODY_POLLREP))
        return 1;

    /* received message type is not one of the expected ones (e.g., error) */
    CMPerr(0, bt == OSSL_CMP_PKIBODY_ERROR ? CMP_R_RECEIVED_ERROR :
           CMP_R_UNEXPECTED_PKIBODY); /* in next line for mkerr.pl */

    if (bt == -1) {
        ERR_add_error_data(1, "no message or invalid message type '-1'");
    } else if (bt != OSSL_CMP_PKIBODY_ERROR) {
        ERR_add_error_data(3, "message type is '", bt_string, "'");
    } else {
        char *buf = OPENSSL_malloc(OSSL_CMP_PKISI_BUFLEN);
        OSSL_CMP_PKISI *si = (*rep)->body->value.error->pKIStatusInfo;

        if (save_statusInfo(ctx, si) && buf != NULL
                && OSSL_CMP_CTX_snprint_PKIStatus(ctx, buf,
                                                  OSSL_CMP_PKISI_BUFLEN) != NULL)
            ERR_add_error_data(1, buf);
        OPENSSL_free(buf);
    }
    return 0;
}

/*
 * When a 'waiting' PKIStatus has been received, this function is used to
 * attempt to poll for a response message.
 *
 * A total timeout may have been set in the context.  The function will continue
 * to poll until the timeout is reached and then poll a last time even when that
 * is before the "checkAfter" sent by the server. If ctx->totaltimeout is 0, the
 * timeout is disabled.
 *
 * returns 1 on success, returns received PKIMESSAGE in *msg argument
 * returns 0 on error or when timeout is reached without a received message
 *
 * TODO: handle multiple poll requests for multiple certificates
 *       --> GitHub issue#67
 */
static int pollForResponse(OSSL_CMP_CTX *ctx, int rid, OSSL_CMP_MSG **out)
{
    OSSL_CMP_MSG *preq = NULL;
    OSSL_CMP_MSG *prep = NULL;
    OSSL_CMP_POLLREP *pollRep = NULL;

    OSSL_CMP_info("received 'waiting' PKIStatus, starting to poll for response");
    for (;;) {
        if ((preq = ossl_cmp_pollReq_new(ctx, rid)) == NULL)
            goto err;

        if (!send_receive_check(ctx, preq, &prep, OSSL_CMP_PKIBODY_POLLREP,
                                CMP_R_POLLREP_NOT_RECEIVED))
            goto err;

        /* handle potential pollRep */
        if (ossl_cmp_msg_get_bodytype(prep) == OSSL_CMP_PKIBODY_POLLREP) {
            int64_t check_after;
            OSSL_CMP_POLLREPCONTENT *prc = prep->body->value.pollRep;

            /*-
             * TODO: handle multiple PollRepContent elements, in case
             *       multiple requests have been sent -->  GitHub issue#67
             */
            if (sk_OSSL_CMP_POLLREP_num(prc) > 1) {
                CMPerr(0, CMP_R_MULTIPLE_RESPONSES_NOT_SUPPORTED);
                goto err;
            }
            if ((pollRep = ossl_cmp_pollrepcontent_get0_pollrep(prc, rid))
                    == NULL)
                goto err;
            if (!ASN1_INTEGER_get_int64(&check_after, pollRep->checkAfter)) {
                CMPerr(0, CMP_R_BAD_CHECKAFTER_IN_POLLREP);
                goto err;
            }
            if (check_after < 0) {
                CMPerr(0, CMP_R_RECEIVED_NEGATIVE_CHECKAFTER_IN_POLLREP);
                goto err;
            }
            /* TODO: print OPTIONAL reason (PKIFreeText) from message */
            OSSL_CMP_log1(INFO,
                          "received polling response, waiting check_after =  "
                          "%ld sec before next polling request", check_after);

            if (ctx->totaltimeout > 0) { /* total timeout is not infinite */
                const int exp = 5; /* expected max time per msg round trip */
                int64_t time_left = (int64_t)(ctx->end_time - exp - time(NULL));

                if (time_left <= 0) {
                    CMPerr(0, CMP_R_TOTAL_TIMEOUT);
                    goto err;
                }
                if (time_left < check_after)
                    check_after = time_left;
                    /* poll one last time just when timeout was reached */
            }

            OSSL_CMP_MSG_free(preq);
            preq = NULL;
            OSSL_CMP_MSG_free(prep);
            prep = NULL;
            sleep((unsigned int)check_after);
        } else {
            OSSL_CMP_info("got ip/cp/kup after polling");
            break;
        }
    }
    if (prep == NULL)
        goto err;

    OSSL_CMP_MSG_free(preq);
    *out = prep;

    return 1;
 err:
    OSSL_CMP_MSG_free(preq);
    OSSL_CMP_MSG_free(prep);
    return 0;
}

/*
 * Send certConf for IR, CR or KUR sequences and check response
 * returns 1 on success, 0 on error
 */
int ossl_cmp_exchange_certConf(OSSL_CMP_CTX *ctx, int fail_info,
                               const char *txt)
{
    OSSL_CMP_MSG *certConf = NULL;
    OSSL_CMP_MSG *PKIconf = NULL;
    int success = 0;

    /*
     * check if all necessary options are set done by OSSL_CMP_certConf_new */
    /* create Certificate Confirmation - certConf
     */
    if ((certConf = ossl_cmp_certConf_new(ctx, fail_info, txt)) == NULL)
        goto err;

    success = send_receive_check(ctx, certConf, &PKIconf,
                                 OSSL_CMP_PKIBODY_PKICONF,
                                 CMP_R_PKICONF_NOT_RECEIVED);

 err:
    OSSL_CMP_MSG_free(certConf);
    OSSL_CMP_MSG_free(PKIconf);
    return success;
}

/*
 * Send given error and check response
 * returns 1 on success, 0 on error
 */
int ossl_cmp_exchange_error(OSSL_CMP_CTX *ctx, int status, int fail_info,
                            const char *txt)
{
    OSSL_CMP_MSG *error = NULL;
    OSSL_CMP_PKISI *si = NULL;
    OSSL_CMP_MSG *PKIconf = NULL;
    int success = 0;

    /*
     * check if all necessary options are set is done in OSSL_CMP_error_new
     * create Error Message - error
     */
    if ((si = ossl_cmp_statusinfo_new(status, fail_info, txt)) == NULL)
        goto err;
    if ((error = ossl_cmp_error_new(ctx, si, -1, NULL, 0)) == NULL)
        goto err;

    success = send_receive_check(ctx, error, &PKIconf, OSSL_CMP_PKIBODY_PKICONF,
                                 CMP_R_PKICONF_NOT_RECEIVED);

 err:
    OSSL_CMP_MSG_free(error);
    OSSL_CMP_PKISI_free(si);
    OSSL_CMP_MSG_free(PKIconf);
    return success;
}

/*
 * Retrieve a copy of the certificate, if any, from the given CertResponse.
 * Take into account PKIStatusInfo of CertResponse in ctx, report it on error.
 * returns NULL if not found or on error
 */
static X509 *get1_cert_status(OSSL_CMP_CTX *ctx, int bodytype,
                              OSSL_CMP_CERTRESPONSE *crep)
{
    char *buf = NULL;
    X509 *crt = NULL;
    EVP_PKEY *privkey = NULL;/* TODO Akretsch remove needless init */

    if (ctx == NULL || crep == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    privkey = OSSL_CMP_CTX_get0_newPkey(ctx, 1);
    switch (ossl_cmp_pkisi_get_pkistatus(crep->status)) {
    case OSSL_CMP_PKISTATUS_waiting:
        OSSL_CMP_err("received \"waiting\" status for cert when actually aiming to extract cert");
        CMPerr(0, CMP_R_ENCOUNTERED_WAITING);
        goto err;
    case OSSL_CMP_PKISTATUS_grantedWithMods:
        OSSL_CMP_warn("received \"grantedWithMods\" for certificate");
        crt = ossl_cmp_certresponse_get1_certificate(privkey, crep);
        break;
    case OSSL_CMP_PKISTATUS_accepted:
        crt = ossl_cmp_certresponse_get1_certificate(privkey, crep);
        break;
        /* get all information in case of a rejection before going to error */
    case OSSL_CMP_PKISTATUS_rejection:
        OSSL_CMP_err("received \"rejection\" status rather than cert");
        CMPerr(0, CMP_R_REQUEST_REJECTED_BY_CA);
        goto err;
    case OSSL_CMP_PKISTATUS_revocationWarning:
        OSSL_CMP_warn("received \"revocationWarning\" - a revocation of the cert is imminent");
        crt = ossl_cmp_certresponse_get1_certificate(privkey, crep);
        break;
    case OSSL_CMP_PKISTATUS_revocationNotification:
        OSSL_CMP_warn("received \"revocationNotification\" - a revocation of the cert has occurred");
        crt = ossl_cmp_certresponse_get1_certificate(privkey, crep);
        break;
    case OSSL_CMP_PKISTATUS_keyUpdateWarning:
        if (bodytype != OSSL_CMP_PKIBODY_KUR) {
            CMPerr(0, CMP_R_ENCOUNTERED_KEYUPDATEWARNING);
            goto err;
        }
        crt = ossl_cmp_certresponse_get1_certificate(privkey, crep);
        break;
    default:
        OSSL_CMP_log1(ERROR,
                      "received unsupported PKIStatus %d for certificate",
                      ctx->status);
        CMPerr(0, CMP_R_ENCOUNTERED_UNSUPPORTED_PKISTATUS);
        goto err;
    }
    if (crt == NULL) /* according to PKIStatus, we can expect a cert */
        CMPerr(0, CMP_R_CERTIFICATE_NOT_FOUND);

    return crt;

 err:
    if ((buf = OPENSSL_malloc(OSSL_CMP_PKISI_BUFLEN)) != NULL
            && OSSL_CMP_CTX_snprint_PKIStatus(ctx, buf,
                                              OSSL_CMP_PKISI_BUFLEN) != NULL)
        ERR_add_error_data(1, buf);
    OPENSSL_free(buf);
    return NULL;
}

/*-
 * Callback fn validating that the new certificate can be verified, using
 * ctx->certConf_cb_arg, which has been initialized using opt_out_trusted, and
 * ctx->untrusted_certs, which at this point already contains ctx->extraCertsIn.
 * Returns 0 on acceptance, else a bit field reflecting PKIFailureInfo.
 * Quoting from RFC 4210 section 5.1. Overall PKI Message:
 *     The extraCerts field can contain certificates that may be useful to
 *     the recipient.  For example, this can be used by a CA or RA to
 *     present an end entity with certificates that it needs to verify its
 *     own new certificate (if, for example, the CA that issued the end
 *     entity's certificate is not a root CA for the end entity).  Note that
 *     this field does not necessarily contain a certification path; the
 *     recipient may have to sort, select from, or otherwise process the
 *     extra certificates in order to use them.
 * Note: While often handy, there is no hard requirement by CMP that
 * an EE must be able to validate the certificates it gets enrolled.
 */
int OSSL_CMP_certConf_cb(OSSL_CMP_CTX *ctx, X509 *cert, int fail_info,
                         const char **text)
{
    X509_STORE *out_trusted = OSSL_CMP_CTX_get_certConf_cb_arg(ctx);
    (void)text; /* make (artificial) use of var to prevent compiler warning */

    if (fail_info != 0) /* accept any error flagged by CMP core library */
        return fail_info;

    if (out_trusted != NULL
            && !OSSL_CMP_validate_cert_path(ctx, out_trusted, cert))
        fail_info = 1 << OSSL_CMP_PKIFAILUREINFO_incorrectData;

    return fail_info;
}

/*
 * Perform the generic handling of certificate responses for IR/CR/KUR/P10CR
 * returns 1 on success, 0 on error
 * Regardless of success, caller is responsible for freeing *resp (unless NULL).
 */
static int cert_response(OSSL_CMP_CTX *ctx, int rid, OSSL_CMP_MSG **resp,
                         int req_type, int not_received)
{
    EVP_PKEY *rkey = OSSL_CMP_CTX_get0_newPkey(ctx /* may be NULL */, 0);
    int fail_info = 0; /* no failure */
    const char *txt = NULL;
    OSSL_CMP_CERTREPMESSAGE *crepmsg;
    OSSL_CMP_CERTRESPONSE *crep;
    X509 *cert;
    char *subj = NULL;
    int ret = 1;

 retry:
    crepmsg = (*resp)->body->value.ip; /* same for cp and kup */
    if (sk_OSSL_CMP_CERTRESPONSE_num(crepmsg->response) > 1) {
        CMPerr(0, CMP_R_MULTIPLE_RESPONSES_NOT_SUPPORTED);
        return 0;
    }
    /*
     * TODO handle multiple CertResponses in CertRepMsg (in case multiple
     * requests have been sent) -->  GitHub issue#67
     */
    if ((crep = ossl_cmp_certrepmessage_get0_certresponse(crepmsg, rid)) == NULL)
        return 0;
    if (rid == -1) {
        /* for OSSL_CMP_PKIBODY_P10CR learn CertReqId from response */
        rid = ossl_cmp_asn1_get_int(crep->certReqId);
        if (rid == -1) {
            CMPerr(0, CMP_R_BAD_REQUEST_ID);
            return 0;
        }
    }

    if (ossl_cmp_pkisi_get_pkistatus(crep->status)
            == OSSL_CMP_PKISTATUS_waiting) {
        OSSL_CMP_MSG_free(*resp);
        if (pollForResponse(ctx, rid, resp)) {
            goto retry; /* got rp/cp/kup which might still indicate 'waiting' */
        } else {
            CMPerr(0, not_received);
            ERR_add_error_data(1, "received 'waiting' pkistatus but polling failed");
            *resp = NULL;
            return 0;
        }
    }

    if (!save_statusInfo(ctx, crep->status))
        return 0;
    cert = get1_cert_status(ctx, (*resp)->body->type, crep);
    if (cert == NULL) {
        ossl_cmp_add_error_data("cannot extract certificate from response");
        return 0;
    }
    if (!ossl_cmp_ctx_set0_newCert(ctx, cert))
        return 0;

    /*
     * if the CMP server returned certificates in the caPubs field, copy them
     * to the context so that they can be retrieved if necessary
     */
    if (crepmsg->caPubs != NULL
            && !ossl_cmp_ctx_set1_caPubs(ctx, crepmsg->caPubs))
        return 0;

    /* copy received extraCerts to ctx->extraCertsIn so they can be retrieved */
    if (!ossl_cmp_ctx_set1_extraCertsIn(ctx, (*resp)->extraCerts))
        return 0;

    subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    if (rkey != NULL
        /* X509_check_private_key() also works if rkey is just public key */
            && !(X509_check_private_key(ctx->newCert, rkey))) {
        fail_info = 1 << OSSL_CMP_PKIFAILUREINFO_incorrectData;
        txt = "public key in new certificate does not match our enrollment key";
        /*-
         * not callling (void)ossl_cmp_exchange_error(ctx,
         *                    OSSL_CMP_PKISTATUS_rejection, fail_info, txt)
         * not throwing CMP_R_CERTIFICATE_NOT_ACCEPTED with txt
         * not returning 0
         * since we better leave this for any ctx->certConf_cb to decide
         */
    }

    /*
     * Execute the certification checking callback function possibly set in ctx,
     * which can determine whether to accept a newly enrolled certificate.
     * It may overrule the pre-decision reflected in 'fail_info' and '*txt'.
     */
    if (ctx->certConf_cb
            && (fail_info = ctx->certConf_cb(ctx, ctx->newCert,
                                             fail_info, &txt)) != 0) {
        if (txt == NULL)
            txt = "CMP client application did not accept it";
    }
    if (fail_info != 0) /* immediately log error before any certConf exchange */
        OSSL_CMP_log1(ERROR,
                      "rejecting newly enrolled cert with subject: %s", subj);

    /*
     * TODO: better move certConf exchange to do_certreq_seq() such that
     * also more low-level errors with CertReqMessages get reported to server
     */
    if (!ctx->disableConfirm
            && !ossl_cmp_hdr_check_implicitConfirm((*resp)->header)) {
        if (!ossl_cmp_exchange_certConf(ctx, fail_info, txt))
            ret = 0;
    }

    /* not throwing failure earlier as transfer_cb may call ERR_clear_error() */
    if (fail_info != 0) {
        CMPerr(0, CMP_R_CERTIFICATE_NOT_ACCEPTED);
        ERR_add_error_data(2, "rejecting newly enrolled cert with subject: ",
                           subj);
        if (txt != NULL)
            ossl_cmp_add_error_txt("; ", txt);
        ret = 0;
    }
    OPENSSL_free(subj);
    return ret;
}

#define INFO_CONTACTING_SERVER(ctx) OSSL_CMP_log2(INFO, "contacting %s:%d", \
    (ctx)->serverName == NULL ? "(no server name)" : (ctx)->serverName, \
    (ctx)->serverPort);

/*
 * Do the full sequence CR/IR/KUR/P10CR, CP/IP/KUP/CP,
 * certConf, PKIconf, and potential polling.
 *
 * All options need to be set in the context.
 *
 * TODO: another function to request two certificates at once should be created
 *
 * returns pointer to received certificate, or NULL if none was received
 */
static X509 *do_certreq_seq(OSSL_CMP_CTX *ctx, int req_type, int req_err,
                            int rep_type, int rep_err)
{
    OSSL_CMP_MSG *req = NULL;
    OSSL_CMP_MSG *rep = NULL;
    int rid = (req_type == OSSL_CMP_PKIBODY_P10CR) ? -1 : OSSL_CMP_CERTREQID;
    X509 *result = NULL;

    if (ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }

    if (ctx->totaltimeout > 0) /* else ctx->end_time is not used */
        ctx->end_time = time(NULL) + ctx->totaltimeout;
    ctx->status = -1;

    /* check if all necessary options are set done by OSSL_CMP_certreq_new */
    if ((req = ossl_cmp_certReq_new(ctx, req_type, req_err)) == NULL)
        goto err;

    INFO_CONTACTING_SERVER(ctx);
    if (!send_receive_check(ctx, req, &rep, rep_type, rep_err))
        goto err;

    if (!cert_response(ctx, rid, &rep, req_type, rep_err))
        goto err;

    result = ctx->newCert;
 err:
    OSSL_CMP_MSG_free(req);
    OSSL_CMP_MSG_free(rep);
    return result;
}

/*
 * Do the full sequence for RR, including RR, RP, and potential polling
 *
 * All options need to be set in the context,
 * in particular oldCert, the certificate to be revoked.
 *
 * TODO: this function can only revoke one certificate so far,
 * should be possible for several (num_RevDetails > 1) according to 5.3.9
 *
 * The RFC is vague in which PKIStatus should be returned by the server, so we
 * take "accepted, "grantedWithMods", and "revocationWarning" as success,
 * "revocationNotification" is used by some CAs as an indication that the
 * certificate was already revoked, "rejection" as indication that the
 * revocation was rejected, and do not expect "waiting" or "keyUpdateWarning"
 * (which are handled as error).
 *
 * returns the revoked cert on success, NULL on error
 */
X509 *OSSL_CMP_exec_RR_ses(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_MSG *rr = NULL;
    OSSL_CMP_MSG *rp = NULL;
    const int num_RevDetails = 1;
    const int rsid = OSSL_CMP_REVREQSID;
    OSSL_CMP_REVREPCONTENT *rrep = NULL;
    OSSL_CMP_PKISI *si = NULL;
    char *buf = NULL;
    X509 *result = NULL;

    if (ctx == NULL) {
        CMPerr(0, CMP_R_INVALID_ARGS);
        return 0;
    }

    ctx->status = -1;

    /*
     * check if all necessary options are set is done in OSSL_CMP_rr_new
     * create Revocation Request - ir
     */
    if ((rr = ossl_cmp_rr_new(ctx)) == NULL)
        goto end;

    INFO_CONTACTING_SERVER(ctx);
    if (!send_receive_check(ctx, rr, &rp, OSSL_CMP_PKIBODY_RP,
                            CMP_R_RP_NOT_RECEIVED))
        goto end;

    rrep = rp->body->value.rp;
    if (sk_OSSL_CMP_PKISI_num(rrep->status) != num_RevDetails) {
        CMPerr(0, CMP_R_WRONG_RP_COMPONENT_COUNT);
        goto end;
    }

    /* evaluate PKIStatus field */
    si = ossl_cmp_revrepcontent_get_pkistatusinfo(rrep, rsid);
    if (!save_statusInfo(ctx, si))
        goto err;
    switch (ossl_cmp_pkisi_get_pkistatus(si)) {
    case OSSL_CMP_PKISTATUS_accepted:
      /*TODO OSSL_CMP_info("revocation accepted (PKIStatus=accepted)");*/
        result = ctx->oldCert;
        break;
    case OSSL_CMP_PKISTATUS_grantedWithMods:
      /*TODO OSSL_CMP_info("revocation accepted (PKIStatus=grantedWithMods)");*/
        result = ctx->oldCert;
        break;
    case OSSL_CMP_PKISTATUS_rejection:
      /*TODO SSL_CMP_info("revocation accepted (PKIStatus=revocationWarning)");*/
        CMPerr(0, CMP_R_REQUEST_REJECTED_BY_CA);
        goto err;
    case OSSL_CMP_PKISTATUS_revocationWarning:
      /*TODO OSSL_CMP_info("revocation accepted (PKIStatus=revocationNotification)");*/
        result = ctx->oldCert;
        break;
    case OSSL_CMP_PKISTATUS_revocationNotification:
        /* interpretation as warning or error depends on CA */
      /*TODO OSSL_CMP_info("revocation accepted (PKIStatus=accepted)");*/
        result = ctx->oldCert;
        break;
    case OSSL_CMP_PKISTATUS_waiting:
    case OSSL_CMP_PKISTATUS_keyUpdateWarning:
        CMPerr(0, CMP_R_UNEXPECTED_PKISTATUS);
        goto err;
    default:
        CMPerr(0, CMP_R_UNKNOWN_PKISTATUS);
        goto err;
    }

    /* check any present CertId in optional revCerts field */
    if (rrep->revCerts != NULL) {
        OSSL_CRMF_CERTID *cid;
        OSSL_CRMF_CERTTEMPLATE *tmpl =
            sk_OSSL_CMP_REVDETAILS_value(rr->body->value.rr, rsid)->certDetails;
        X509_NAME *issuer = OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl);
        ASN1_INTEGER *serial = OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl);

        if (sk_OSSL_CRMF_CERTID_num(rrep->revCerts) != num_RevDetails) {
            CMPerr(0, CMP_R_WRONG_RP_COMPONENT_COUNT);
            result = NULL;
            goto err;
        }
        if ((cid = ossl_cmp_revrepcontent_get_CertId(rrep, rsid)) == NULL) {
            result = NULL;
            goto err;
        }
        if (X509_NAME_cmp(issuer, OSSL_CRMF_CERTID_get0_issuer(cid)) != 0
            || ASN1_INTEGER_cmp(serial,
                                OSSL_CRMF_CERTID_get0_serialNumber(cid)) != 0) {
            CMPerr(0, CMP_R_WRONG_CERTID_IN_RP);
            result = NULL;
            goto err;
        }
    }

    /* check number of any optionally present crls */
    if (rrep->crls != NULL && sk_X509_CRL_num(rrep->crls) != num_RevDetails) {
        CMPerr(0, CMP_R_WRONG_RP_COMPONENT_COUNT);
        result = NULL;
        goto err;
    }

 err:
    /* print out OpenSSL and CMP errors via the log callback or OSSL_CMP_puts */
    if (result == NULL) {
        if ((buf = OPENSSL_malloc(OSSL_CMP_PKISI_BUFLEN)) != NULL
                && OSSL_CMP_CTX_snprint_PKIStatus(ctx, buf,
                                                  OSSL_CMP_PKISI_BUFLEN) != NULL)
            ERR_add_error_data(1, buf);
        OPENSSL_free(buf);
    }

 end:
    OSSL_CMP_MSG_free(rr);
    OSSL_CMP_MSG_free(rp);
    return result;
}

X509 *OSSL_CMP_exec_IR_ses(OSSL_CMP_CTX *ctx)
{
    return do_certreq_seq(ctx, OSSL_CMP_PKIBODY_IR,
                          CMP_R_ERROR_CREATING_IR, OSSL_CMP_PKIBODY_IP,
                          CMP_R_IP_NOT_RECEIVED);
}

X509 *OSSL_CMP_exec_CR_ses(OSSL_CMP_CTX *ctx)
{
    return do_certreq_seq(ctx, OSSL_CMP_PKIBODY_CR,
                          CMP_R_ERROR_CREATING_CR, OSSL_CMP_PKIBODY_CP,
                          CMP_R_CP_NOT_RECEIVED);
}

X509 *OSSL_CMP_exec_KUR_ses(OSSL_CMP_CTX *ctx)
{
    return do_certreq_seq(ctx, OSSL_CMP_PKIBODY_KUR,
                          CMP_R_ERROR_CREATING_KUR, OSSL_CMP_PKIBODY_KUP,
                          CMP_R_KUP_NOT_RECEIVED);
}

X509 *OSSL_CMP_exec_P10CR_ses(OSSL_CMP_CTX *ctx)
{
    return do_certreq_seq(ctx, OSSL_CMP_PKIBODY_P10CR,
                          CMP_R_ERROR_CREATING_P10CR, OSSL_CMP_PKIBODY_CP,
                          CMP_R_CP_NOT_RECEIVED);
}

/*
 * Send a general message to the server to request information specified in the
 * InfoType and Value (itav) given in the ctx->genm_itavs, see section 5.3.19
 * and E.5.
 *
 * returns pointer to stack of ITAVs received in the answer or NULL on error
 */
STACK_OF(OSSL_CMP_ITAV) *OSSL_CMP_exec_GENM_ses(OSSL_CMP_CTX *ctx)
{
    OSSL_CMP_MSG *genm = NULL;
    OSSL_CMP_MSG *genp = NULL;
    STACK_OF(OSSL_CMP_ITAV) *rcvd_itavs = NULL;

    if ((genm = ossl_cmp_genm_new(ctx)) == NULL)
        goto err;

    INFO_CONTACTING_SERVER(ctx);
    if (!send_receive_check(ctx, genm, &genp, OSSL_CMP_PKIBODY_GENP,
                            CMP_R_GENP_NOT_RECEIVED))
        goto err;

    /* received stack of itavs not to be freed with the genp */
    rcvd_itavs = genp->body->value.genp;
    genp->body->value.genp = NULL;

 err:
    OSSL_CMP_MSG_free(genm);
    OSSL_CMP_MSG_free(genp);

    return rcvd_itavs; /* recv_itavs == NULL indicates an error */
}
