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

/* general CMP server functions */

#include <openssl/asn1t.h>

#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <openssl/cmp.h>
#include <openssl/err.h>

/* the context for the generic CMP server */
struct ossl_cmp_srv_ctx_st
{
    OSSL_CMP_CTX *ctx; /* Client CMP context, partly reused for srv */
    void *custom_ctx;  /* pointer to specific server context */

    OSSL_CMP_SRV_cert_request_cb_t process_cert_request;
    OSSL_CMP_SRV_rr_cb_t process_rr;
    OSSL_CMP_SRV_genm_cb_t process_genm;
    OSSL_CMP_SRV_error_cb_t process_error;
    OSSL_CMP_SRV_certConf_cb_t process_certConf;
    OSSL_CMP_SRV_pollReq_cb_t process_pollReq;

    int sendUnprotectedErrors; /* Send error and rejection msgs unprotected */
    int acceptUnprotected;     /* Accept requests with no/invalid prot. */
    int acceptRAVerified;      /* Accept ir/cr/kur with POPO RAVerified */
    int grantImplicitConfirm;  /* Grant implicit confirmation if requested */

}; /* OSSL_CMP_SRV_CTX */

void OSSL_CMP_SRV_CTX_free(OSSL_CMP_SRV_CTX *srv_ctx)
{
    if (srv_ctx == NULL)
        return;

    OSSL_CMP_CTX_free(srv_ctx->ctx);
    OPENSSL_free(srv_ctx);
}

OSSL_CMP_SRV_CTX *OSSL_CMP_SRV_CTX_new(void)
{
    OSSL_CMP_SRV_CTX *ctx = OPENSSL_zalloc(sizeof(OSSL_CMP_SRV_CTX));

    if (ctx == NULL)
        goto err;

    if ((ctx->ctx = OSSL_CMP_CTX_new()) == NULL)
        goto err;

    /* all other elements are initialized to 0 or NULL, respectively */
    return ctx;
 err:
    OSSL_CMP_SRV_CTX_free(ctx);
    return NULL;
}

int OSSL_CMP_SRV_CTX_init(OSSL_CMP_SRV_CTX *srv_ctx, void *custom_ctx,
                          OSSL_CMP_SRV_cert_request_cb_t process_cert_request,
                          OSSL_CMP_SRV_rr_cb_t process_rr,
                          OSSL_CMP_SRV_genm_cb_t process_genm,
                          OSSL_CMP_SRV_error_cb_t process_error,
                          OSSL_CMP_SRV_certConf_cb_t process_certConf,
                          OSSL_CMP_SRV_pollReq_cb_t process_pollReq)
{
    if (srv_ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    srv_ctx->custom_ctx = custom_ctx;
    srv_ctx->process_cert_request = process_cert_request;
    srv_ctx->process_rr = process_rr;
    srv_ctx->process_genm = process_genm;
    srv_ctx->process_error = process_error;
    srv_ctx->process_certConf = process_certConf;
    srv_ctx->process_pollReq = process_pollReq;
    return 1;
}

OSSL_CMP_CTX *OSSL_CMP_SRV_CTX_get0_cmp_ctx(const OSSL_CMP_SRV_CTX *srv_ctx)
{
    if (srv_ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return srv_ctx->ctx;
}

void *OSSL_CMP_SRV_CTX_get0_custom_ctx(const OSSL_CMP_SRV_CTX *srv_ctx)
{
    if (srv_ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    return srv_ctx->custom_ctx;
}

int OSSL_CMP_SRV_CTX_set_send_unprotected_errors(OSSL_CMP_SRV_CTX *srv_ctx,
                                                 int val)
{
    if (srv_ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    srv_ctx->sendUnprotectedErrors = val != 0;
    return 1;
}

int OSSL_CMP_SRV_CTX_set_accept_unprotected(OSSL_CMP_SRV_CTX *srv_ctx, int val)
{
    if (srv_ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    srv_ctx->acceptUnprotected = val != 0;
    return 1;
}

int OSSL_CMP_SRV_CTX_set_accept_raverified(OSSL_CMP_SRV_CTX *srv_ctx, int val)
{
    if (srv_ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    srv_ctx->acceptRAVerified = val != 0;
    return 1;
}

int OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(OSSL_CMP_SRV_CTX *srv_ctx,
                                                int val)
{
    if (srv_ctx == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    srv_ctx->grantImplicitConfirm = val != 0;
    return 1;
}

/*
 * Processes an ir/cr/p10cr/kur and returns a certification response.
 * Only handles the first certification request contained in req
 * returns an ip/cp/kup on success and NULL on error
 */
static OSSL_CMP_MSG *process_cert_request(OSSL_CMP_SRV_CTX *srv_ctx,
                                          const OSSL_CMP_MSG *req)
{
    OSSL_CMP_MSG *msg = NULL;
    OSSL_CMP_PKISI *si = NULL;
    X509 *certOut = NULL;
    STACK_OF(X509) *chainOut = NULL, *caPubs = NULL;
    OSSL_CRMF_MSG *crm = NULL;
    int bodytype;
    int certReqId;

    if (!ossl_assert(srv_ctx != NULL && req != NULL))
        return NULL;

    switch (ossl_cmp_msg_get_bodytype(req)) {
    case OSSL_CMP_PKIBODY_P10CR:
    case OSSL_CMP_PKIBODY_CR:
        bodytype = OSSL_CMP_PKIBODY_CP;
        break;
    case OSSL_CMP_PKIBODY_IR:
        bodytype = OSSL_CMP_PKIBODY_IP;
        break;
    case OSSL_CMP_PKIBODY_KUR:
        bodytype = OSSL_CMP_PKIBODY_KUP;
        break;
    default:
        CMPerr(0, CMP_R_UNEXPECTED_PKIBODY);
        return NULL;
    }

    if (ossl_cmp_msg_get_bodytype(req) == OSSL_CMP_PKIBODY_P10CR) {
        certReqId = OSSL_CMP_CERTREQID;
    } else {
        OSSL_CRMF_MSGS *reqs = req->body->value.ir; /* same for cr and kur */

        /*
         * TODO: handle multiple elements, in case multiple requests have
         * been sent - see https://github.com/mpeylo/cmpossl/issues/67
         */
        if (sk_OSSL_CRMF_MSG_num(reqs) != 1) {
            CMPerr(0, CMP_R_MULTIPLE_REQUESTS_NOT_SUPPORTED);
            return NULL;
        }

        if ((crm = sk_OSSL_CRMF_MSG_value(reqs, OSSL_CMP_CERTREQID)) == NULL) {
            CMPerr(0, CMP_R_CERTREQMSG_NOT_FOUND);
            return NULL;
        }
        certReqId = OSSL_CRMF_MSG_get_certReqId(crm);
    }

    if (!ossl_cmp_verify_popo(req, srv_ctx->acceptRAVerified)) {
        /* Proof of possession could not be verified */
        if ((si = OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection,
                                          1 << OSSL_CMP_PKIFAILUREINFO_badPOP,
                                          NULL)) == NULL)
            return NULL;
    } else {
        si = srv_ctx->process_cert_request(srv_ctx, req, certReqId,
                                           &certOut, &chainOut, &caPubs);
        if (si == NULL)
            goto err;
        if (certOut != NULL)
            OSSL_CMP_CTX_set_option(srv_ctx->ctx, OSSL_CMP_OPT_IMPLICITCONFIRM,
                                    ossl_cmp_hdr_has_implicitConfirm(req->
                                                                     header)
                                        && srv_ctx->grantImplicitConfirm);
    }

    msg = ossl_cmp_certRep_new(srv_ctx->ctx, bodytype, certReqId, si,
                               certOut, chainOut, caPubs, 0 /* encrypted */,
                               srv_ctx->sendUnprotectedErrors);
    /*
     * TODO when implemented in ossl_cmp_certrep_new():
     * in case OSSL_CRMF_POPO_KEYENC, set encrypted
     */
    if (msg == NULL)
        CMPerr(0, CMP_R_ERROR_CREATING_CERTREP);

 err:
    OSSL_CMP_PKISI_free(si);
    X509_free(certOut);
    sk_X509_pop_free(chainOut, X509_free);
    sk_X509_pop_free(caPubs, X509_free);
    return msg;
}

static OSSL_CMP_MSG *process_rr(OSSL_CMP_SRV_CTX *srv_ctx,
                                const OSSL_CMP_MSG *req)
{
    OSSL_CMP_MSG *msg = NULL;
    OSSL_CMP_REVDETAILS *details;
    OSSL_CRMF_CERTID *certId;
    OSSL_CRMF_CERTTEMPLATE *tmpl;
    X509_NAME *issuer;
    ASN1_INTEGER *serial;
    OSSL_CMP_PKISI *si;

    if (!ossl_assert(srv_ctx != NULL && req != NULL))
        return NULL;

    /*
     * TODO: handle multiple elements, in case multiple requests have
     * been sent - see https://github.com/mpeylo/cmpossl/issues/67
     */
    if (sk_OSSL_CMP_REVDETAILS_num(req->body->value.rr) != 1) {
        CMPerr(0, CMP_R_MULTIPLE_REQUESTS_NOT_SUPPORTED);
        return NULL;
    }

    if ((details = sk_OSSL_CMP_REVDETAILS_value(req->body->value.rr,
                                                OSSL_CMP_REVREQSID)) == NULL) {
        CMPerr(0, CMP_R_ERROR_PROCESSING_MSG);
        return NULL;
    }

    tmpl = details->certDetails;
    issuer = OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl);
    serial = OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl);
    if ((certId = OSSL_CRMF_CERTID_gen(issuer, serial)) == NULL)
        return NULL;
    if ((si = srv_ctx->process_rr(srv_ctx, req, issuer, serial)) == NULL) {
        CMPerr(0, CMP_R_REQUEST_NOT_ACCEPTED);
        goto err;
    }

    if ((msg = ossl_cmp_rp_new(srv_ctx->ctx, si, certId,
                               srv_ctx->sendUnprotectedErrors)) == NULL)
        CMPerr(0, CMP_R_ERROR_CREATING_RR);

 err:
    OSSL_CRMF_CERTID_free(certId);
    OSSL_CMP_PKISI_free(si);
    return msg;
}

/*
 * Processes genm and creates a genp message mirroring the contents of the
 * incoming message
 */
static OSSL_CMP_MSG *process_genm(OSSL_CMP_SRV_CTX *srv_ctx,
                                  const OSSL_CMP_MSG *req)
{
    OSSL_CMP_GENMSGCONTENT *itavs;

    if (!ossl_assert(srv_ctx != NULL && srv_ctx->ctx != NULL && req != NULL))
        return NULL;

    if (!srv_ctx->process_genm(srv_ctx, req, req->body->value.genm, &itavs))
        return NULL;
    return ossl_cmp_genp_new(srv_ctx->ctx, itavs);
}

static OSSL_CMP_MSG *process_error(OSSL_CMP_SRV_CTX *srv_ctx,
                                   const OSSL_CMP_MSG *req)
{
    OSSL_CMP_ERRORMSGCONTENT *errorContent = req->body->value.error;
    OSSL_CMP_MSG *msg = ossl_cmp_pkiconf_new(srv_ctx->ctx);

    srv_ctx->process_error(srv_ctx, req, errorContent->pKIStatusInfo,
                           errorContent->errorCode, errorContent->errorDetails);

    if (msg == NULL)
        CMPerr(0, CMP_R_ERROR_CREATING_PKICONF);
    return msg;
}

static OSSL_CMP_MSG *process_certConf(OSSL_CMP_SRV_CTX *srv_ctx,
                                      const OSSL_CMP_MSG *req)
{
    OSSL_CMP_CTX *ctx = srv_ctx->ctx;
    OSSL_CMP_CERTCONFIRMCONTENT *ccc = req->body->value.certConf;
    int num = sk_OSSL_CMP_CERTSTATUS_num(ccc);
    OSSL_CMP_MSG *msg = NULL;
    OSSL_CMP_CERTSTATUS *status = NULL;

    if (num == 0) {
        OSSL_CMP_err(ctx, "certificate rejected by client");
    } else {
        if (num > 1)
            OSSL_CMP_warn(ctx, "All CertStatus but the first will be ignored");
        status = sk_OSSL_CMP_CERTSTATUS_value(ccc, OSSL_CMP_CERTREQID);
    }

    if (status != NULL) {
        int certReqId = ossl_cmp_asn1_get_int(status->certReqId);
        ASN1_OCTET_STRING *certHash = status->certHash;
        OSSL_CMP_PKISI *si = status->statusInfo;

        if (!srv_ctx->process_certConf(srv_ctx, req, certReqId, certHash))
            return NULL;

        if (si != NULL && ossl_cmp_pkisi_get_status(si)
            != OSSL_CMP_PKISTATUS_accepted) {
            int pki_status = ossl_cmp_pkisi_get_status(si);
            const char *str = ossl_cmp_PKIStatus_to_string(pki_status);

            OSSL_CMP_log2(INFO, ctx, "certificate rejected by client %s %s",
                          str == NULL ? "without" : "with",
                          str == NULL ? "PKIStatus" : str);
        }
    }

    if ((msg = ossl_cmp_pkiconf_new(ctx)) == NULL)
        CMPerr(0, CMP_R_ERROR_CREATING_PKICONF);
    return msg;
}

static OSSL_CMP_MSG *process_pollReq(OSSL_CMP_SRV_CTX *srv_ctx,
                                     const OSSL_CMP_MSG *req)
{
    OSSL_CMP_POLLREQCONTENT *prc;
    OSSL_CMP_POLLREQ *pr;
    int certReqId;
    OSSL_CMP_MSG *certReq;
    int64_t check_after = 0;
    OSSL_CMP_MSG *msg = NULL;

    if (!ossl_assert(srv_ctx != NULL))
        return NULL;

    prc = req->body->value.pollReq;
    /*
     * TODO: handle multiple elements, in case multiple requests have
     * been sent - see https://github.com/mpeylo/cmpossl/issues/67
     */
    if (sk_OSSL_CMP_POLLREQ_num(prc) != 1) {
        CMPerr(0, CMP_R_MULTIPLE_REQUESTS_NOT_SUPPORTED);
        return NULL;
    }

    pr = sk_OSSL_CMP_POLLREQ_value(prc, 0);
    certReqId = ossl_cmp_asn1_get_int(pr->certReqId);
    if (!srv_ctx->process_pollReq(srv_ctx, req, certReqId,
                                  &certReq, &check_after))
        return NULL;

    if (certReq != NULL) {
        if ((msg = process_cert_request(srv_ctx, certReq)) == NULL)
            CMPerr(0, CMP_R_ERROR_PROCESSING_CERTREQ);
    } else {
        if ((msg = ossl_cmp_pollRep_new(srv_ctx->ctx, certReqId,
                                        check_after)) == NULL)
            CMPerr(0, CMP_R_ERROR_CREATING_POLLREP);
    }
    return msg;
}

/*
 * Determines whether missing protection is allowed
 */
static int unprotected_exception(const OSSL_CMP_CTX *ctx,
                                 const OSSL_CMP_MSG *req,
                                 int invalid_protection,
                                 int accept_unprotected_requests)
{
    if (accept_unprotected_requests) {
        OSSL_CMP_log1(WARN, ctx, "ignoring %s protection of request message",
                      invalid_protection ? "invalid" : "missing");
        return 1;
    }
    if (ossl_cmp_msg_get_bodytype(req) == OSSL_CMP_PKIBODY_ERROR
        && OSSL_CMP_CTX_get_option(ctx, OSSL_CMP_OPT_UNPROTECTED_ERRORS) == 1) {
        OSSL_CMP_warn(ctx, "ignoring missing protection of error message");
        return 1;
    }
    return 0;
}

/*
 * returns 1 if a message was created and 0 on internal error
 */
int OSSL_CMP_SRV_process_request(OSSL_CMP_SRV_CTX *srv_ctx,
                                 const OSSL_CMP_MSG *req,
                                 OSSL_CMP_MSG **rsp)
{
    GENERAL_NAME *sender;
    OSSL_CMP_CTX *ctx;

    if (rsp != NULL)
        *rsp = NULL;
    if (srv_ctx == NULL || srv_ctx->ctx == NULL || req == NULL || rsp == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx = srv_ctx->ctx;

    sender = OSSL_CMP_MSG_get0_header(req)->sender;
    if (sender->type != GEN_DIRNAME) {
        CMPerr(0, CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED);
        goto err;
    }
    if (!OSSL_CMP_CTX_set1_recipient(ctx, sender->d.directoryName))
        goto err;
    if (req->body != NULL)
        switch (req->body->type) {
        case OSSL_CMP_PKIBODY_IR:
        case OSSL_CMP_PKIBODY_CR:
        case OSSL_CMP_PKIBODY_KUR:
        case OSSL_CMP_PKIBODY_P10CR:
        case OSSL_CMP_PKIBODY_RR:
            /*
             * looks like a start of a new transaction,
             * clear last transactionID and senderNonce
             */
            if (!OSSL_CMP_CTX_set1_transactionID(ctx, NULL)
                    || !OSSL_CMP_CTX_set1_senderNonce(ctx, NULL))
                goto err;
            break;
        default: ; /* transactionID should be already initialized */
        }
    if (ossl_cmp_msg_check_received(ctx, req, unprotected_exception,
                                    srv_ctx->acceptUnprotected) < 0)
        goto err;

    switch (ossl_cmp_msg_get_bodytype(req)) {
    case OSSL_CMP_PKIBODY_IR:
    case OSSL_CMP_PKIBODY_CR:
    case OSSL_CMP_PKIBODY_P10CR:
    case OSSL_CMP_PKIBODY_KUR:
        if (srv_ctx->process_cert_request == NULL)
            CMPerr(0, CMP_R_UNEXPECTED_PKIBODY);
        else
            *rsp = process_cert_request(srv_ctx, req);
        break;
    case OSSL_CMP_PKIBODY_RR:
        if (srv_ctx->process_rr == NULL)
            CMPerr(0, CMP_R_UNEXPECTED_PKIBODY);
        else
            *rsp = process_rr(srv_ctx, req);
        break;
    case OSSL_CMP_PKIBODY_GENM:
        if (srv_ctx->process_genm == NULL)
            CMPerr(0, CMP_R_UNEXPECTED_PKIBODY);
        else
            *rsp = process_genm(srv_ctx, req);
        break;
    case OSSL_CMP_PKIBODY_ERROR:
        if (srv_ctx->process_error == NULL)
            CMPerr(0, CMP_R_UNEXPECTED_PKIBODY);
        else
            *rsp = process_error(srv_ctx, req);
        break;
    case OSSL_CMP_PKIBODY_CERTCONF:
        if (srv_ctx->process_certConf == NULL)
            CMPerr(0, CMP_R_UNEXPECTED_PKIBODY);
        else
            *rsp = process_certConf(srv_ctx, req);
        break;
    case OSSL_CMP_PKIBODY_POLLREQ:
        if (srv_ctx->process_pollReq == NULL)
            CMPerr(0, CMP_R_UNEXPECTED_PKIBODY);
        else
            *rsp = process_pollReq(srv_ctx, req);
        break;
    default:
        CMPerr(0, CMP_R_UNEXPECTED_PKIBODY);
    }

 err:
    if (*rsp == NULL) {
        /* on error, try to respond with CMP error message to client */
        const char *data;
        int flags = 0;
        unsigned long err = ERR_peek_error_data(&data, &flags);
        int fail_info = 1 << OSSL_CMP_PKIFAILUREINFO_badRequest;
        /* TODO fail_info could be more specific */
        OSSL_CMP_PKISI *si = NULL;

        if ((si = OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection,
                                          fail_info, NULL)) == NULL)
            return 0;
        if (err == 0 || (flags & ERR_TXT_STRING) == 0)
            data = NULL;
        *rsp = ossl_cmp_error_new(srv_ctx->ctx, si,
                                  err != 0 ? ERR_GET_REASON(err) : -1,
                                  data, srv_ctx->sendUnprotectedErrors);
        OSSL_CMP_PKISI_free(si);
    }
    return *rsp != NULL;
}

/*
 * Server interface that may substitute OSSL_CMP_MSG_http_perform at the client.
 * The OSSL_CMP_SRV_CTX must be set as client_ctx->transfer_cb_arg.
 * returns 1 on success, else 0 and pushes an element on the error stack.
 */
int OSSL_CMP_CTX_server_perform(OSSL_CMP_CTX *client_ctx,
                                const OSSL_CMP_MSG *req,
                                OSSL_CMP_MSG **rsp)
{
    OSSL_CMP_SRV_CTX *srv_ctx = NULL;

    if (client_ctx == NULL || req == NULL || rsp == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    if ((srv_ctx = OSSL_CMP_CTX_get_transfer_cb_arg(client_ctx)) == NULL) {
        CMPerr(0, CMP_R_ERROR_TRANSFERRING_OUT);
        return 0;
    }

    return OSSL_CMP_SRV_process_request(srv_ctx, req, rsp);
}
