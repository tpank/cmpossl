/*
 * Copyright 2004-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/* =============================================================================
 * crypto/cmp/cmp_srv.c
 * CMP (RFC 4210) server functions for OpenSSL
 * Initial version by Tobias Pankert at Siemens AG.
 */

#include <openssl/cmp.h>
#include "cmp_int.h"
#include "../crmf/crmf_int.h"
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>
#ifndef NDEBUG

typedef CMP_PKIMESSAGE *(*cmp_srv_process_cb_t)
 (CMP_SRV_CTX *ctx, const CMP_PKIMESSAGE *msg);

/*
 * this structure is used to store the context for the CMP mock server
 * partly using OpenSSL ASN.1 types in order to ease handling it - such ASN.1
 * entries must be given first, in same order as ASN1_SEQUENCE(CMP_SRV_CTX)
 */
struct cmp_srv_ctx_st {
    X509 *certOut;              /* Certificate to be returned in cp/ip/kup */
    STACK_OF(X509) *chainOut;   /* Cert chain useful to validate certOut */
    STACK_OF(X509) *caPubsOut;  /* caPubs for ip */
    CMP_PKISTATUSINFO *pkiStatusOut; /* PKI Status Info to be returned */
    CMP_PKIMESSAGE *certReq;    /* ir/cr/p10cr/kur saved in case of polling */
    int certReqId;              /* id saved in case of polling */
    CMP_CTX *ctx;               /* client cmp context, partly reused for srv */
    unsigned int pollCount;     /* Number of polls before cert response */
    long checkAfterTime;        /* time to wait for the next poll in seconds */
    int grantImplicitConfirm;   /* Grant implicit confirmation if requested */
    int sendError;              /* Always send error if true */
    int sendUnprotectedErrors;  /* Send error and rejection msgs uprotected */
    int acceptUnprotectedRequests; /* Accept unprotected request messages */
    int acceptRAVerified;       /* Accept ir/cr/kur with POPO RAVerified */
    int encryptcert;            /* Encrypt certs in cert response message */
    /* callbacks for message processing */
    cmp_srv_process_cb_t process_ir_cb;
    cmp_srv_process_cb_t process_cr_cb;
    cmp_srv_process_cb_t process_p10cr_cb;
    cmp_srv_process_cb_t process_kur_cb;
    cmp_srv_process_cb_t process_rr_cb;
    cmp_srv_process_cb_t process_certconf_cb;
    cmp_srv_process_cb_t process_error_cb;
    cmp_srv_process_cb_t process_pollreq_cb;
    cmp_srv_process_cb_t process_genm_cb;

} /* CMP_SRV_CTX */ ;

ASN1_SEQUENCE(CMP_SRV_CTX) = {
    ASN1_OPT(CMP_SRV_CTX, certOut, X509),
        ASN1_SEQUENCE_OF_OPT(CMP_SRV_CTX, chainOut, X509),
        ASN1_SEQUENCE_OF_OPT(CMP_SRV_CTX, caPubsOut, X509),
        ASN1_SIMPLE(CMP_SRV_CTX, pkiStatusOut, CMP_PKISTATUSINFO),
        ASN1_OPT(CMP_SRV_CTX, certReq, CMP_PKIMESSAGE)
} ASN1_SEQUENCE_END(CMP_SRV_CTX)
IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(CMP_SRV_CTX)

void CMP_SRV_CTX_delete(CMP_SRV_CTX *srv_ctx)
{
    if (srv_ctx == NULL)
        return;
    CMP_CTX_delete(srv_ctx->ctx);
    srv_ctx->ctx = NULL;
    CMP_SRV_CTX_free(srv_ctx);
}

CMP_CTX *CMP_SRV_CTX_get0_ctx(CMP_SRV_CTX *srv_ctx)
{
    if (srv_ctx == NULL)
        return NULL;
    return srv_ctx->ctx;
}

int CMP_SRV_CTX_set_grant_implicit_confirm(CMP_SRV_CTX *srv_ctx, int value)
{
    if (srv_ctx == NULL)
        return 0;
    srv_ctx->grantImplicitConfirm = value ? 1 : 0;
    return 1;
}

int CMP_SRV_CTX_set_accept_unprotected(CMP_SRV_CTX *srv_ctx, int value)
{
    if (srv_ctx == NULL)
        return 0;
    srv_ctx->acceptUnprotectedRequests = value ? 1 : 0;
    return 1;
}

int CMP_SRV_CTX_set_send_unprotected_errors(CMP_SRV_CTX *srv_ctx, int value)
{
    if (srv_ctx == NULL)
        return 0;
    srv_ctx->sendUnprotectedErrors = value ? 1 : 0;
    return 1;
}

int CMP_SRV_CTX_set_statusInfo(CMP_SRV_CTX *srv_ctx, int status,
                               unsigned long failInfo, const char *text)
{
    if (srv_ctx == NULL)
        return 0;
    CMP_PKISTATUSINFO_free(srv_ctx->pkiStatusOut);
    return (srv_ctx->pkiStatusOut = CMP_statusInfo_new(status, failInfo, text))
        != NULL;
}

int CMP_SRV_CTX_set1_certOut(CMP_SRV_CTX *srv_ctx, X509 *cert)
{
    if (srv_ctx == NULL)
        return 0;
    X509_free(srv_ctx->certOut);
    if (X509_up_ref(cert)) {
        srv_ctx->certOut = cert;
        return 1;
    }
    srv_ctx->certOut = NULL;
    return 0;
}

int CMP_SRV_CTX_set1_chainOut(CMP_SRV_CTX *srv_ctx, STACK_OF(X509) *chain)
{
    if (srv_ctx == NULL || chain == NULL)
        return 0;
    sk_X509_pop_free(srv_ctx->chainOut, X509_free);
    return (srv_ctx->chainOut = X509_chain_up_ref(chain)) != NULL;
}

int CMP_SRV_CTX_set1_caPubsOut(CMP_SRV_CTX *srv_ctx, STACK_OF(X509) *caPubs)
{
    if (srv_ctx == NULL || caPubs == NULL)
        return 0;
    sk_X509_pop_free(srv_ctx->caPubsOut, X509_free);
    return (srv_ctx->caPubsOut = X509_chain_up_ref(caPubs)) != NULL;
}

int CMP_SRV_CTX_set_send_error(CMP_SRV_CTX *srv_ctx, int error)
{
    if (srv_ctx == NULL)
        return 0;
    srv_ctx->sendError = error ? 1 : 0;
    return 1;
}

int CMP_SRV_CTX_set_checkAfterTime(CMP_SRV_CTX *srv_ctx, long time)
{
    if (srv_ctx == NULL)
        return 0;
    srv_ctx->checkAfterTime = time;
    return 1;
}

int CMP_SRV_CTX_set_pollCount(CMP_SRV_CTX *srv_ctx, int count)
{
    if (srv_ctx == NULL || count < 0)
        return 0;
    srv_ctx->pollCount = count;
    return 1;
}

int CMP_SRV_CTX_set_accept_raverified(CMP_SRV_CTX *srv_ctx, int raverified)
{
    if (srv_ctx == NULL)
        return 0;
    srv_ctx->acceptRAVerified = raverified ? 1 : 0;
    return 1;
}

/*
 * Creates a pkiconf message.
 */
static CMP_PKIMESSAGE *CMP_pkiconf_new(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *msg = CMP_PKIMESSAGE_create(ctx, V_CMP_PKIBODY_PKICONF);

    if (msg == NULL)
        goto err;
    if (CMP_PKIMESSAGE_protect(ctx, msg))
        return msg;
 err:
    CMPerr(CMP_F_CMP_PKICONF_NEW, CMP_R_ERROR_CREATING_PKICONF);
    CMP_PKIMESSAGE_free(msg);
    return NULL;
}

/* TODO start: later move these _new functions to cmp_msg.c */
/*
 * Creates a revocation response message to a given revocation request.
 * Only handles the first given request. Consumes certId.
 */
static CMP_PKIMESSAGE *CMP_rp_new(CMP_CTX *ctx, CMP_PKISTATUSINFO *si,
                                  CRMF_CERTID *certId, int unprotectedErrors)
{
    CMP_REVREPCONTENT *rep = NULL;
    CMP_PKISTATUSINFO *si1 = NULL;
    CMP_PKIMESSAGE *msg = NULL;

    if ((msg = CMP_PKIMESSAGE_create(ctx, V_CMP_PKIBODY_RP)) == NULL)
        goto oom;
    rep = msg->body->value.rp;

    if ((si1 = CMP_PKISTATUSINFO_dup(si)) == NULL)
        goto oom;
    sk_CMP_PKISTATUSINFO_push(rep->status, si1);

    if ((rep->certId = sk_CRMF_CERTID_new_null()) == NULL)
        goto oom;
    sk_CRMF_CERTID_push(rep->certId, certId);
    certId = NULL;

    if (!(unprotectedErrors &&
          CMP_PKISTATUSINFO_PKIStatus_get(si) == CMP_PKISTATUS_rejection) &&
        !CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;
    return msg;

 oom:
    CMPerr(CMP_F_CMP_RP_NEW, CMP_R_OUT_OF_MEMORY);
 err:
    CMPerr(CMP_F_CMP_RP_NEW, CMP_R_ERROR_CREATING_RP);
    CRMF_CERTID_free(certId);
    CMP_PKIMESSAGE_free(msg);
    return NULL;
}

/*
 * Create certificate response PKIMessage for IP/CP/KUP
 * returns a pointer to the PKIMessage on success, NULL on error
 */
static CMP_PKIMESSAGE *CMP_certrep_new(CMP_CTX *ctx, int bodytype,
                                       int certReqId, CMP_PKISTATUSINFO *si,
                                       X509 *cert, STACK_OF(X509) *chain,
                                       STACK_OF(X509) *caPubs, int encrypted,
                                       int unprotectedErrors)
{
    CMP_PKIMESSAGE *msg = NULL;
    CMP_CERTREPMESSAGE *repMsg = NULL;
    CMP_CERTRESPONSE *resp = NULL;
    int status = -1;

    if (ctx == NULL || si == NULL) {
        CMPerr(CMP_F_CMP_CERTREP_NEW, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    if ((msg = CMP_PKIMESSAGE_create(ctx, bodytype)) == NULL)
        goto oom;
    repMsg = msg->body->value.ip; /* value.ip is same for cp and kup */

    /* header */
    if (ctx->implicitConfirm && !CMP_PKIMESSAGE_set_implicitConfirm(msg))
        goto oom;

    /* body */
    if ((resp = CMP_CERTRESPONSE_new()) == NULL)
        goto oom;
    CMP_PKISTATUSINFO_free(resp->status);
    if ((resp->status = CMP_PKISTATUSINFO_dup(si)) == NULL ||
        !ASN1_INTEGER_set(resp->certReqId, certReqId)) {
        goto oom;
    }

    status = CMP_PKISTATUSINFO_PKIStatus_get(resp->status);
    if (status != CMP_PKISTATUS_rejection &&
        status != CMP_PKISTATUS_waiting && cert != NULL) {
        if (encrypted) {
            CMPerr(CMP_F_CMP_CERTREP_NEW, CMP_R_INVALID_PARAMETERS);
            /*TODO implement (not urgent) */
            goto err;
        } else {
            if ((resp->certifiedKeyPair = CMP_CERTIFIEDKEYPAIR_new()) == NULL)
                goto oom;
            resp->certifiedKeyPair->certOrEncCert->type =
                CMP_CERTORENCCERT_CERTIFICATE;
            if (!X509_up_ref(cert))
                goto err;
            resp->certifiedKeyPair->certOrEncCert->value.certificate = cert;
        }
    }

    if (!sk_CMP_CERTRESPONSE_push(repMsg->response, resp))
        goto oom;
    resp = NULL;
    /* TODO: here optional 2nd certrep could be pushed to the stack */

    if (bodytype == V_CMP_PKIBODY_IP && caPubs &&
        (repMsg->caPubs = X509_chain_up_ref(caPubs)) == NULL)
        goto oom;
    if (chain && !CMP_sk_X509_add1_certs(msg->extraCerts, chain, 0, 1))
        goto oom;

    if (!(unprotectedErrors &&
          CMP_PKISTATUSINFO_PKIStatus_get(si) == CMP_PKISTATUS_rejection) &&
        !CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;

    return msg;

 oom:
    CMPerr(CMP_F_CMP_CERTREP_NEW, CMP_R_OUT_OF_MEMORY);
 err:
    CMPerr(CMP_F_CMP_CERTREP_NEW, CMP_R_ERROR_CREATING_CERTREP);
    CMP_CERTRESPONSE_free(resp);
    CMP_PKIMESSAGE_free(msg);
    return NULL;
}

/*
 * Creates a new poll response message for the given request id
 * returns a poll response on success and NULL on error
 */
static CMP_PKIMESSAGE *CMP_pollrep_new(CMP_CTX *ctx, long certReqId,
                                       long pollAfter)
{
    CMP_PKIMESSAGE *msg;
    CMP_POLLREP *pollRep;

    if (ctx == NULL) {
        CMPerr(CMP_F_CMP_POLLREP_NEW, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    if ((msg = CMP_PKIMESSAGE_create(ctx, V_CMP_PKIBODY_POLLREP)) == NULL)
        goto err;
    if ((pollRep = CMP_POLLREP_new()) == NULL)
        goto err;
    sk_CMP_POLLREP_push(msg->body->value.pollRep, pollRep);
    ASN1_INTEGER_set(pollRep->certReqId, certReqId);
    ASN1_INTEGER_set(pollRep->checkAfter, pollAfter);

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;
    return msg;

 err:
    CMPerr(CMP_F_CMP_POLLREP_NEW, CMP_R_ERROR_CREATING_POLLREP);
    CMP_PKIMESSAGE_free(msg);
    return NULL;
}

/* TODO is nearly identical to CMP_genm_new in cmp_msg.c */
static CMP_PKIMESSAGE *CMP_genp_new(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *msg = NULL;

    if (ctx == NULL) {
        CMPerr(CMP_F_CMP_GENP_NEW, CMP_R_NULL_ARGUMENT);
        return NULL;
    }

    if ((msg = CMP_PKIMESSAGE_create(ctx, V_CMP_PKIBODY_GENP)) == NULL)
        goto err;

    if (ctx->genm_itavs)
        if (!CMP_PKIMESSAGE_genm_items_push1(msg, ctx->genm_itavs))
            goto err;

    if (!CMP_PKIMESSAGE_protect(ctx, msg))
        goto err;

    return msg;

 err:
    CMPerr(CMP_F_CMP_GENP_NEW, CMP_R_ERROR_CREATING_GENP);
    CMP_PKIMESSAGE_free(msg);
    return NULL;
}
/* TODO end: later move these _new functions to cmp_msg.c */

static int CMP_X509_PUBKEY_cmp(X509_PUBKEY *a, X509_PUBKEY *b)
{
    X509_ALGOR *algA = NULL, *algB = NULL;
    int res = 0;

    if (a == b)
        return 0;
    if (a == NULL)
        return -1;
    if (b == NULL)
        return 1;
    (void)X509_PUBKEY_get0_param(NULL, NULL, NULL, &algA, a);
    (void)X509_PUBKEY_get0_param(NULL, NULL, NULL, &algB, b);
    if ((res = X509_ALGOR_cmp(algA, algB)) != 0)
        return res;
    return EVP_PKEY_cmp(X509_PUBKEY_get0(a), X509_PUBKEY_get0(b));
}

static int cmp_verify_popo(CMP_SRV_CTX *srv_ctx, const CMP_PKIMESSAGE *msg)
{

    if (srv_ctx == NULL || msg == NULL || msg->body == NULL) {
        CMPerr(CMP_F_CMP_VERIFY_POPO, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    if (msg->body->type == V_CMP_PKIBODY_P10CR) {
        X509_REQ *req = msg->body->value.p10cr;
        if (X509_REQ_verify(req, X509_REQ_get0_pubkey(req)) > 0)
            return 1;
    } else {
        X509_PUBKEY *pubkey = NULL;
        CRMF_POPOSIGNINGKEY *sig = NULL;
        CRMF_CERTREQMSG *req =
            sk_CRMF_CERTREQMSG_value(msg->body->value.ir, CERTREQID);
        switch (req->popo->type) {
        case CRMF_PROOFOFPOSESSION_RAVERIFIED:
            if (srv_ctx->acceptRAVerified)
                return 1;
            break;
        case CRMF_PROOFOFPOSESSION_SIGNATURE:
            pubkey = req->certReq->certTemplate->publicKey;
            sig = req->popo->value.signature;
            if (sig->poposkInput != NULL) {
/* According to RFC 4211:
publicKey contains a copy of the public key from the certificate template.
This MUST be exactly the same value as is contained in the certificate template.
*/
                if (pubkey == NULL ||
                    sig->poposkInput->publicKey == NULL ||
                    CMP_X509_PUBKEY_cmp(pubkey, sig->poposkInput->publicKey) ||
                    ASN1_item_verify(ASN1_ITEM_rptr(CRMF_POPOSIGNINGKEYINPUT),
                                     sig->algorithmIdentifier, sig->signature,
                                     sig->poposkInput,
                                     X509_PUBKEY_get0(pubkey)) < 1)
                    break;
            } else {
                if (pubkey == NULL ||
                    req->certReq->certTemplate->subject == NULL ||
                    ASN1_item_verify(ASN1_ITEM_rptr(CRMF_CERTREQUEST),
                                     sig->algorithmIdentifier, sig->signature,
                                     req->certReq,
                                     X509_PUBKEY_get0(pubkey)) < 1)
                    break;
            }
            return 1;
        case CRMF_PROOFOFPOSESSION_KEYENCIPHERMENT:
            if (req->popo->value.keyEncipherment->type
                != CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE)
                goto unsupported;
            if (ASN1_INTEGER_get
                (req->popo->value.keyEncipherment->value.subsequentMessage) !=
                CRMF_SUBSEQUENTMESSAGE_ENCRCERT)
                goto unsupported;
#if 0 /* TODO enable code when implemented in CMP_certrep_new() */
            srv_ctx->encryptcert = 1;
            return 1;
#else
            goto unsupported;
#endif
        case CRMF_PROOFOFPOSESSION_KEYAGREEMENT:
        default:
 unsupported:
            CMPerr(CMP_F_CMP_VERIFY_POPO, CMP_R_UNSUPPORTED_POPO_METHOD);
            return 0;
        }
    }
    CMPerr(CMP_F_CMP_VERIFY_POPO, CMP_R_REQUEST_NOT_ACCEPTED);
    return 0;
}

/*
 * Processes an ir/cr/p10cr/kur and returns a certification response.
 * Only handles the first certification request contained in certReq
 * returns an ip/cp/kup on success and NULL on error
 */
static CMP_PKIMESSAGE *CMP_process_cert_request(CMP_SRV_CTX *srv_ctx,
                                                const CMP_PKIMESSAGE *certReq)
{
    CMP_PKIMESSAGE *msg = NULL;
    CMP_PKISTATUSINFO *si = NULL;
    X509 *certOut = NULL;
    STACK_OF(X509) *chainOut = NULL, *caPubs = NULL;
    CRMF_CERTREQMSG *certRequestMsg = NULL;
    int bodytype;
    if (srv_ctx == NULL || certReq == NULL) {
        CMPerr(CMP_F_CMP_PROCESS_CERT_REQUEST, CMP_R_INVALID_ARGS);
        return NULL;
    }
    switch (certReq->body->type) {
    case V_CMP_PKIBODY_P10CR:
    case V_CMP_PKIBODY_CR:
        bodytype = V_CMP_PKIBODY_CP;
        break;
    case V_CMP_PKIBODY_IR:
        bodytype = V_CMP_PKIBODY_IP;
        break;
    case V_CMP_PKIBODY_KUR:
        bodytype = V_CMP_PKIBODY_KUP;
        break;
    default:
        CMPerr(CMP_F_CMP_PROCESS_CERT_REQUEST, CMP_R_UNEXPECTED_PKIBODY);
        return NULL;
    }

    if (certReq->body->type == V_CMP_PKIBODY_P10CR) {
        srv_ctx->certReqId = CERTREQID;
    } else {
        if ((certRequestMsg =
             sk_CRMF_CERTREQMSG_value(certReq->body->value.cr, 0)) == NULL) {
            CMPerr(CMP_F_CMP_PROCESS_CERT_REQUEST, CMP_R_CERTREQMSG_NOT_FOUND);
            return NULL;
        }
        srv_ctx->certReqId =
            ASN1_INTEGER_get(certRequestMsg->certReq->certReqId);
    }

    if (!cmp_verify_popo(srv_ctx, certReq)) {
        /* Proof of possession could not be verified */
        if ((si = CMP_statusInfo_new(CMP_PKISTATUS_rejection,
                                     1 << CMP_PKIFAILUREINFO_badPOP,
                                     NULL)) == NULL)
            goto oom;
    } else if (srv_ctx->pollCount > 0) {
        srv_ctx->pollCount--;
        if ((si = CMP_statusInfo_new(CMP_PKISTATUS_waiting, 0, NULL)) == NULL)
            goto oom;
        CMP_PKIMESSAGE_free(srv_ctx->certReq);
        if ((srv_ctx->certReq = CMP_PKIMESSAGE_dup((CMP_PKIMESSAGE *)certReq))
            == NULL)
            goto oom;
    } else {
        certOut = srv_ctx->certOut;
        chainOut = srv_ctx->chainOut;
        caPubs = srv_ctx->caPubsOut;
        if (CMP_PKIMESSAGE_check_implicitConfirm((CMP_PKIMESSAGE *) certReq) &&
            srv_ctx->grantImplicitConfirm)
            CMP_CTX_set_option(srv_ctx->ctx, CMP_CTX_OPT_IMPLICITCONFIRM, 1);
        if ((si = CMP_PKISTATUSINFO_dup(srv_ctx->pkiStatusOut)) == NULL)
            goto oom;
    }

    msg = CMP_certrep_new(srv_ctx->ctx, bodytype, srv_ctx->certReqId, si,
                          certOut, chainOut, caPubs, srv_ctx->encryptcert,
                          srv_ctx->sendUnprotectedErrors);
    if (msg == NULL)
        CMPerr(CMP_F_CMP_PROCESS_CERT_REQUEST, CMP_R_ERROR_CREATING_CERTREP);

    CMP_PKISTATUSINFO_free(si);
    return msg;

 oom:
    CMPerr(CMP_F_CMP_PROCESS_CERT_REQUEST, CMP_R_OUT_OF_MEMORY);
    CMP_PKISTATUSINFO_free(si);
    return NULL;
}

static CMP_PKIMESSAGE *process_rr(CMP_SRV_CTX *srv_ctx,
                                  const CMP_PKIMESSAGE *req)
{
    CMP_PKIMESSAGE *msg;
    CMP_REVDETAILS *details;
    CRMF_CERTID *certId;

    if (srv_ctx == NULL || req == NULL) {
        CMPerr(CMP_F_PROCESS_RR, CMP_R_NULL_ARGUMENT);
        return NULL;
    }

    if ((details = sk_CMP_REVDETAILS_value(req->body->value.rr,
                                           REVREQSID)) == NULL) {
        CMPerr(CMP_F_PROCESS_RR, CMP_R_ERROR_PROCESSING_MSG);
        return NULL;
    }

    /* accept revocation only for the certificate we send in ir/cr/kur */
    if (ASN1_INTEGER_cmp(details->certDetails->serialNumber,
                         X509_get0_serialNumber(srv_ctx->certOut)) != 0 ||
        X509_NAME_cmp(details->certDetails->issuer,
                      X509_get_issuer_name(srv_ctx->certOut)) != 0) {
        CMPerr(CMP_F_PROCESS_RR, CMP_R_REQUEST_NOT_ACCEPTED);
        return NULL;
    }

    if ((certId = CRMF_CERTID_new()) == NULL) {
        CMPerr(CMP_F_PROCESS_RR, CMP_R_OUT_OF_MEMORY);
        return NULL;
    }
    GENERAL_NAME_set0_value(certId->issuer, GEN_DIRNAME,
                            X509_NAME_dup(details->certDetails->issuer));
    ASN1_INTEGER_free(certId->serialNumber);
    certId->serialNumber = ASN1_INTEGER_dup(details->certDetails->serialNumber);

    if ((msg = CMP_rp_new(srv_ctx->ctx, srv_ctx->pkiStatusOut, certId,
                          srv_ctx->sendUnprotectedErrors)) == NULL)
        CMPerr(CMP_F_PROCESS_RR, CMP_R_ERROR_CREATING_RR);
    return msg;
}

static CMP_PKIMESSAGE *process_certConf(CMP_SRV_CTX *srv_ctx,
                                        const CMP_PKIMESSAGE *req)
{
    CMP_PKIMESSAGE *msg = NULL;
    CMP_CERTSTATUS *status = NULL;
    ASN1_OCTET_STRING *tmp = NULL;
    int res;
    int num = sk_CMP_CERTSTATUS_num(req->body->value.certConf);

    if (num == 0) {
        CMP_printf(srv_ctx->ctx, "Certificate rejected by client\n");
    } else {
        if (num > 1)
            CMP_printf(srv_ctx->ctx,
                       "All CertStatus but the first will be ignored\n");
        status = sk_CMP_CERTSTATUS_value(req->body->value.certConf, CERTREQID);
    }

    if (status != NULL) {
        /* check cert request id */
        if (ASN1_INTEGER_get(status->certReqId) != srv_ctx->certReqId) {
            CMPerr(CMP_F_PROCESS_CERTCONF, CMP_R_UNEXPECTED_REQUEST_ID);
            return NULL;
        }

        /* check cert hash by recalculating it in place */
        tmp = status->certHash;
        status->certHash = NULL;
        res = CMP_CERTSTATUS_set_certHash(status, srv_ctx->certOut) &&
            ASN1_OCTET_STRING_cmp(tmp, status->certHash) == 0;
        ASN1_OCTET_STRING_free(status->certHash);
        status->certHash = tmp;
        if (!res) {
            CMPerr(CMP_F_PROCESS_CERTCONF, CMP_R_WRONG_CERT_HASH);
            return NULL;
        }

        if (status->statusInfo != NULL) {
            char *tmpbuf = OPENSSL_malloc(CMP_PKISTATUSINFO_BUFLEN);
            if (tmpbuf == NULL)
                goto oom;
            CMP_printf(srv_ctx->ctx, "Certificate rejected by client:\n");
            if (CMP_PKISTATUSINFO_snprint(status->statusInfo, tmpbuf,
                                          CMP_PKISTATUSINFO_BUFLEN) != NULL)
                CMP_printf(srv_ctx->ctx, "%s\n", tmpbuf);
            OPENSSL_free(tmpbuf);
        }
    }

    if ((msg = CMP_pkiconf_new(srv_ctx->ctx)) == NULL) {
        CMPerr(CMP_F_PROCESS_CERTCONF, CMP_R_ERROR_CREATING_PKICONF);
        return NULL;
    }

    return msg;

 oom:
    CMPerr(CMP_F_PROCESS_CERTCONF, CMP_R_OUT_OF_MEMORY);
    return NULL;
}

static CMP_PKIMESSAGE *process_error(CMP_SRV_CTX *srv_ctx,
                                     const CMP_PKIMESSAGE *req)
{
    CMP_PKIMESSAGE *msg = CMP_pkiconf_new(srv_ctx->ctx);

    if (msg == NULL) {
        CMPerr(CMP_F_PROCESS_ERROR, CMP_R_ERROR_CREATING_PKICONF);
        return NULL;
    }

    return msg;
}

static CMP_PKIMESSAGE *process_pollReq(CMP_SRV_CTX *srv_ctx,
                                       const CMP_PKIMESSAGE *req)
{
    CMP_PKIMESSAGE *msg = NULL;
    if (!srv_ctx || !srv_ctx->certReq) {
        CMPerr(CMP_F_PROCESS_POLLREQ, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    if (srv_ctx->pollCount == 0) {
        if ((msg = CMP_process_cert_request(srv_ctx, srv_ctx->certReq)) == NULL)
            CMPerr(CMP_F_PROCESS_POLLREQ, CMP_R_ERROR_PROCESSING_CERTREQ);
    } else {
        srv_ctx->pollCount--;
        if ((msg = CMP_pollrep_new(srv_ctx->ctx, srv_ctx->certReqId,
                                   srv_ctx->checkAfterTime)) == NULL)
            CMPerr(CMP_F_PROCESS_POLLREQ, CMP_R_ERROR_CREATING_POLLREP);
    }
    return msg;
}

/*
 * Processes genm and creates a genp message mirroring the contents of the
 * incoming message
 */
static CMP_PKIMESSAGE *process_genm(CMP_SRV_CTX *srv_ctx,
                                    const CMP_PKIMESSAGE *req)
{
    CMP_PKIMESSAGE *msg = NULL;
    STACK_OF(CMP_INFOTYPEANDVALUE) *tmp = NULL;

    if (srv_ctx == NULL || srv_ctx->ctx == NULL || req == NULL) {
        CMPerr(CMP_F_PROCESS_GENM, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    /* Back up potential genm_itavs */
    tmp = srv_ctx->ctx->genm_itavs;
    srv_ctx->ctx->genm_itavs = req->body->value.genm;
    if ((msg = CMP_genp_new(srv_ctx->ctx)) == NULL)
        CMPerr(CMP_F_PROCESS_GENM, CMP_R_OUT_OF_MEMORY);
    /* restore genm_itavs */
    srv_ctx->ctx->genm_itavs = tmp;
    return msg;
}

/*
 * Determines whether missing protection is allowed
 */
static int unprotected_exception(const CMP_CTX *ctx,
                                 int accept_unprotected_requests,
                                 const CMP_PKIMESSAGE *req)
{
    if (accept_unprotected_requests) {
        CMP_printf(ctx, "WARN: ignoring missing protection of request message");
        return 1;
    }
    if (req->body->type == V_CMP_PKIBODY_ERROR && ctx->unprotectedErrors) {
        CMP_printf(ctx, "WARN: ignoring missing protection of error message");
        return 1;
    }
    return 0;
}

/*
 * Mocks the server/responder.
 * srv_ctx is the context of the server
 * returns 1 if a message was created and 0 on error
 */
static int process_request(CMP_SRV_CTX *srv_ctx, const CMP_PKIMESSAGE *req,
                           CMP_PKIMESSAGE **rsp)
{
    cmp_srv_process_cb_t process_cb = NULL;
    CMP_CTX *ctx;

    if (srv_ctx == NULL || srv_ctx->ctx == NULL || req == NULL || rsp == NULL) {
        CMPerr(CMP_F_PROCESS_REQUEST, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    ctx = srv_ctx->ctx;
    *rsp = NULL;

    if (req->header->sender->type != GEN_DIRNAME) {
        CMPerr(CMP_F_PROCESS_REQUEST,
               CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED);
        return 0;
    }
    if (!X509_NAME_set(&ctx->recipient, req->header->sender->d.directoryName)) {
        CMPerr(CMP_F_PROCESS_REQUEST, CMP_R_OUT_OF_MEMORY);
        return 0;
    }

    if (CMP_PKIMESSAGE_check_received(ctx, req,
                                      srv_ctx->acceptUnprotectedRequests,
                                      unprotected_exception) < 0) {
        CMPerr(CMP_F_PROCESS_REQUEST, CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE);
        return 0;
    }
    if (srv_ctx->sendError) {
        if ((*rsp = CMP_error_new(ctx, srv_ctx->pkiStatusOut, -1, NULL,
                                  srv_ctx->sendUnprotectedErrors)))
            return 1;
        CMPerr(CMP_F_PROCESS_REQUEST, CMP_R_ERROR_CREATING_ERROR);
        return 0;
    }

    switch (req->body->type) {
    case V_CMP_PKIBODY_IR:
        process_cb = srv_ctx->process_ir_cb;
        break;
    case V_CMP_PKIBODY_CR:
        process_cb = srv_ctx->process_cr_cb;
        break;
    case V_CMP_PKIBODY_P10CR:
        process_cb = srv_ctx->process_p10cr_cb;
        break;
    case V_CMP_PKIBODY_KUR:
        process_cb = srv_ctx->process_kur_cb;
        break;
    case V_CMP_PKIBODY_POLLREQ:
        process_cb = srv_ctx->process_pollreq_cb;
        break;
    case V_CMP_PKIBODY_RR:
        process_cb = srv_ctx->process_rr_cb;
        break;
    case V_CMP_PKIBODY_ERROR:
        process_cb = srv_ctx->process_error_cb;
        break;
    case V_CMP_PKIBODY_CERTCONF:
        process_cb = srv_ctx->process_certconf_cb;
        break;
    case V_CMP_PKIBODY_GENM:
        process_cb = srv_ctx->process_genm_cb;
        break;
    default:
        CMPerr(CMP_F_PROCESS_REQUEST, CMP_R_UNEXPECTED_PKIBODY);
        break;
    }
    if (process_cb == NULL)
        return 0;
    if ((*rsp = process_cb(srv_ctx, req)) == NULL)
        return 0;

    return 1;
}

/*
 * Mocks the server connection. Works similar to CMP_PKIMESSAGE_http_perform.
 * A CMP_SRV_CTX must be set as transfer_cb_arg
 * returns 0 on success and else a CMP error reason code defined in cmp.h
 */
int CMP_mock_server_perform(CMP_CTX *cmp_ctx, const CMP_PKIMESSAGE *req,
                            CMP_PKIMESSAGE **rsp)
{
    CMP_PKIMESSAGE *srv_req = NULL, *srv_rsp = NULL;
    CMP_SRV_CTX *srv_ctx = NULL;
    int error = 0;

    if (cmp_ctx == NULL || req == NULL || rsp == NULL)
        return CMP_R_NULL_ARGUMENT;
    *rsp = NULL;

    if ((srv_ctx = CMP_CTX_get_transfer_cb_arg(cmp_ctx)) == NULL)
        return CMP_R_ERROR_TRANSFERRING_OUT;

    /* CMP_PKIMESSAGE_dup en- and decodes ASN.1, used for checking encoding */
    if ((srv_req = CMP_PKIMESSAGE_dup((CMP_PKIMESSAGE *)req)) == NULL)
        error = CMP_R_ERROR_DECODING_MESSAGE;

    if (process_request(srv_ctx, srv_req, &srv_rsp) == 0) {
        CMP_PKISTATUSINFO *si;
        const char *data;
        int flags = 0;
        unsigned long err = ERR_peek_error_line_data(NULL, NULL, &data, &flags);
        if ((si = CMP_statusInfo_new(CMP_PKISTATUS_rejection,
                                     /* TODO make failure bits more specific */
                                     1 << CMP_PKIFAILUREINFO_badRequest,
                                     NULL))) {
            srv_rsp = CMP_error_new(cmp_ctx, si,
                                    err != 0 ? ERR_GET_REASON(err): -1,
                                    CMP_PKIFREETEXT_push_str(NULL,
                                            flags&ERR_TXT_STRING ? data : NULL),
                                    srv_ctx->sendUnprotectedErrors);
            CMP_PKISTATUSINFO_free(si);
        } else {
            error = CMP_R_ERROR_PROCESSING_MSG;
        }
        goto end;
    }

    /* CMP_PKIMESSAGE_dup en- and decodes ASN.1, used for checking encoding */
    if ((*rsp = CMP_PKIMESSAGE_dup(srv_rsp)) == NULL) {
        error = CMP_R_ERROR_DECODING_MESSAGE;
        goto end;
    }

 end:
    CMP_PKIMESSAGE_free(srv_req);
    CMP_PKIMESSAGE_free(srv_rsp);

    return error;
}

/*
 * creates and initializes a CMP_SRV_CTX structure
 * returns pointer to created CMP_SRV_ on success, NULL on error
 */
CMP_SRV_CTX *CMP_SRV_CTX_create(void)
{
    CMP_SRV_CTX *ctx = NULL;
    if ((ctx = CMP_SRV_CTX_new()) == NULL)
        goto oom;
    ctx->certReqId = -1;
    if ((ctx->ctx = CMP_CTX_create()) == NULL)
        goto oom;
    ctx->pollCount = 0;
    ctx->checkAfterTime = 1;
    ctx->grantImplicitConfirm = 0;
    ctx->sendError = 0;
    ctx->sendUnprotectedErrors = 0;
    ctx->acceptUnprotectedRequests = 0;
    ctx->encryptcert = 0;
    ctx->acceptRAVerified = 0;
    ctx->certReqId = CERTREQID;
    ctx->process_ir_cb = CMP_process_cert_request;
    ctx->process_cr_cb = CMP_process_cert_request;
    ctx->process_p10cr_cb = CMP_process_cert_request;
    ctx->process_kur_cb = CMP_process_cert_request;
    ctx->process_certconf_cb = process_certConf;
    ctx->process_error_cb = process_error;
    ctx->process_rr_cb = process_rr;
    ctx->process_pollreq_cb = process_pollReq;
    ctx->process_genm_cb = process_genm;
    return ctx;
 oom:
    CMPerr(CMP_F_CMP_SRV_CTX_CREATE, CMP_R_OUT_OF_MEMORY);
    CMP_SRV_CTX_free(ctx);
    return NULL;
}
#endif                          /* NDEBUG */
