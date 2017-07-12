 /* crypto/cmp/cmp_ses.c
  * Functions to do CMP (RFC 4210) message sequences for OpenSSL
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
 *              notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *              notice, this list of conditions and the following disclaimer in
 *              the documentation and/or other materials provided with the
 *              distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *              software must display the following acknowledgment:
 *              "This product includes software developed by the OpenSSL Project
 *              for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *              endorse or promote products derived from this software without
 *              prior written permission. For written permission, please contact
 *              openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *              nor may "OpenSSL" appear in their names without prior written
 *              permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *              acknowledgment:
 *              "This product includes software developed by the OpenSSL Project
 *              for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

#include <string.h>

#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#define sleep(x) Sleep((x) * 1000)
#endif

#include "cmp_int.h"

/* XXX this is here to fool the openssl perl script that checks errors codes strictly
 *     without func() the macro below would cause the script to complain */
#if 0
static void func()
{
}
#endif
/* adds connection error information to OpenSSL error queue */
#define ADD_HTTP_ERROR_INFO(cmp_f_func, errcode, msg)\
                if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT\
                        && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)\
                        CMPerr(cmp_f_func, errcode);\
                else\
                        { CMP_add_error_data("unable to send"); CMP_add_error_data(msg); }

/* ############################################################################ *
 * table used to translate PKIMessage body type number into a printable string
 * ############################################################################ */
static char *V_CMP_TABLE[] = {
    "IR",
    "IP",
    "CR",
    "CP",
    "P10CR",
    "POPDECC",
    "POPDECR",
    "KUR",
    "KUP",
    "KRR",
    "KRP",
    "RR",
    "RP",
    "CCR",
    "CCP",
    "CKUANN",
    "CANN",
    "RANN",
    "CRLANN",
    "PKICONF",
    "NESTED",
    "GENM",
    "GENP",
    "ERROR",
    "CERTCONF",
    "POLLREQ",
    "POLLREP",
};

#define MSG_TYPE_STR(type)      \
        (((unsigned int) (type) < sizeof(V_CMP_TABLE)/sizeof(V_CMP_TABLE[0])) \
         ? V_CMP_TABLE[(unsigned int)(type)] : "unknown")

/* ############################################################################ *
 * internal function
 *
 * adds error data of the given CMP_PKIMESSAGE
 * ############################################################################ */
static void message_add_error_data(CMP_PKIMESSAGE *msg)
{
    char tempbuf[1024], *s;
    switch (CMP_PKIMESSAGE_get_bodytype(msg)) {
    case V_CMP_PKIBODY_ERROR:
        s = CMP_PKISTATUSINFO_snprint(msg->body->value.error->
                                      pKIStatusInfo, tempbuf, sizeof(tempbuf));
        ERR_add_error_data(2, "got error message; ", s);
        break;
    case -1:
        ERR_add_error_data(1, "got no message");
        break;
    default:
        ERR_add_error_data(3, "got unexpected message type '",
                               MSG_TYPE_STR(CMP_PKIMESSAGE_get_bodytype(msg)), "'");
        break;
    }
}

/* evaluate whether there's an standard-violating exception configured for
   handling unportected errors */
static int unprotected_exception(const CMP_PKIMESSAGE *rep,
                                 int type_rep,
                                 int rcvd_type,
                                 CMP_CTX *ctx)
{
    int exception = 0;

    if (ctx->unprotectedErrors) {
        if (rcvd_type == V_CMP_PKIBODY_ERROR) {
            CMP_printf(ctx, "WARN: ignoring missing protection of error response");
            exception = 1;
        }
        if (rcvd_type == V_CMP_PKIBODY_RP &&
                CMP_REVREPCONTENT_PKIStatus_get(rep->body->value.rp, 0) == CMP_PKISTATUS_rejection) {
            CMP_printf(ctx, "WARN: ignoring missing protection of revocation response message with rejection status");
            exception = 1;
        }
        if (rcvd_type == V_CMP_PKIBODY_PKICONF) {
            CMP_printf(ctx, "WARN: ignoring missing protection of PKI Confirmation message");
            exception = 1;
        }
        if (rcvd_type == type_rep &&
                (rcvd_type == V_CMP_PKIBODY_IP ||
                 rcvd_type == V_CMP_PKIBODY_CP ||
                 rcvd_type == V_CMP_PKIBODY_KUP)) {
            CMP_CERTRESPONSE *crep =
                CMP_CERTREPMESSAGE_certResponse_get0(rep->body->value.ip, 0); /* same for cp and kup */
            /* TODO handle multiple CertResponses in CertRepMsg (in case multiple requests have been sent) */
            if (!crep)
                return 0;
            if (CMP_CERTRESPONSE_PKIStatus_get(crep) == CMP_PKISTATUS_rejection) {
                CMP_printf(ctx, "WARN: ignoring missing protection of CertRepMessage with rejection status");
                exception = 1;
            }
        }
    }
    return exception;
}

/* ############################################################################ *
 * internal function
 *
 * performs the generic aspects of sending a request and receiving a response
 * returns 1 on success, 0 on error
 * Regardless of success, caller is responsible for freeing *rep (unless NULL).
 * ############################################################################ */
static int send_receive_check(CMP_CTX *ctx,
                        const CMP_PKIMESSAGE *req, const char *type_string, int type_function,
                              CMP_PKIMESSAGE **rep, int type_rep, int not_received)
{
    int rcvd_type;

    CMP_printf(ctx, "INFO: Sending %s", type_string);
    if (!(CMP_PKIMESSAGE_http_perform(ctx, req, rep))) {
        ADD_HTTP_ERROR_INFO(type_function, not_received, type_string);
        *rep = NULL;
        return 0;
    }

    rcvd_type = CMP_PKIMESSAGE_get_bodytype(*rep);

    CMP_printf(ctx, "INFO: Got response");

    /* validate message protection */
    if ((*rep)->header->protectionAlg) {
        if (!CMP_validate_msg(ctx, *rep)) {
            /* validation failed */
             CMPerr(type_function, CMP_R_ERROR_VALIDATING_PROTECTION);
             return 0;
         }
    } else {
        CMP_printf(ctx, "INFO: response message is not protected");
        /* detect explicitly permitted exceptions */
        if (!unprotected_exception(*rep, type_rep, rcvd_type, ctx)) {
            CMPerr(type_function, CMP_R_ERROR_VALIDATING_PROTECTION);
            return 0;
        }
    }

    /* compare received nonce with the one sent in request */
    if (req->header->senderNonce && (!(*rep)->header->recipNonce ||
        ASN1_OCTET_STRING_cmp(req->header->senderNonce, (*rep)->header->recipNonce))) {
        /* senderNonce != recipNonce (sic although there is no "!" in the if) */
        CMPerr(type_function, CMP_R_ERROR_NONCES_DO_NOT_MATCH);
        return 0;
    }

    /* compare received transactionID with our current one */
    if (ctx->transactionID && (!(*rep)->header->transactionID ||
        ASN1_OCTET_STRING_cmp(ctx->transactionID, (*rep)->header->transactionID))) {
        CMPerr(type_function, CMP_R_ERROR_TRANSACTIONID_UNMATCHED);
        return 0;
    }

    /* catch if the received message type is not one of the expected ones (e.g. error) */
    if (rcvd_type != type_rep &&
        !(type_rep == V_CMP_PKIBODY_POLLREP && /* instead of pollrep there could be IP/CP/KUP */
        (rcvd_type == V_CMP_PKIBODY_IP ||
         rcvd_type == V_CMP_PKIBODY_CP ||
         rcvd_type == V_CMP_PKIBODY_KUP))) {
        CMPerr(type_function, CMP_R_PKIBODY_ERROR);
        message_add_error_data(*rep);
        return 0;
    }

    /* RFC 4210 section 5.1.1 states: the recipNonce is copied from
       the senderNonce of the previous message in the transaction. */
    CMP_CTX_set1_recipNonce(ctx, (*rep)->header->senderNonce); /* store for setting in the next msg */

    return 1;
}

/* ############################################################################ *
 * internal function
 *
 * When a 'waiting' PKIStatus has been received, this function is used to attempt
 * to poll for a response message.
 *
 * A maxPollTime timeout can be set in the context.  The function will continue
 * to poll until the timeout is reached and then poll a last time even when that
 * is before the "checkAfter" sent by the server.  If ctx->maxPollTime is 0, the
 * timeout is disabled.
 *
 * returns 1 on success, returns received PKIMESSAGE in *msg argument
 * returns 0 on error or when timeout is reached without a received messsage
 *
 * TODO handle multiple pollreqs for multiple certificates
 * ############################################################################ */
static int pollForResponse(CMP_CTX *ctx, CMP_PKIMESSAGE **out)
{
    int maxTimeLeft = ctx->maxPollTime;
    CMP_PKIMESSAGE *preq = NULL;
    CMP_PKIMESSAGE *prep = NULL;
    CMP_POLLREP *pollRep = NULL;

    CMP_printf(ctx,
               "INFO: Received 'waiting' PKIStatus, starting to poll for response.");
    for (;;) {
        if (!(preq = CMP_pollReq_new(ctx, 0)))
            goto err;           /* TODO: this only handles one certificate request so far */

        if (!send_receive_check(ctx, preq, "pollReq", CMP_F_POLLFORRESPONSE,
                                    &prep, V_CMP_PKIBODY_POLLREP, CMP_R_POLLREP_NOT_RECEIVED))
             goto err;

        /* handle potential pollRep */
        if (CMP_PKIMESSAGE_get_bodytype(prep) == V_CMP_PKIBODY_POLLREP) {
            int checkAfter;
            if (!(pollRep =
                  sk_CMP_POLLREP_value(prep->body->value.pollRep, 0)))
                goto err;       /* TODO: this only handles one certificate request so far */
            checkAfter = ASN1_INTEGER_get(pollRep->checkAfter);
            if (checkAfter < 0) {
                CMPerr(CMP_F_POLLFORRESPONSE, CMP_R_RECEIVED_NEGATIVE_CHECKAFTER_IN_POLLREP);
                goto err;
            }
            /* TODO: print OPTIONAL reason (PKIFreeText) from message */
            CMP_printf(ctx,
                       "INFO: Received polling response, waiting checkAfter = %ld sec before next polling request.",
                       checkAfter);

            if (ctx->maxPollTime != 0) { /* timout is set in context */
                if (maxTimeLeft == 0)
                    goto err;   /* timeout reached */
                if (maxTimeLeft > checkAfter) {
                    maxTimeLeft -= checkAfter;
                } else {
                    checkAfter = maxTimeLeft; /* poll a last time just when the set timeout will be reached */
                    maxTimeLeft = 0;
                }
            }

            CMP_PKIMESSAGE_free(preq);
            preq = NULL;
            CMP_PKIMESSAGE_free(prep);
            prep = NULL;
            sleep((unsigned int)checkAfter);
        } else {
            CMP_printf(ctx, "INFO: Got final response after polling.");
            break;              /* final success */
        }
    }
    if (!prep)
        goto err;

    CMP_PKIMESSAGE_free(preq);
    *out = prep;

    return 1;
 err:
    CMP_PKIMESSAGE_free(preq);
    CMP_PKIMESSAGE_free(prep);
    return 0;
}

/* ############################################################################ *
 * internal function
 *
 * send certConf for IR, CR or KUR sequences and check response
 * returns 1 on success, 0 on error
 * ############################################################################ */
static int exchange_certConf(CMP_CTX *ctx, int failure, const char *text)
{
    CMP_PKIMESSAGE *certConf = NULL;
    CMP_PKIMESSAGE *PKIconf = NULL;
    int success = 0;

    /* check if all necessary options are set is done in CMP_certConf_new */
    /* create Certificate Confirmation - certConf */
    if (!(certConf = CMP_certConf_new(ctx, failure, text)))
        goto err;

    success = send_receive_check(ctx, certConf, "certConf", CMP_F_EXCHANGE_CERTCONF,
                                 &PKIconf, V_CMP_PKIBODY_PKICONF, CMP_R_PKICONF_NOT_RECEIVED);

 err:
    CMP_PKIMESSAGE_free(certConf);
    CMP_PKIMESSAGE_free(PKIconf);
    return success;
}

/* ############################################################################ *
 * internal function
 *
 * send given error and check response
 * returns 1 on success, 0 on error
 * ############################################################################ */
static int exchange_error(CMP_CTX *ctx, int status, int failure, const char *text)
{
    CMP_PKIMESSAGE *error = NULL;
    CMP_PKISTATUSINFO *si = NULL;
    CMP_PKIMESSAGE *PKIconf = NULL;
    int success = 0;

    /* check if all necessary options are set is done in CMP_error_new */
    /* create Error Message - error */
    if (!(si = CMP_statusInfo_new(status, failure, text)))
        goto err;
    if (!(error = CMP_error_new(ctx, si, -1, NULL))) {
        CMP_PKISTATUSINFO_free(si);
        goto err;
    }

    success = send_receive_check(ctx, error, "error", CMP_F_EXCHANGE_ERROR,
                                 &PKIconf, V_CMP_PKIBODY_PKICONF, CMP_R_PKICONF_NOT_RECEIVED);

 err:
    CMP_PKIMESSAGE_free(error); /* also frees si if included */
    CMP_PKIMESSAGE_free(PKIconf);
    return success;
}

/* ############################################################################ *
 * internal function
 *
 * saves error information from PKIStatusInfo field of a certresponse into the ctx
 * ############################################################################ */
static int save_certresponse_statusInfo(CMP_CTX *ctx, CMP_CERTRESPONSE *resp)
{
    int i;
    STACK_OF (ASN1_UTF8STRING) *ss;

    if (!resp)
        return 0;
    (void)CMP_CTX_set_failInfoCode(ctx, CMP_CERTRESPONSE_PKIFailureInfo_get0(resp));
    if ((ctx->lastPKIStatus = CMP_PKISTATUSINFO_PKIStatus_get(resp->status) < 0)) /* TODO: create CTX function */
        return 0;

    if (!ctx->lastStatusString &&
        !(ctx->lastStatusString = sk_ASN1_UTF8STRING_new_null()))
        return 0;

    ss = CMP_CERTRESPONSE_PKIStatusString_get0(resp);
    for (i = 0; i < sk_ASN1_UTF8STRING_num(ss); i++) {
        ASN1_UTF8STRING *str = sk_ASN1_UTF8STRING_value(ss, i);
        if (!sk_ASN1_UTF8STRING_push(ctx->lastStatusString,
                                     ASN1_STRING_dup(str)))
            return 0;
    }
    return 1;
}

/* ############################################################################ *
 * internal function
 *
 * performs the generic handling of certificate responses for IR/CR/KUR
 * returns 1 on success, 0 on error
 * Regardless of success, caller is responsible for freeing *resp (unless NULL).
 * ############################################################################ */
static int cert_response(CMP_CTX *ctx,
                         CMP_PKIMESSAGE **resp,
                         int type_function, int not_received)
{
    int failure = -1; /* no failure */
    const char *text = NULL;
    CMP_CERTREPMESSAGE *body;
    CMP_CERTRESPONSE *crep;

 retry:
    body = (*resp)->body->value.ip; /* same for cp and kup */

    /* TODO handle multiple CertResponses in CertRepMsg (in case multiple requests have been sent) */
    crep = CMP_CERTREPMESSAGE_certResponse_get0(body, 0);
    if (!crep)
        return 0;

    if (CMP_CERTRESPONSE_PKIStatus_get(crep) == CMP_PKISTATUS_waiting) {
        CMP_PKIMESSAGE_free(*resp);
        if (pollForResponse(ctx, resp)) {
            goto retry;
        } else {
            CMPerr(type_function, not_received);
            ERR_add_error_data(1, "received 'waiting' pkistatus but polling failed");
            *resp = NULL;
            return 0;
        }
    }

    if (!save_certresponse_statusInfo(ctx, crep))
        return 0;
    if (!(ctx->newClCert = CMP_CERTRESPONSE_get_certificate(ctx, crep))) {
        CMP_add_error_data("cannot extract certificate from response");
        return 0;
    }

    /* if the CMP server returned certificates in the caPubs field, copy them
     * to the context so that they can be retrieved if necessary */
    if (body->caPubs)
        CMP_CTX_set1_caPubs(ctx, body->caPubs);

    /* copy any received extraCerts to ctx->extraCertsIn so they can be retrieved */
    if ((*resp)->extraCerts)
        CMP_CTX_set1_extraCertsIn(ctx, (*resp)->extraCerts);

    if (!(X509_check_private_key(ctx->newClCert, ctx->newPkey ? ctx->newPkey : ctx->pkey))) {
        /* TODO: not entirely clear if in this case an error message or a negative certConfirm should be sent */
        failure = CMP_PKIFAILUREINFO_incorrectData;
        text = "public key in new certificate does not match our private key";
        (void)exchange_error(ctx, CMP_PKISTATUS_rejection, failure, text);
        /* cannot flag the error earlier because send_receive_check() indirectly calls ERR_clear_error() */
        CMPerr(type_function, CMP_R_CERTIFICATE_NOT_ACCEPTED);
        ERR_add_error_data(1, text);
        return 0;
    }
    /* TODO: possibly compare also subject and other fields of the newly enrolled cert with requested cert template */
    /* if present, execute the callback function set in ctx which can be used to
     * examine whether a received certificate should be accepted */
    if (ctx->certConf_cb &&
             (failure = ctx->certConf_cb(ctx, ctx->lastPKIStatus, ctx->newClCert)) >= 0) {
        text = "CMP client application did not accept newly enrolled certificate";
    }

    /* check if implicit confirm is set in generalInfo and send certConf if not */
    /* TODO: send negative certConf also in case implicit confirmation has been granted? */
    if (!ctx->disableConfirm && !CMP_PKIMESSAGE_check_implicitConfirm(*resp))
        if (!exchange_certConf(ctx, failure, text))
            return 0;

    if (failure >= 0) {
        /* cannot flag the error earlier because send_receive_check() indirectly calls ERR_clear_error() */
        CMPerr(type_function, CMP_R_CERTIFICATE_NOT_ACCEPTED);
        ERR_add_error_data(1, "certConf callback resulted in rejection of new certificate");
        return 0;
    }
    return 1;
}

/* ############################################################################ *
 * do the full sequence for IR, including IR, IP, certConf, PKIconf and
 * potential polling
 *
 * All options need to be set in the context.
 *
 * TODO: another function to request two certificates at once should be created
 *
 * returns pointer to received certificate, NULL if none was received
 * ############################################################################ */
X509 *CMP_doInitialRequestSeq(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *ir = NULL;
    CMP_PKIMESSAGE *ip = NULL;
    X509 *result = NULL;

    /* check if all necessary options are set is done in CMP_ir_new */
    /* create Initialization Request - ir */
    if (!(ir = CMP_ir_new(ctx)))
            goto err;

    if (!send_receive_check(ctx, ir, "ir", CMP_F_CMP_DOINITIALREQUESTSEQ,
                                &ip, V_CMP_PKIBODY_IP, CMP_R_IP_NOT_RECEIVED))
        goto err;

    if (!cert_response(ctx, &ip, CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_IP_NOT_RECEIVED))
        goto err;

    result = ctx->newClCert;
 err:
    if (ir)
        CMP_PKIMESSAGE_free(ir);
    if (ip)
        CMP_PKIMESSAGE_free(ip);

    /* print out openssl and cmp errors to error_cb if it's set */
    if (!result && ctx && ctx->error_cb)
        ERR_print_errors_cb(CMP_CTX_error_callback, (void *)ctx);
    return result;
}

/* ############################################################################ *
 * do the full sequence for RR, including RR, RP and potential polling
 *
 * All options need to be set in the context.
 *
 * TODO: this function can only revoke one certifcate so far, should be possible
 * for several according to 5.3.9
 *
 * The RFC is vague in which PKIStatus should be returned by the server, so we
 * take "accepted, grantedWithMods, revocationWarning, revocationNotification"
 * as information that the certifcate was revoked, "rejection" as information
 * that the revocation was rejected and don't expect "waiting, keyUpdateWarning"
 * (which are handled as error)
 *
 * returns according to PKIStatus received, 0 on error
 *          accepted               (1)
 *          grantedWithMods        (2)
 *          rejection              (3) (this is not an error!)
 *          revocationWarning      (5)
 *          revocationNotification (6)
 * ############################################################################ */
int CMP_doRevocationRequestSeq(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *rr = NULL;
    CMP_PKIMESSAGE *rp = NULL;
    int pkiStatus = 0;
    int result = 0;

    /* check if all necessary options are set is done in CMP_rr_new */
    /* create Revocation Request - ir */
    if (!(rr = CMP_rr_new(ctx)))
        goto err;

    if (!send_receive_check(ctx, rr, "rr", CMP_F_CMP_DOREVOCATIONREQUESTSEQ,
                                &rp, V_CMP_PKIBODY_RP, CMP_R_RP_NOT_RECEIVED))
        goto err;

    /* evaluate PKIStatus field */
    switch (pkiStatus =
            CMP_REVREPCONTENT_PKIStatus_get(rp->body->value.rp, 0)) {
    case CMP_PKISTATUS_accepted:
        CMP_printf(ctx, "INFO: revocation accepted (PKIStatus=accepted)");
        break;
    case CMP_PKISTATUS_grantedWithMods:
        CMP_printf(ctx,
                   "INFO: revocation accepted (PKIStatus=grantedWithMods)");
        break;
    case CMP_PKISTATUS_rejection:
        CMP_printf(ctx, "INFO: revocation rejected (PKIStatus=rejection)");
        puts("warning: certificate has already been revoked"); /* TODO: add proper warning function */
        break;
    case CMP_PKISTATUS_revocationWarning:
        CMP_printf(ctx,
                   "INFO: revocation accepted (PKIStatus=revocationWarning)");
        break;
    case CMP_PKISTATUS_revocationNotification:
        CMP_printf(ctx,
                   "INFO: revocation accepted (PKIStatus=revocationNotification)");
        break;
    case CMP_PKISTATUS_waiting:
    case CMP_PKISTATUS_keyUpdateWarning:
        CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_UNEXPECTED_PKISTATUS);
        goto err;
    default:
        CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_UNKNOWN_PKISTATUS);
        goto err;
    }

    result = pkiStatus + 1;
 err:
    if (rr)
        CMP_PKIMESSAGE_free(rr);
    if (rp)
        CMP_PKIMESSAGE_free(rp);

    /* print out openssl and cmp errors to error_cb if it's set */
    if (!result && ctx && ctx->error_cb)
        ERR_print_errors_cb(CMP_CTX_error_callback, (void *)ctx);
    return result;
}

/* ############################################################################ *
 * do the full sequence for CR, including CR, CP, certConf, PKIconf and
 * potential polling
 *
 * All options need to be set in the context.
 *
 * TODO: another function to request two certificates at once should be created
 *
 * returns pointer to received certificate, NULL if non was received
 * ############################################################################ */
X509 *CMP_doCertificateRequestSeq(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *cr = NULL;
    CMP_PKIMESSAGE *cp = NULL;
    X509 *result = NULL;

    /* check if all necessary options are set is done by CMP_cr_new */
    /* create Certificate Request - cr */
    if (!(cr = CMP_cr_new(ctx)))
        goto err;

    if (!send_receive_check(ctx, cr, "cr", CMP_F_CMP_DOCERTIFICATEREQUESTSEQ,
                                &cp, V_CMP_PKIBODY_CP, CMP_R_CP_NOT_RECEIVED))
        goto err;

    if (!cert_response(ctx, &cp, CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_CP_NOT_RECEIVED))
        goto err;

    result = ctx->newClCert;
 err:
    if (cr)
        CMP_PKIMESSAGE_free(cr);
    if (cp)
        CMP_PKIMESSAGE_free(cp);

    /* print out openssl and cmp errors to error_cb if it's set */
    if (!result && ctx && ctx->error_cb)
        ERR_print_errors_cb(CMP_CTX_error_callback, (void *)ctx);
    return result;
}

/* ############################################################################ *
 * do the full sequence for KUR, including KUR, KUP, certConf, PKIconf and
 * potential polling
 *
 * All options need to be set in the context.
 *
 * NB: the ctx->newPkey can be set *by the user* as the same as the current key
 * as per section 5.3.5:
 * An update is a replacement
 * certificate containing either a new subject public key or the current
 * subject public key (although the latter practice may not be
 * appropriate for some environments).
 *
 * TODO: another function to request two certificates at once should be created
 *
 * returns pointer to received certificate, NULL if non was received
 * ############################################################################ */
X509 *CMP_doKeyUpdateRequestSeq(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *kur = NULL;
    CMP_PKIMESSAGE *kup = NULL;
    X509 *result = NULL;

    /* check if all necessary options are set is done in CMP_kur_new */
    /* create Key Update Request - kur */
    if (!(kur = CMP_kur_new(ctx)))
        goto err;

    if (!send_receive_check(ctx, kur, "kur", CMP_F_CMP_DOKEYUPDATEREQUESTSEQ,
                                &kup, V_CMP_PKIBODY_KUP, CMP_R_KUP_NOT_RECEIVED))
        goto err;

    if (!cert_response(ctx, &kup, CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_KUP_NOT_RECEIVED))
            goto err;

    result = ctx->newClCert;
 err:
    if (kur)
        CMP_PKIMESSAGE_free(kur);
    if (kup)
        CMP_PKIMESSAGE_free(kup);

    /* print out openssl and cmp errors to error_cb if it's set */
    if (!result && ctx && ctx->error_cb)
        ERR_print_errors_cb(CMP_CTX_error_callback, (void *)ctx);
    return result;
}

/* ############################################################################ *
 * Sends a general message to the server to request information specified in the
 * InfoType and Value (itav) given in the ctx->genm_itavs, see section 5.3.19
 * and E.5.
 *
 * returns pointer to stack of ITAVs received in the answer or NULL on error
 * ############################################################################ */
STACK_OF (CMP_INFOTYPEANDVALUE) *CMP_doGeneralMessageSeq(CMP_CTX *ctx)
{
    CMP_PKIMESSAGE *genm = NULL;
    CMP_PKIMESSAGE *genp = NULL;
    STACK_OF (CMP_INFOTYPEANDVALUE) *rcvd_itavs = NULL;

    if (!(genm = CMP_genm_new(ctx)))
        goto err;

    if (!send_receive_check(ctx, genm, "genm", CMP_F_CMP_DOGENERALMESSAGESEQ,
                             &genp, V_CMP_PKIBODY_GENP, CMP_R_GENP_NOT_RECEIVED))
         goto err;

    /* received stack of itavs not to be freed with the genp */
    rcvd_itavs = genp->body->value.genp;
    genp->body->value.genp = NULL;

 err:
    if (genm)
        CMP_PKIMESSAGE_free(genm);
    if (genp)
        CMP_PKIMESSAGE_free(genp);

    /* print out openssl and cmp errors to error_cb if it's set */
    /* TODO: verify that !recv_itavs is necessarily an error */
    if (!rcvd_itavs && ctx && ctx->error_cb)
        ERR_print_errors_cb(CMP_CTX_error_callback, (void *)ctx);
    return rcvd_itavs;
}
