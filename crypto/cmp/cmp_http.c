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

#include <string.h>
#include <stdio.h>

#include <openssl/asn1t.h>
#include <openssl/http.h>
#include "internal/sockets.h"

#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/cmp.h>
#include <openssl/err.h>

#ifndef OPENSSL_NO_SOCK

static void add_conn_error_hint(const OSSL_CMP_CTX *ctx, unsigned long detail)
{
    char buf[200];

    BIO_snprintf(buf, 200, "host '%s' port %d",
                 ctx->serverName, ctx->serverPort);
    ossl_cmp_add_error_data(buf);
    if (detail == 0) {
        BIO_snprintf(buf, 200, "server has disconnected%s",
                     ctx->http_cb_arg != NULL ? " violating the protocol" :
                     ", likely because it requires the use of TLS");
        ossl_cmp_add_error_data(buf);
    }
}

/*
 * Create a new http connection BIO, as specified in CMP CTX
 * returns the created BIO or NULL on failure
 */
static BIO *CMP_new_http_bio(const OSSL_CMP_CTX *ctx)
{
    BIO *cbio = NULL;
    char sport[32];
    char pport[32];

    if (!ossl_assert(ctx != NULL))
        return NULL;

    BIO_snprintf(sport, sizeof(sport), "%d", ctx->serverPort);
    BIO_snprintf(pport, sizeof(pport), "%d", ctx->proxyPort);
    cbio = HTTP_new_bio(ctx->serverName, sport, ctx->proxyName, pport);
    return cbio;
}

static HTTP_REQ_CTX *CMP_sendreq_new(BIO *io, const char *host,
                                     const char *path,
                                     const char *server, const char *port,
                                     const OSSL_CMP_MSG *req, int maxline)
{
    HTTP_REQ_CTX *rctx = HTTP_sendreq_new(io, path, server, port,
                                          NULL, NULL, NULL, maxline);

    if (rctx == NULL)
        return NULL;

    if (host != NULL) {
        if (!HTTP_REQ_CTX_add1_header(rctx, "Host", host))
            goto err;
    }
    if (!HTTP_REQ_CTX_add1_header(rctx, "Pragma", "no-cache"))
        goto err;

    if (req != NULL && !HTTP_REQ_CTX_i2d(rctx, "application/pkixcmp",
                                         ASN1_ITEM_rptr(OSSL_CMP_MSG),
                                         (ASN1_VALUE *)req))
        goto err;

    return rctx;

 err:
    HTTP_REQ_CTX_free(rctx);
    return NULL;
}

/*
 * Send out CMP request and get response on blocking or non-blocking BIO
 * returns -4: other, -3: send, -2: receive, or -1: parse error, 0: timeout,
 * 1: success and then provides the received message via the *resp argument
 */
static int CMP_sendreq(BIO *bio, const char *host, const char *path,
                       const char *server, const char *port,
                       const OSSL_CMP_MSG *req, OSSL_CMP_MSG **resp,
                       time_t max_time)
{
    HTTP_REQ_CTX *rctx;
    int rv;

    if ((rctx = CMP_sendreq_new(bio, host, path, server, port, req,
                                -1 /* default max resp line length */)) == NULL)
        return -4;

    rv = HTTP_REQ_CTX_sendreq_d2i(rctx, max_time,
                                  ASN1_ITEM_rptr(OSSL_CMP_MSG),
                                  (ASN1_VALUE **)resp);

    /* this indirectly calls ERR_clear_error(): */
    HTTP_REQ_CTX_free(rctx);

    return rv;
}

/*
 * Send the PKIMessage req and on success place the response in *res.
 * Any previous error is likely to be removed by ERR_clear_error().
 * returns 0 on success, else a CMP error reason code defined in cmp.h
 */
int OSSL_CMP_MSG_http_perform(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req,
                              OSSL_CMP_MSG **res)
{
    int rv;
    char *server_host = NULL;
    char server_port[32];
    char *path = NULL;
    BIO *bio, *hbio = NULL;
    int err = ERR_R_MALLOC_FAILURE;
    time_t max_time;

    if (ctx == NULL || req == NULL || res == NULL
            || ctx->serverName == NULL || ctx->serverPort == 0)
        return CMP_R_NULL_ARGUMENT;

    max_time = ctx->msgtimeout > 0 ? time(NULL) + ctx->msgtimeout : 0;

    if ((hbio = CMP_new_http_bio(ctx)) == NULL)
        goto err;

    /* tentatively set error, which allows accumulating diagnostic info */
    (void)ERR_set_mark();
    CMPerr(0, CMP_R_ERROR_CONNECTING);
    rv = BIO_connect_retry(hbio, ctx->msgtimeout);
    if (rv <= 0) {
        err = (rv == 0) ? CMP_R_CONNECT_TIMEOUT : CMP_R_ERROR_CONNECTING;
        goto err;
    } else {
        (void)ERR_pop_to_mark(); /* discard diagnostic info */
    }

    /* callback can be used to wrap or prepend TLS session */
    if (ctx->http_cb != NULL) {
        if ((bio = (*ctx->http_cb)(ctx, hbio, 1)) == NULL)
            goto err;
        hbio = bio;
    }

    server_port[0] = '\0';
    /*
     * Section 5.1.2 of RFC 1945 states that the absoluteURI form is only
     * allowed when using a proxy
     */
    if (ctx->http_cb == NULL /* no TLS */
            && ctx->proxyName != NULL && ctx->proxyPort != 0) {
        server_host = ctx->serverName;
        BIO_snprintf(server_port, sizeof(server_port), "%d", ctx->serverPort);
    }

    rv = CMP_sendreq(hbio, ctx->serverName, ctx->serverPath,
                     server_host, server_port, req, res, max_time);
    OPENSSL_free(path);
    if (rv == -3)
        err = CMP_R_FAILED_TO_SEND_REQUEST;
    else if (rv == -2)
        err = CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE;
    else if (rv == -1)
        err = CMP_R_ERROR_DECODING_MESSAGE;
    else if (rv == 0) /* timeout */
        err = CMP_R_READ_TIMEOUT;
    else
        err = 0;

 err:
    if (err != 0) {
        if (ERR_GET_LIB(ERR_peek_error()) == ERR_LIB_SSL)
            err = CMP_R_TLS_ERROR;
        CMPerr(0, err);
        if (err == CMP_R_TLS_ERROR || err == CMP_R_CONNECT_TIMEOUT
                || err == CMP_R_ERROR_CONNECTING)
            add_conn_error_hint(ctx, ERR_peek_error());
    }

    if (ctx->http_cb && (*ctx->http_cb)(ctx, hbio, ERR_peek_error()) == NULL)
        err = ERR_R_MALLOC_FAILURE;
    BIO_free_all(hbio); /*
                         * also frees any (e.g., SSL/TLS) BIOs linked with hbio
                         * and, like BIO_reset(hbio), calls SSL_shutdown() to
                         * notify/alert peer
                         */

    return err;
}

int OSSL_CMP_proxy_connect(BIO *bio, OSSL_CMP_CTX *ctx,
                           BIO *bio_err, const char *prog)
{
    char server_port[32];

    BIO_snprintf(server_port, sizeof(server_port), "%d", ctx->serverPort);
    return HTTP_proxy_connect(bio, ctx->serverName, server_port,
                              NULL, NULL, /* no proxy auth */
                              ctx->msgtimeout, bio_err, prog);
}

#endif /* !defined(OPENSSL_NO_SOCK) */
