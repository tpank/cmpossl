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

static HTTP_REQ_CTX *CMP_sendreq_new(BIO *bio, const char *host,
                                     const char *path,
                                     const char *server, const char *port,
                                     const OSSL_CMP_MSG *req)
{
    STACK_OF(CONF_VALUE) *headers = NULL;
    HTTP_REQ_CTX *rctx = NULL;

    if (!X509V3_add_value("Pragma", "no-cache", &headers))
        return NULL;

    rctx = HTTP_sendreq_new(bio, path, server, port,
                            headers, host, "application/pkixcmp",
                            ASN1_ITEM_rptr(OSSL_CMP_MSG),
                            (ASN1_VALUE *)req, -1);
    sk_CONF_VALUE_pop_free(headers, X509V3_conf_free);
    return rctx;
}

/* Send out CMP request and get response on blocking or non-blocking BIO */
static OSSL_CMP_MSG *CMP_sendreq(BIO *bio, const char *host, const char *path,
                       const char *server, const char *port,
                       const OSSL_CMP_MSG *req, time_t max_time)
{
    HTTP_REQ_CTX *rctx;
    OSSL_CMP_MSG *re;

    if ((rctx = CMP_sendreq_new(bio, host, path, server, port, req)) == NULL)
        return NULL;

    re = (OSSL_CMP_MSG *)HTTP_REQ_CTX_sendreq_d2i(rctx, max_time,
                                                  ASN1_ITEM_rptr(OSSL_CMP_MSG));

    /* this indirectly calls ERR_clear_error(): */
    HTTP_REQ_CTX_free(rctx);

    return re;
}

/*
 * Send the PKIMessage req and on success place the response in *res.
 * Any previous error is likely to be removed by ERR_clear_error().
 */
OSSL_CMP_MSG *OSSL_CMP_MSG_http_perform(OSSL_CMP_CTX *ctx,
                                        const OSSL_CMP_MSG *req)
{
    char *server_host = NULL;
    char server_port[32];
    BIO *bio, *hbio = NULL;
    time_t max_time;
    OSSL_CMP_MSG *res = NULL;

    if (ctx == NULL || req == NULL || res == NULL
            || ctx->serverName == NULL || ctx->serverPort == 0) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    max_time = ctx->msgtimeout > 0 ? time(NULL) + ctx->msgtimeout : 0;

    if ((hbio = CMP_new_http_bio(ctx)) == NULL)
        goto err;

    if (BIO_connect_retry(hbio, ctx->msgtimeout) <= 0)
        goto err;

    /* callback can be used to wrap or prepend TLS session */
    if (ctx->http_cb != NULL) {
        bio = (*ctx->http_cb)(ctx, hbio, 1);
        if (bio == NULL)
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

    res = CMP_sendreq(hbio, ctx->serverName, ctx->serverPath,
                      server_host, server_port, req, max_time);

 err:
    if (res == NULL) {
        if (ERR_GET_LIB(ERR_peek_error()) == ERR_LIB_SSL
                || ERR_GET_REASON(ERR_peek_error()) == BIO_R_CONNECT_TIMEOUT
                || ERR_GET_REASON(ERR_peek_error()) == BIO_R_CONNECT_ERROR)
            add_conn_error_hint(ctx, ERR_peek_error());
    }

    if (ctx->http_cb != NULL
            && (*ctx->http_cb)(ctx, hbio, ERR_peek_error()) == NULL) {
        OSSL_CMP_MSG_free(res);
        res = NULL;
    }
    BIO_free_all(hbio); /*
                         * also frees any (e.g., SSL/TLS) BIOs linked with hbio
                         * and, like BIO_reset(hbio), calls SSL_shutdown() to
                         * notify/alert peer
                         */

    return res;
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
