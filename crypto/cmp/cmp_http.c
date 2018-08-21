/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "e_os.h"
#include <openssl/cmp.h>
#include <openssl/ocsp.h>

#include <fcntl.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "cmp_int.h"

#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)

static void add_conn_error_hint(const OSSL_CMP_CTX *ctx, unsigned long errdetail)
{
    char buf[200];
    snprintf(buf, 200, "connecting to '%s' port %d", ctx->serverName,
             ctx->serverPort);
    OSSL_CMP_add_error_data(buf);
    if (errdetail == 0) {
        snprintf(buf, 200, "server has disconnected%s",
                 ctx->http_cb_arg != NULL ? " violating the protocol" :
                               ", likely because it requires the use of TLS");
        OSSL_CMP_add_error_data(buf);
    }
}

/*
 * internal function
 * Create a new http connection, with a specified source ip/interface
 * returns the created BIO or NULL on failure
 */
static BIO *CMP_new_http_bio(const OSSL_CMP_CTX *ctx)
{
    char *host;
    int port;
    BIO *cbio = NULL;
    char buf[32];

    if (ctx == NULL)
        goto end;

    host = ctx->proxyName;
    port = ctx->proxyPort;
    if (host == NULL || port == 0) {
        host = ctx->serverName;
        port = ctx->serverPort;
    }
    cbio = BIO_new_connect(host);
    if (cbio == NULL)
        goto end;
    snprintf(buf, sizeof(buf), "%d", port);
    (void)BIO_set_conn_port(cbio, buf);

 end:
    return cbio;
}

static OCSP_REQ_CTX *CMP_sendreq_new(BIO *io, const char *path,
                                     const OSSL_CMP_MSG *req,
                                     int maxline, int timeout)
{
    static const char req_hdr[] =
        "Content-Type: application/pkixcmp\r\n"
        "Cache-Control: no-cache\r\n" "Content-Length: %d\r\n\r\n";
    OCSP_REQ_CTX *rctx = NULL;

    rctx = OCSP_REQ_CTX_new(io, maxline, timeout);
    if (rctx == NULL)
        return NULL;

    if (!OCSP_REQ_CTX_add1_http(rctx, "POST", path))
        goto err;

    if (req != NULL &&
        !OCSP_REQ_CTX_i2d(rctx, req_hdr, ASN1_ITEM_rptr(OSSL_CMP_MSG),
                          (ASN1_VALUE *)req))
        goto err;

    return rctx;

 err:
    OCSP_REQ_CTX_free(rctx);
    return NULL;
}

/*
 * Send the PKIMessage req and on success place the response in *res.
 * Any previous error is likely to be removed by ERR_clear_error().
 * returns 0 on success, else a CMP error reason code defined in cmp.h
 */
int OSSL_CMP_MSG_http_perform(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req,
                              OSSL_CMP_MSG **res)
{
    int rv = 0;
    char *path = NULL;
    size_t pos = 0, pathlen = 0;
    BIO *hbio = NULL;
    OCSP_REQ_CTX *rctx;
    int err = ERR_R_MALLOC_FAILURE;
    int retries = 1;

    if (ctx == NULL || req == NULL || res == NULL ||
        ctx->serverName == NULL || ctx->serverPath == NULL || !ctx->serverPort)
        return CMP_R_NULL_ARGUMENT;

    pathlen = strlen(ctx->serverName) + strlen(ctx->serverPath) + 33;
    path = (char *)OPENSSL_malloc(pathlen);
    if (path == NULL)
        goto err;

    /*
     * Section 5.1.2 of RFC 1945 states that the absoluteURI form is only
     * allowed when using a proxy
     */
    if (ctx->proxyName != NULL && ctx->proxyPort != 0)
        pos = BIO_snprintf(path, pathlen-1, "http://%s:%d",
                           ctx->serverName, ctx->serverPort);

    /* make sure path includes a forward slash */
    if (ctx->serverPath[0] != '/')
        path[pos++] = '/';
    BIO_snprintf(path + pos, pathlen - pos - 1, "%s", ctx->serverPath);

 retry:
    if ((hbio = CMP_new_http_bio(ctx)) == NULL)
        goto err;
    if (ctx->http_cb != NULL) {
        BIO *bio = (*ctx->http_cb)(ctx, hbio, 1/* connecting */);
        if (bio == NULL)
            goto err;
        hbio = bio;
    }

    if ((rctx = CMP_sendreq_new(hbio, path, req, -1, ctx->msgtimeout)) == NULL)
        goto err;
    rv = OCSP_REQ_CTX_sendreq(rctx);  /* indirectly calls ERR_clear_error(); */
    if (rv == 1 && ((*res = OCSP_REQ_CTX_D2I(rctx, OSSL_CMP_MSG)) == NULL))
        rv = 0;
    OCSP_REQ_CTX_free(rctx);
    if (rv == 1) {
        err = 0;
    } else {
        err = ERR_GET_REASON(ERR_peek_last_error());
        if (err == 0)
            err = ERR_R_INTERNAL_ERROR;
    }

 err: /* TODO DvO clean up error reporting */
    /* for any cert verify error at TLS level: */
    put_cert_verify_err(CMP_F_OSSL_CMP_MSG_HTTP_PERFORM);

    if (err != 0) {
        if (ERR_GET_LIB(ERR_peek_error()) == ERR_LIB_SSL)
            err = CMP_R_TLS_ERROR;
        CMPerr(CMP_F_OSSL_CMP_MSG_HTTP_PERFORM, err);
        if (err != ERR_R_MALLOC_FAILURE)
            add_conn_error_hint(ctx, ERR_peek_error());
    }

    if (ctx->http_cb != NULL)
        (void)(*ctx->http_cb)(ctx, hbio, ERR_peek_error());
    BIO_free_all(hbio); /* also frees any (e.g., SSL/TLS) BIOs linked with hbio
       and, like BIO_reset(hbio), calls SSL_shutdown() to notify/alert peer */

    /* On HTTP status 503 indicating server overload, wait for 5 seconds
       then retry at most 'retries' times */
    if (--retries >= 0 && rv == 503) {
        sleep(5);
        goto retry;
    }

    OPENSSL_free(path);
    return err;
}

#endif /* !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK) */
