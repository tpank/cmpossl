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

/*
 * one declaration and two defines copied from ocsp_ht.c - keep in sync!
 * These have been copied just to get access to* internal state variable;
 * TODO better avoid this by pushing upstream the below code using them
 */
struct http_req_ctx_st
{
    int state;                  /* Current I/O state */
    unsigned char *iobuf;       /* Line buffer */
    int iobuflen;               /* Line buffer length */
    BIO *io;                    /* BIO to perform I/O with */
    BIO *mem;                   /* Memory BIO response is built into */
    unsigned long asn1_len;     /* ASN1 length of response */
    unsigned long max_resp_len; /* Maximum length of response */
};

/* TODO DvO: push this upstream with extended load_cert_crl_http() */
typedef int (*http_fn)(HTTP_REQ_CTX *rctx, ASN1_VALUE **resp);
/*
 * Even better would be to extend HTTP_REQ_CTX_nbio() and
 * thus HTTP_REQ_CTX_nbio_d2i() to include this retry behavior
 */
/*
 * Exchange ASN.1 request and response via HTTP on any BIO
 * returns -4: other, -3: send, -2: receive, or -1: parse error, 0: timeout,
 * 1: success and then provides the received message via the *resp argument
 */
static int bio_http(HTTP_REQ_CTX *rctx, http_fn fn, ASN1_VALUE **resp,
                    time_t max_time)
{
    int rv = -4, rc, sending = 1;
    int blocking = max_time == 0;
    ASN1_VALUE *const pattern = (ASN1_VALUE *)-1;

    *resp = pattern; /* used for detecting parse errors */

    do {
        rc = (*fn)(rctx, resp);
        if (rc != -1) {
            if (rc == 0) { /* an error occurred */
                if (sending && !blocking) {
                    rv = -3; /* send error */
                } else {
                    if (*resp == pattern)
                        rv = -2; /* receive error */
                    else
                        rv = -1; /* parse error */
                }
                *resp = NULL;
            }
            break;
        }
        /* else BIO_should_retry was true */
        sending = 0;
        if (!blocking) {
            rv = BIO_wait(rctx->io, max_time - time(NULL));
            if (rv <= 0) { /* error or timeout */
                if (rv < 0) /* error */
                    rv = -4;
                *resp = NULL;
                break;
            }
        }
    } while (rc == -1); /* BIO_should_retry was true */

    return rv;
}

static int CMP_REQ_CTX_i2d(HTTP_REQ_CTX *rctx, const OSSL_CMP_MSG *req)
{
    return HTTP_REQ_CTX_i2d(rctx, "application/pkixcmp",
                            ASN1_ITEM_rptr(OSSL_CMP_MSG), (ASN1_VALUE *)req);
}

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

    if (!ossl_assert(ctx != NULL))
        return NULL;


    host = ctx->proxyName;
    port = ctx->proxyPort;

    if (host == NULL || port == 0) {
        host = ctx->serverName;
        port = ctx->serverPort;
    }
    cbio = BIO_new_connect(host);
    if (cbio == NULL)
        goto end;
    BIO_snprintf(buf, sizeof(buf), "%d", port);
    (void)BIO_set_conn_port(cbio, buf);

 end:
    return cbio;
}

static HTTP_REQ_CTX *CMP_sendreq_new(BIO *io, const char *host,
                                     const char *path, const OSSL_CMP_MSG *req,
                                     int maxline)
{
    HTTP_REQ_CTX *rctx = NULL;

    rctx = HTTP_REQ_CTX_new(io, maxline);
    if (rctx == NULL)
        return NULL;

    if (!HTTP_REQ_CTX_http(rctx, "POST", path))
        goto err;
    if (host != NULL) {
        if (!HTTP_REQ_CTX_add1_header(rctx, "Host", host))
            goto err;
    }
    if (!HTTP_REQ_CTX_add1_header(rctx, "Pragma", "no-cache"))
        goto err;

    if (req != NULL && !CMP_REQ_CTX_i2d(rctx, req))
        goto err;

    return rctx;

 err:
    HTTP_REQ_CTX_free(rctx);
    return NULL;
}

/*
 * Exchange CMP request/response via HTTP on (non-)blocking BIO
 * returns 1 on success, 0 on error, -1 on BIO_should_retry
 */
static int CMP_http_nbio(HTTP_REQ_CTX *rctx, ASN1_VALUE **resp)
{
    return HTTP_REQ_CTX_nbio_d2i(rctx, resp, ASN1_ITEM_rptr(OSSL_CMP_MSG));
}

/*
 * Send out CMP request and get response on blocking or non-blocking BIO
 * returns -4: other, -3: send, -2: receive, or -1: parse error, 0: timeout,
 * 1: success and then provides the received message via the *resp argument
 */
static int CMP_sendreq(BIO *bio, const char *host, const char *path,
                       const OSSL_CMP_MSG *req, OSSL_CMP_MSG **resp,
                       time_t max_time)
{
    HTTP_REQ_CTX *rctx;
    int rv;

    if ((rctx = CMP_sendreq_new(bio, host, path, req, -1)) == NULL)
        return -4;

    rv = bio_http(rctx, CMP_http_nbio, (ASN1_VALUE **)resp, max_time);

    /* This indirectly calls ERR_clear_error(); */
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
    char *server_path;
    char *path = NULL;
    size_t pos = 0, pathlen = 0;
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

    server_path = ctx->serverPath == NULL ? "" : ctx->serverPath;
    pathlen = strlen(ctx->serverName) + strlen(server_path) + 33;
    path = OPENSSL_malloc(pathlen);
    if (path == NULL)
        goto err;

    /*
     * Section 5.1.2 of RFC 1945 states that the absoluteURI form is only
     * allowed when using a proxy
     */
    if (ctx->http_cb == NULL /* no TLS */
            && ctx->proxyName != NULL && ctx->proxyPort != 0)
        pos = BIO_snprintf(path, pathlen-1, "http://%s:%d",
                           ctx->serverName, ctx->serverPort);

    /* make sure path includes a forward slash */
    if (server_path[0] != '/')
        path[pos++] = '/';

    BIO_snprintf(path + pos, pathlen - pos - 1, "%s", server_path);

    rv = CMP_sendreq(hbio, ctx->serverName, path, req, res, max_time);
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

/*
 * adapted from apps/lib/apps.c to include connection timeout
 * TODO DvO: push this improved version upstream
 */
int OSSL_CMP_load_cert_crl_http_timeout(const char *url, int req_timeout,
                                        X509 **pcert, X509_CRL **pcrl,
                                        BIO *bio_err)
{
    char *host = NULL;
    char *port = NULL;
    char *path = NULL;
    BIO *bio = NULL;
    HTTP_REQ_CTX *rctx = NULL;
    int use_ssl;
    int rv = -4;
    time_t max_time = req_timeout > 0 ? time(NULL) + req_timeout : 0;
    http_fn fn =
        pcert != NULL ? (http_fn)X509_http_nbio : (http_fn)X509_CRL_http_nbio;
    ASN1_VALUE **presp =
        pcert != NULL ? (ASN1_VALUE **)pcert : (ASN1_VALUE **)pcrl;

    if (!HTTP_parse_url(url, &host, &port, &path, &use_ssl))
        goto err;
    if (use_ssl) {
        BIO_puts(bio_err, "https not supported for CRL fetching\n");
        goto err;
    }
    bio = BIO_new_connect(host);
    if (bio == NULL || !BIO_set_conn_port(bio, port))
        goto err;

    if (BIO_connect_retry(bio, req_timeout) <= 0)
        goto err;

    rctx = HTTP_REQ_CTX_new(bio, 1024);
    if (rctx == NULL)
        goto err;
    if (!HTTP_REQ_CTX_http(rctx, "GET", path))
        goto err;
    if (!HTTP_REQ_CTX_add1_header(rctx, "Host", host))
        goto err;

    rv = bio_http(rctx, fn, presp, max_time);

 err:
    OPENSSL_free(host);
    OPENSSL_free(path);
    OPENSSL_free(port);
    BIO_free_all(bio);
    HTTP_REQ_CTX_free(rctx);
    if (rv != 1) {
        BIO_printf(bio_err, "%s loading %s from '%s'\n",
                   rv == 0 ? "timeout" :
                   rv == -1 ? "parse Error" : "transfer error",
                   pcert != NULL ? "certificate" : "CRL", url);
        ERR_print_errors(bio_err);
    }
    return rv;
}

int OSSL_CMP_proxy_connect(BIO *bio, OSSL_CMP_CTX *ctx,
                           BIO *bio_err, const char *prog)
{
    return HTTP_proxy_connect(bio, ctx->serverName, ctx->serverPort,
                              ctx->msgtimeout, bio_err, prog);
}

#endif /* !defined(OPENSSL_NO_SOCK) */
