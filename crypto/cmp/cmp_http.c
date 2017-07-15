/* crypto/cmp/cmp_http.c
 * HTTP functions for CMP (RFC 4210) for OpenSSL
 */
/* ====================================================================
 * Originally written by Martin Peylo for the OpenSSL project.
 * <martin dot peylo at nsn dot com>
 * 2010-2013 Miikka Viljanen <mviljane@users.sourceforge.net>
 *
 * HTTP code taken from crypto/ocsp/ocsp_ht.c, written by
 * Dr Stephen N Henson (steve@openssl.org)
 */
/* ====================================================================
 * Copyright (c) 2007-2010 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in
 *        the documentation and/or other materials provided with the
 *        distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *        software must display the following acknowledgment:
 *        "This product includes software developed by the OpenSSL Project
 *        for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *        endorse or promote products derived from this software without
 *        prior written permission. For written permission, please contact
 *        openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *        nor may "OpenSSL" appear in their names without prior written
 *        permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *        acknowledgment:
 *        "This product includes software developed by the OpenSSL Project
 *        for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 */
/* ====================================================================
 * Copyright 2007-2014 Nokia Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by
 * Nokia for contribution to the OpenSSL project.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "e_os.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <ctype.h>
#include <fcntl.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "cmp_int.h"

typedef BIO CMPBIO;

/* from apps.h */
# ifndef openssl_fdset
#  ifdef OPENSSL_SYSNAME_WIN32
#   define openssl_fdset(a,b) FD_SET((unsigned int)a, b)
#  else
#   define openssl_fdset(a,b) FD_SET(a, b)
#  endif
# endif

static void print_error_hint(const CMP_CTX *ctx, unsigned long errdetail)
{
    char buf[200];
    if (errdetail == 0) {
        snprintf(buf, 200, "server has disconnected%s",
                 ctx->tlsBIO ? " violating the protocol" : ", likely because it requires the use of TLS");
        CMP_add_error_data(buf);
        snprintf(buf, 200, "connecting to '%s' port %d", ctx->serverName, ctx->serverPort);
        CMP_add_error_data(buf);
    } else {
        CMP_add_error_data(ERR_lib_error_string(errdetail));
        CMP_add_error_data(ERR_func_error_string(errdetail));
        CMP_add_error_data(ERR_reason_error_string(errdetail));

        switch(ERR_GET_REASON(errdetail)) {
    /*  case 0x1408F10B: */ /* xSL_F_SSL3_GET_RECORD */
        case SSL_R_WRONG_VERSION_NUMBER:
    /*  case 0x140770FC: */ /* xSL_F_SSL23_GET_SERVER_HELLO */
        case SSL_R_UNKNOWN_PROTOCOL:
            CMP_add_error_data("The server does not support (a recent version of) TLS");
            break;
    /*  case 0x1407E086: */ /* xSL_F_SSL3_GET_SERVER_HELLO */
    /*  case 0x1409F086: */ /* xSL_F_SSL3_WRITE_PENDING */
    /*  case 0x14090086: */ /* xSL_F_SSL3_GET_SERVER_CERTIFICATE */
    /*  case 0x1416F086: */ /* xSL_F_TLS_PROCESS_SERVER_CERTIFICATE */
        case SSL_R_CERTIFICATE_VERIFY_FAILED:
            CMP_add_error_data("Cannot authenticate the server via its TLS certificate; hint: verify the trusted TLS certs");
            break;
    /*  case 0x14094418: */ /* xSL_F_SSL3_READ_BYTES */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
#else
        case SSL_AD_REASON_OFFSET+TLS1_AD_UNKNOWN_CA:
#endif
            CMP_add_error_data("Server did not accept our TLS certificate, likely due to mismatch with server's trust anchor, or missing/invalid CRL");
            break;
        default:
            break;
        }
    }
}

/* one declaration and three defines copied from ocsp_ht.c; keep in sync! */
struct ocsp_req_ctx_st { /* dummy declaration to get access to internal state variable */
    int state;                  /* Current I/O state */
    unsigned char *iobuf;       /* Line buffer */
    int iobuflen;               /* Line buffer length */
    BIO *io;                    /* BIO to perform I/O with */
    BIO *mem;                   /* Memory BIO response is built into */
};
#define OHS_NOREAD              0x1000
#define OHS_ASN1_WRITE_INIT     (5 | OHS_NOREAD)

/* adapted from OCSP_REQ_CTX_i2d in crypto/ocsp/ocsp_ht.c - TODO: generalize the function there */
static int OCSP_REQ_CTX_i2d_hdr(OCSP_REQ_CTX *rctx, const char *req_hdr, const ASN1_ITEM *it, ASN1_VALUE *val)
{
    int reqlen = ASN1_item_i2d(val, NULL, it);
    if (BIO_printf(rctx->mem, req_hdr, reqlen) <= 0)
        return 0;
    if (ASN1_item_i2d_bio(it, rctx->mem, val) <= 0)
        return 0;
    rctx->state = OHS_ASN1_WRITE_INIT;
    return 1;
}

/* ########################################################################## *
 * internal function
 * Create a new http connection, with a specified source ip/interface
 * returns 1 on success, 0 on error, returns the created bio inside the *bio
 * argument
 * ########################################################################## */
static int CMP_new_http_bio(CMPBIO ** bio, const CMP_CTX *ctx)
{
    BIO *cbio = NULL;

    if (!ctx)
        goto err;

    if (!ctx->proxyName || !ctx->proxyPort) {
        char buf[32];
        cbio = BIO_new_connect(ctx->serverName);
        if (!cbio)
            goto err;
        snprintf(buf, sizeof(buf), "%d", ctx->serverPort);
        BIO_set_conn_port(cbio, buf);
    } else {
        char buf[32];
        cbio = BIO_new_connect(ctx->proxyName);
        if (!cbio)
            goto err;
        snprintf(buf, sizeof(buf), "%d", ctx->proxyPort);
        BIO_set_conn_port(cbio, buf);
    }

    *bio = cbio;
    return 1;

 err:
    return 0;
}

static OCSP_REQ_CTX *CMP_sendreq_new(BIO *io, const char *path, const CMP_PKIMESSAGE *req,
                               int maxline)
{
    static const char req_hdr[] =
        "Content-Type: application/pkixcmp\r\n"
        "Cache-control: no-cache\r\n" "Content-Length: %d\r\n\r\n";
    OCSP_REQ_CTX *rctx = NULL;

    rctx = OCSP_REQ_CTX_new(io, maxline);
    if (!rctx)
        return NULL;

    if (!OCSP_REQ_CTX_http(rctx, "POST", path))
        goto err;

    if (req && !OCSP_REQ_CTX_i2d_hdr(rctx, req_hdr, ASN1_ITEM_rptr(CMP_PKIMESSAGE),
                                 (ASN1_VALUE *)req))
        goto err;

    return rctx;

 err:
    OCSP_REQ_CTX_free(rctx);
    return NULL;
}

/* returns 1 on success, 0 on error, -1 on BIO_should_retry */
static int CMP_sendreq_nbio(CMP_PKIMESSAGE **presp, OCSP_REQ_CTX *rctx)
{
    return OCSP_REQ_CTX_nbio_d2i(rctx,
                                 (ASN1_VALUE **)presp,
                                 ASN1_ITEM_rptr(CMP_PKIMESSAGE));
}

static int wait(BIO *bio, int for_read, int max_seconds)
{
    int fd;
    fd_set confds;
    struct timeval tv;

    if (BIO_get_fd(bio, &fd) <= 0)
        return -2;

    FD_ZERO(&confds);
    openssl_fdset(fd, &confds);
    tv.tv_usec = 0;
    tv.tv_sec = max_seconds;
    return select(fd + 1, for_read ? &confds : NULL,
                  for_read ? NULL : &confds, NULL, &tv);
}

/* returns -1 on timeout, 0 on send/receive error, else
   provides the received message (or NULL on result parse error) via the *out argument */
static int CMP_sendreq(BIO *bio, const char *path, const CMP_PKIMESSAGE *req, CMP_PKIMESSAGE **out, time_t max_time)
{
    OCSP_REQ_CTX *ctx;
    int rv, rc;

    if (!(ctx = CMP_sendreq_new(bio, path, req, -1)))
        return 0;

    for (;;) {
        rv = CMP_sendreq_nbio(out, ctx);
        if (rv != -1)
            break;
        /* BIO_should_retry was true */
        if (max_time != 0) { /* non-blocking mode */
            int max_seconds = max_time - time(NULL);
            if (max_seconds <= 0) /* timeout */
                break;
            rc = wait(bio, BIO_should_read(bio), max_seconds);
            if (rc == 0) /* timeout */
            break;
            if (rc < 0) { /* select error */
                rc = 0;
                break;
            }
        }
    }

    OCSP_REQ_CTX_free(ctx);

    return rv;
}

/* ################################################################ *
 * Send the PKIMessage req and on success place the response in *res.
 * returns 0 on success, else a CMP error reason code defined in cmp.h
 * ################################################################ */

int CMP_PKIMESSAGE_http_perform(const CMP_CTX *ctx,
                                const CMP_PKIMESSAGE *req,
                                CMP_PKIMESSAGE **res)
{
    int rv;
    char *path = 0;
    size_t pos = 0, pathlen = 0;
    CMPBIO *cbio = NULL;
    CMPBIO *hbio = NULL;
    int err = CMP_R_SERVER_NOT_REACHABLE;
    int blocking = ctx->msgTimeOut == 0;
    time_t max_time = ctx->msgTimeOut != 0 ? time(NULL) + ctx->msgTimeOut : 0;

    if (!ctx || !req || !res)
        return CMP_R_NULL_ARGUMENT;

    if (!ctx->serverName || !ctx->serverPath || !ctx->serverPort)
        return CMP_R_NULL_ARGUMENT;

    CMP_new_http_bio(&hbio, ctx);
    if (!hbio)
        return CMP_R_NULL_ARGUMENT; /* better: out of memory */

    cbio = (ctx->tlsBIO) ? BIO_push(ctx->tlsBIO, hbio) : hbio;

    if (!blocking)
        BIO_set_nbio(cbio, 1);
    rv = BIO_do_connect(cbio);
    if (rv <= 0 && (blocking || !BIO_should_retry(cbio)))
        goto err; /* Error connecting */

    if (!blocking && rv <= 0) {
        rv = wait(cbio, 0, ctx->msgTimeOut);
        if (rv <= 0) {
            err = (rv == 0) ? CMP_R_CONNECT_TIMEOUT :
                              CMP_R_SERVER_NOT_REACHABLE; /* the right error to return? */
            goto err;
        }
    }

    pathlen = strlen(ctx->serverName) + strlen(ctx->serverPath) + 33;
    path = (char *)OPENSSL_malloc(pathlen);
    if (!path)
        goto err; /* is CMP_R_SERVER_NOT_REACHABLE the right error to return? */


    /* Section 5.1.2 of RFC 1945 states that the absoluteURI form is only
     * allowed when using a proxy */
    if (ctx->proxyName && ctx->proxyPort)
        pos = BIO_snprintf(path, pathlen-1, "http%s://%s:%d",
                           ctx->tlsBIO ? "s" : "", ctx->serverName, ctx->serverPort);

    /* make sure path includes a forward slash */
    if (ctx->serverPath[0] != '/')
        path[pos++] = '/';

    BIO_snprintf(path + pos, pathlen - pos - 1, "%s", ctx->serverPath);

    rv = CMP_sendreq(cbio, path, req, res, max_time);
    if (rv == -1)
        err = CMP_R_READ_TIMEOUT;
    else if (rv == 0)
        err = CMP_R_FAILED_TO_SEND_REQUEST;
    else
        err = (*res == NULL) ? CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE : 0;

    OPENSSL_free(path);

    (void) BIO_reset(cbio);
    if (ctx->tlsBIO) {
        BIO_pop(ctx->tlsBIO);
    }

 err:
    BIO_free(hbio);
    if (err) {
        CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, err);
        if (err != CMP_R_SERVER_NOT_REACHABLE)
            print_error_hint(ctx, ERR_peek_error());
    }

    return err;
}

