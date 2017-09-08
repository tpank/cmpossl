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

#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)

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

static void add_TLS_error_hint(const CMP_CTX *ctx, unsigned long errdetail)
{
    char buf[200];
    if (errdetail == 0) {
        snprintf(buf, 200, "server has disconnected%s",
                 ctx->tlsBIO ? " violating the protocol" : ", likely because it requires the use of TLS");
        CMP_add_error_data(buf);
        snprintf(buf, 200, "connecting to '%s' port %d", ctx->serverName, ctx->serverPort);
        CMP_add_error_data(buf);
    } else {
#if 0
        CMP_add_error_data(ERR_lib_error_string(errdetail));
        CMP_add_error_data(ERR_func_error_string(errdetail));
        CMP_add_error_data(ERR_reason_error_string(errdetail));
#endif
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
            CMP_add_error_data("Cannot authenticate the server via its TLS certificate; hint: verify the trusted root certs and cert revocation status if CRLs or OCSP is used");
            break;
    /*  case 0x14094418: */ /* xSL_F_SSL3_READ_BYTES */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
#else
        case SSL_AD_REASON_OFFSET+TLS1_AD_UNKNOWN_CA:
#endif
            CMP_add_error_data("Server did not accept our TLS certificate, likely due to mismatch with server's trust anchor, or missing/invalid CRL");
            break;
        case SSL_AD_REASON_OFFSET+40:
            CMP_add_error_data("Server requires our TLS certificate but did not receive one");
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

/* Exchange CMP request/response via HTTP on (non-)blocking BIO
   returns 1 on success, 0 on error, -1 on BIO_should_retry */
static int CMP_http_nbio(OCSP_REQ_CTX *rctx, ASN1_VALUE **resp)
{
    return OCSP_REQ_CTX_nbio_d2i(rctx, resp, ASN1_ITEM_rptr(CMP_PKIMESSAGE));
}

/* TODO dvo: push that upstream with extended load_cert_crl_http(),
   simplifying also other uses of select(), e.g., in query_responder() in apps/ocsp.c */
/* returns < 0 on error, 0 on timeout, > 0 on success */
int socket_wait(int fd, int for_read, int timeout)
{
    fd_set confds;
    struct timeval tv;

    if (timeout <= 0)
        return 0;

    FD_ZERO(&confds);
    openssl_fdset(fd, &confds);
    tv.tv_usec = 0;
    tv.tv_sec = timeout;
    return select(fd + 1, for_read ? &confds : NULL,
                  for_read ? NULL : &confds, NULL, &tv);
}

/* TODO dvo: push that upstream with extended load_cert_crl_http(),
   simplifying also other uses of select(), e.g., in query_responder() in apps/ocsp.c */
/* returns < 0 on error, 0 on timeout, > 0 on success */
int bio_wait(BIO *bio, int timeout) {
    int fd;
    if (BIO_get_fd(bio, &fd) <= 0)
        return -1;
    return socket_wait(fd, BIO_should_read(bio), timeout);
}

/* TODO dvo: push that upstream with extended load_cert_crl_http(),
   simplifying also other uses of connect(), e.g., in query_responder() in apps/ocsp.c */
/* returns -1 on error, 0 on timeout, 1 on success */
int bio_connect(BIO *bio, int timeout) {
    int blocking;
    time_t max_time;
    int rv;

    blocking = timeout <= 0;
    max_time = timeout > 0 ? time(NULL) + timeout : 0;

/* https://www.openssl.org/docs/man1.1.0/crypto/BIO_should_io_special.html */
    if (!blocking)
        BIO_set_nbio(bio, 1);
 retry: /* it does not help here to set SSL_MODE_AUTO_RETRY */
    rv = BIO_do_connect(bio);
    if (rv <= 0 && (errno == ETIMEDOUT /* in blocking case,
          despite blocking BIO, BIO_do_connect() timed out */ ||
          ERR_GET_REASON(ERR_peek_error()) == ETIMEDOUT/* when non-blocking,
          BIO_do_connect() timed out early with rv == -1 and errno == 0 */)) {
        ERR_clear_error();
        (void)BIO_reset(bio); /* otherwise, blocking next connect() may crash
                             and non-blocking next BIO_do_connect() will fail */
        goto retry;
    }
    if (rv <= 0 && BIO_should_retry(bio)) {
        if (blocking || (rv = bio_wait(bio, max_time - time(NULL))) > 0)
            goto retry;
    }
    return rv;
}

/* TODO dvo: push that upstream with extended load_cert_crl_http(),
   simplifying also other uses of XXX_sendreq_nbio, e.g., in query_responder() in apps/ocsp.c */
/* Even better would be to extend OCSP_REQ_CTX_nbio() and
   thus OCSP_REQ_CTX_nbio_d2i() to include this retry behavior */
/* Exchange ASN.1 request and response via HTTP on any BIO
   returns -4: other, -3: send, -2: receive, or -1: parse error, 0: timeout,
   1: success and then provides the received message via the *resp argument */
int bio_http(BIO *bio/* could be removed if we could access rctx->io */,
             OCSP_REQ_CTX *rctx, http_fn fn, ASN1_VALUE **resp, time_t max_time)
{
    int rv, rc, sending = 1;
    int blocking = max_time == 0;
    ASN1_VALUE *const pattern = (ASN1_VALUE *)-1;

    *resp = pattern; /* used for detecting parse errors */
    do {
        rc = fn(rctx, resp);
        if (rc != -1) {
            if (rc == 0) { /* an error occurred */
                if (sending && !blocking)
                    rv = -3; /* send error */
                else {
                    if (*resp == pattern)
                        rv = -2;/* receive error */
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
            rv = bio_wait(bio, max_time - time(NULL));
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

/* Send out CNP request and get response on blocking or non-blocking BIO
   returns -4: other, -3: send, -2: receive, or -1: parse error, 0: timeout,
   1: success and then provides the received message via the *resp argument */
static int CMP_sendreq(BIO *bio, const char *path, const CMP_PKIMESSAGE *req,
                       CMP_PKIMESSAGE **resp, time_t max_time)
{
    OCSP_REQ_CTX *rctx;
    int rv;

    if (!(rctx = CMP_sendreq_new(bio, path, req, -1)))
        return -4;

    rv = bio_http(bio, rctx, CMP_http_nbio, (ASN1_VALUE **)resp, max_time);

    OCSP_REQ_CTX_free(rctx);

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
    time_t max_time;

    if (!ctx || !req || !res)
        return CMP_R_NULL_ARGUMENT;

    max_time = ctx->msgTimeOut > 0 ? time(NULL) + ctx->msgTimeOut : 0;

    if (!ctx->serverName || !ctx->serverPath || !ctx->serverPort)
        return CMP_R_NULL_ARGUMENT;

    CMP_new_http_bio(&hbio, ctx);
    if (!hbio)
        return CMP_R_OUT_OF_MEMORY;
    cbio = (ctx->tlsBIO) ? BIO_push(ctx->tlsBIO, hbio) : hbio;

    rv = bio_connect(cbio, ctx->msgTimeOut);
    /* BIO_do_connect modifies hbio->prev_bio, which was ctx->tlsBIO - why?? */
    if (rv <= 0) {
        if (rv == 0)
            err = CMP_R_CONNECT_TIMEOUT;
        /* else CMP_R_SERVER_NOT_REACHABLE */
        goto err;
    }

    pathlen = strlen(ctx->serverName) + strlen(ctx->serverPath) + 33;
    path = (char *)OPENSSL_malloc(pathlen);
    if (!path) {
        err = CMP_R_OUT_OF_MEMORY;
        goto err;
    }

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
    OPENSSL_free(path);
    if (rv == -3)
        err = CMP_R_FAILED_TO_SEND_REQUEST;
    else if (rv == -2)
        err = CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE;
    else if (rv == -1)
        err = CMP_R_ERROR_DECODING_MESSAGE;
    else if (rv == 0) { /* timeout */
        /* We should notify/alert the peer when we abort; TODO: does the below BIO_reset suffice?
           We cannot do one of the following because ssl is not available here: SSL_shutdown(ssl);
           or more directly sth like ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_CLOSE_NOTIFY); */
        err = CMP_R_READ_TIMEOUT;
    } else
        err = 0;

 err:
    if (err) {
        if (ERR_GET_LIB(ERR_peek_error()) == ERR_LIB_SSL)
            err = CMP_R_TLS_ERROR;
        CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, err);
        if (err == CMP_R_TLS_ERROR || CMP_R_SERVER_NOT_REACHABLE)
            add_TLS_error_hint(ctx, ERR_peek_error());
    }

    (void)BIO_reset(cbio); /* notify/alert peer, init for potential next use */
    if (ctx->tlsBIO) {
        /* BIO_set_next(cbio, NULL); workaround for altered forward pointer */
        /* Must not pop ctx->tlsBIO or hbio nor do this before reset,
           else ssl_free_wbio_buffer() fails on ossl_assert(s->wbio != NULL) */
    }
    BIO_free(hbio);

    return err;
}

#endif /* !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK) */
