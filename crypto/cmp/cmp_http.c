/*
 * Copyright 2007-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

#include <string.h>
#include <stdio.h>
#ifndef _WIN32
# include <unistd.h>
#else
# include <winsock.h> /* for type fd_set */
#endif

#include <openssl/asn1t.h>
#include <openssl/ocsp.h>

#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/cmp.h>
#include <openssl/err.h>


#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)

/* from apps.h */
# ifndef openssl_fdset
#  if defined(OPENSSL_SYSNAME_WIN32) \
   || defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WINCE)
#   define openssl_fdset(a,b) FD_SET((unsigned int)a, b)
#  else
#   define openssl_fdset(a,b) FD_SET(a, b)
#  endif
# endif

/* from bio_sock.c */
/*
 * Wait on fd at most until max_time; succeed immediately if max_time == 0.
 * If for_read == 0 then assume to wait for writing, else wait for reading.
 * Returns -1 on error, 0 on timeout, and 1 on success.
 */
static int BIO_socket_wait(int fd, int for_read, time_t max_time)
{
    fd_set confds;
    struct timeval tv;
    time_t now;

    if (fd < 0 || fd >= FD_SETSIZE)
        return -1;
    if (max_time == 0)
        return 1;

    now = time(NULL);
    if (max_time <= now)
        return 0;

    FD_ZERO(&confds);
    openssl_fdset(fd, &confds);
    tv.tv_usec = 0;
    tv.tv_sec = (long)(max_time - now); /* might overflow */
    return select(fd + 1, for_read ? &confds : NULL,
                  for_read ? NULL : &confds, NULL, &tv);
}

/* from bio_lib.c */
/* Internal variant of the below BIO_wait() not calling BIOerr() */
static int bio_wait(BIO *bio, time_t max_time, unsigned int nap_milliseconds)
{
#ifndef OPENSSL_NO_SOCK
    int fd;
#endif
    long sec_diff;

    if (max_time == 0) /* no timeout */
        return 1;

#ifndef OPENSSL_NO_SOCK
    if (BIO_get_fd(bio, &fd) > 0 && fd < FD_SETSIZE)
        return BIO_socket_wait(fd, BIO_should_read(bio), max_time);
#endif
    /* fall back to polling since no sockets are available */

    sec_diff = (long)(max_time - time(NULL)); /* might overflow */
    if (sec_diff < 0)
        return 0; /* clearly timeout */

    /* now take a nap at most the given number of milliseconds */
    if (sec_diff == 0) { /* we are below the 1 seconds resolution of max_time */
        if (nap_milliseconds > 1000)
            nap_milliseconds = 1000;
    } else { /* for sec_diff > 0, take min(sec_diff * 1000, nap_milliseconds) */
        if ((unsigned long)sec_diff * 1000 < nap_milliseconds)
            nap_milliseconds = (unsigned int)sec_diff * 1000;
    }
    ossl_sleep(nap_milliseconds);
    return 1;
}

/* from bio_lib.c */
/*-
 * Wait on (typically socket-based) BIO at most until max_time.
 * Succeed immediately if max_time == 0.
 * If sockets are not available support polling: succeed after waiting at most
 * the number of nap_milliseconds in order to avoid a tight busy loop.
 * Call BIOerr(...) on timeout or error.
 * Returns -1 on error, 0 on timeout, and 1 on success.
 */
static int BIO_wait(BIO *bio, time_t max_time, unsigned int nap_milliseconds)
{
    int rv = bio_wait(bio, max_time, nap_milliseconds);

    if (rv <= 0)
        ERR_raise(ERR_LIB_BIO,
                  rv == 0 ? BIO_R_TRANSFER_TIMEOUT : BIO_R_TRANSFER_ERROR);
    return rv;
}

/* from bio_lib.c */
/*
 * Connect via given BIO using BIO_do_connect() until success/timeout/error.
 * Parameter timeout == 0 means no timeout, < 0 means exactly one try.
 * For non-blocking and potentially even non-socket BIOs perform polling with
 * the given density: between polls sleep nap_milliseconds using BIO_wait()
 * in order to avoid a tight busy loop.
 * Returns -1 on error, 0 on timeout, and 1 on success.
 */
static int BIO_do_connect_retry(BIO *bio, int timeout, int nap_milliseconds)
{
    int blocking = timeout <= 0;
    time_t max_time = timeout > 0 ? time(NULL) + timeout : 0;
    int rv;

    if (bio == NULL) {
        ERR_raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    if (nap_milliseconds < 0)
        nap_milliseconds = 100;
    BIO_set_nbio(bio, !blocking);

 retry:
    ERR_set_mark();
    rv = BIO_do_connect(bio);

    if (rv <= 0) { /* could be timeout or retryable error or fatal error */
        int err = ERR_peek_last_error();
        int reason = ERR_GET_REASON(err);
        int do_retry = BIO_should_retry(bio); /* may be 1 only if !blocking */

        if (ERR_GET_LIB(err) == ERR_LIB_BIO) {
            switch (reason) {
            case ERR_R_SYS_LIB:
                /*
                 * likely retryable system error occurred, which may be
                 * EAGAIN (resource temporarily unavailable) some 40 secs after
                 * calling getaddrinfo(): Temporary failure in name resolution
                 * or a premature ETIMEDOUT, some 30 seconds after connect()
                 */
            case BIO_R_CONNECT_ERROR:
            case BIO_R_NBIO_CONNECT_ERROR:
                /* some likely retryable connection error occurred */
                (void)BIO_reset(bio); /* often needed to avoid retry failure */
                do_retry = 1;
                break;
            default:
                break;
            }
        }
        if (timeout >= 0 && do_retry) {
            ERR_pop_to_mark();
            /* will not actually wait if timeout == 0 (i.e., blocking BIO): */
            rv = bio_wait(bio, max_time, nap_milliseconds);
            if (rv > 0)
                goto retry;
            ERR_raise(ERR_LIB_BIO,
                      rv == 0 ? BIO_R_CONNECT_TIMEOUT : BIO_R_CONNECT_ERROR);
        } else {
            ERR_clear_last_mark();
            rv = -1;
            if (err == 0) /* missing error queue entry */
                /* workaround: general error */
                ERR_raise(ERR_LIB_BIO, BIO_R_CONNECT_ERROR);
        }
    } else {
        ERR_clear_last_mark();
    }

    return rv;
}

/* from http_client.c */
/* BASE64 encoder used for encoding basic proxy authentication credentials */
static char *base64encode(const void *buf, size_t len)
{
    int i;
    size_t outl;
    char *out;

    /* Calculate size of encoded data */
    outl = (len / 3);
    if (len % 3 > 0)
        outl++;
    outl <<= 2;
    out = OPENSSL_malloc(outl + 1);
    if (out == NULL)
        return 0;

    i = EVP_EncodeBlock((unsigned char *)out, buf, len);
    if (!ossl_assert(0 <= i && (size_t)i <= outl)) {
        OPENSSL_free(out);
        return NULL;
    }
    return out;
}

/* from http_client.c */
#define HAS_PREFIX(str, prefix) (strncmp(str, prefix, sizeof(prefix) - 1) == 0)
#define HTTP_PREFIX "HTTP/"
#define HTTP_VERSION_PATT "1." /* allow 1.x */
#define HTTP_VERSION_STR_LEN sizeof(HTTP_VERSION_PATT) /* == strlen("1.0") */
#define HTTP_PREFIX_VERSION HTTP_PREFIX""HTTP_VERSION_PATT
#define HTTP_1_0 HTTP_PREFIX_VERSION"0" /* "HTTP/1.0" */
#define HTTP_LINE1_MINLEN (sizeof(HTTP_PREFIX_VERSION "x 200\n") - 1)
#define OSSL_HTTP_PORT "80"
#define OSSL_HTTPS_PORT "443"

/* from http_client.c */
/*
 * Promote the given connection BIO using the CONNECT method for a TLS proxy.
 * This is typically called by an app, so bio_err and prog are used unless NULL
 * to print additional diagnostic information in a user-oriented way.
 */
int OSSL_HTTP_proxy_connect(BIO *bio, const char *server, const char *port,
                            const char *proxyuser, const char *proxypass,
                            int timeout, BIO *bio_err, const char *prog)
{
#undef BUF_SIZE
#define BUF_SIZE (8 * 1024)
    char *mbuf = OPENSSL_malloc(BUF_SIZE);
    char *mbufp;
    int read_len = 0;
    int ret = 0;
    BIO *fbio = BIO_new(BIO_f_buffer());
    int rv;
    time_t max_time = timeout > 0 ? time(NULL) + timeout : 0;

    if (bio == NULL || server == NULL
            || (bio_err != NULL && prog == NULL)) {
        ERR_raise(ERR_LIB_HTTP, ERR_R_PASSED_NULL_PARAMETER);
        goto end;
    }
    if (port == NULL || *port == '\0')
        port = OSSL_HTTPS_PORT;

    if (mbuf == NULL || fbio == NULL) {
        BIO_printf(bio_err /* may be NULL */, "%s: out of memory", prog);
        goto end;
    }
    BIO_push(fbio, bio);

    BIO_printf(fbio, "CONNECT %s:%s "HTTP_1_0"\r\n", server, port);

    /*
     * Workaround for broken proxies which would otherwise close
     * the connection when entering tunnel mode (e.g., Squid 2.6)
     */
    BIO_printf(fbio, "Proxy-Connection: Keep-Alive\r\n");

    /* Support for basic (base64) proxy authentication */
    if (proxyuser != NULL) {
        size_t len = strlen(proxyuser) + 1;
        char *proxyauth, *proxyauthenc = NULL;

        if (proxypass != NULL)
            len += strlen(proxypass);
        proxyauth = OPENSSL_malloc(len + 1);
        if (proxyauth == NULL)
            goto end;
        if (BIO_snprintf(proxyauth, len + 1, "%s:%s", proxyuser,
                         proxypass != NULL ? proxypass : "") != (int)len)
            goto proxy_end;
        proxyauthenc = base64encode(proxyauth, len);
        if (proxyauthenc != NULL) {
            BIO_printf(fbio, "Proxy-Authorization: Basic %s\r\n", proxyauthenc);
            OPENSSL_clear_free(proxyauthenc, strlen(proxyauthenc));
        }
    proxy_end:
        OPENSSL_clear_free(proxyauth, len);
        if (proxyauthenc == NULL)
            goto end;
    }

    /* Terminate the HTTP CONNECT request */
    BIO_printf(fbio, "\r\n");

    for (;;) {
        if (BIO_flush(fbio) != 0)
            break;
        /* potentially needs to be retried if BIO is non-blocking */
        if (!BIO_should_retry(fbio))
            break;
    }

    for (;;) {
        /* will not actually wait if timeout == 0 */
        rv = BIO_wait(fbio, max_time, 100 /* milliseconds */);
        if (rv <= 0) {
            BIO_printf(bio_err, "%s: HTTP CONNECT %s\n", prog,
                       rv == 0 ? "timed out" : "failed waiting for data");
            goto end;
        }

        /*-
         * The first line is the HTTP response.
         * According to RFC 7230, it is formatted exactly like this:
         * HTTP/d.d ddd reason text\r\n
         */
        read_len = BIO_gets(fbio, mbuf, BUF_SIZE);
        /* the BIO may not block, so we must wait for the 1st line to come in */
        if (read_len < (int)HTTP_LINE1_MINLEN)
            continue;

        /* Check for HTTP/1.x */
        if (!HAS_PREFIX(mbuf, HTTP_PREFIX) != 0) {
            ERR_raise(ERR_LIB_HTTP, HTTP_R_HEADER_PARSE_ERROR);
            BIO_printf(bio_err, "%s: HTTP CONNECT failed, non-HTTP response\n",
                       prog);
            /* Wrong protocol, not even HTTP, so stop reading headers */
            goto end;
        }
        mbufp = mbuf + strlen(HTTP_PREFIX);
        if (!HAS_PREFIX(mbufp, HTTP_VERSION_PATT) != 0) {
            ERR_raise(ERR_LIB_HTTP, HTTP_R_RECEIVED_WRONG_HTTP_VERSION);
            BIO_printf(bio_err,
                       "%s: HTTP CONNECT failed, bad HTTP version %.*s\n",
                       prog, (int)HTTP_VERSION_STR_LEN, mbufp);
            goto end;
        }
        mbufp += HTTP_VERSION_STR_LEN;

        /* RFC 7231 4.3.6: any 2xx status code is valid */
        if (!HAS_PREFIX(mbufp, " 2")) {
            /* chop any trailing whitespace */
            while (read_len > 0 && ossl_isspace(mbuf[read_len - 1]))
                read_len--;
            mbuf[read_len] = '\0';
            ERR_raise_data(ERR_LIB_HTTP, HTTP_R_CONNECT_FAILURE,
                           "reason=%s", mbufp);
            BIO_printf(bio_err, "%s: HTTP CONNECT failed, reason=%s\n",
                       prog, mbufp);
            goto end;
        }
        ret = 1;
        break;
    }

    /* Read past all following headers */
    do {
        /*
         * This does not necessarily catch the case when the full
         * HTTP response came in in more than a single TCP message.
         */
        read_len = BIO_gets(fbio, mbuf, BUF_SIZE);
    } while (read_len > 2);

 end:
    if (fbio != NULL) {
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
    }
    OPENSSL_free(mbuf);
    return ret;
#undef BUF_SIZE
}

/* wait if max_time != 0. returns < 0 on error, 0 on timeout, > 0 on success */
static int bio_wait_100(BIO *bio, time_t max_time) {
    return bio_wait(bio, max_time, 100);
}

/* returns -1 on error, 0 on timeout, 1 on success */
static int bio_connect(BIO *bio, int timeout) {
    return BIO_do_connect_retry(bio, timeout, 100);
}

typedef int (*http_fn)(OCSP_REQ_CTX *rctx,ASN1_VALUE **resp);
/*
 * Even better would be to extend OCSP_REQ_CTX_nbio() and
 * thus OCSP_REQ_CTX_nbio_d2i() to include this retry behavior */
/*
 * Exchange ASN.1 request and response via HTTP on any BIO
 * returns -4: other, -3: send, -2: receive, or -1: parse error, 0: timeout,
 * 1: success and then provides the received message via the *resp argument
 */
static int bio_http(BIO *bio/* could be removed if we could access rctx->io */,
                    OCSP_REQ_CTX *rctx, http_fn fn, ASN1_VALUE **resp,
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
            rv = bio_wait_100(bio, max_time);
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

/* one declaration and three defines copied from ocsp_ht.c; keep in sync! */
/* dummy declaration to get access to internal state variable */
struct ocsp_req_ctx_st {
    int state;                  /* Current I/O state */
    unsigned char *iobuf;       /* Line buffer */
    int iobuflen;               /* Line buffer length */
    BIO *io;                    /* BIO to perform I/O with */
    BIO *mem;                   /* Memory BIO response is built into */
};
# define OHS_NOREAD              0x1000
# define OHS_ASN1_WRITE_INIT     (5 | OHS_NOREAD)

/* adapted from legacy OCSP_REQ_CTX_i2d() in crypto/ocsp/ocsp_ht.c */
static int CMP_REQ_CTX_i2d(OCSP_REQ_CTX *rctx,
                           const ASN1_ITEM *it, ASN1_VALUE *val)
{
    static const char req_hdr[] =
        "Content-Type: application/pkixcmp\r\n"
        "Content-Length: %d\r\n\r\n";
    int reqlen = ASN1_item_i2d(val, NULL, it);

    if (BIO_printf(rctx->mem, req_hdr, reqlen) <= 0)
        return 0;
    if (ASN1_item_i2d_bio(it, rctx->mem, val) <= 0)
        return 0;
    rctx->state = OHS_ASN1_WRITE_INIT;
    return 1;
}



static void add_conn_error_hint(const OSSL_CMP_CTX *ctx, unsigned long errdetail)
{
    char buf[200];

    snprintf(buf, 200, "host '%s' port %d", ctx->server, ctx->serverPort);
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

    if (ctx->proxy == NULL) {
        host = ctx->server;
        port = ctx->serverPort;
    } else {
        # define URL_HTTP_PREFIX "http://"
        # define URL_HTTPS_PREFIX "https://"
        host = ctx->proxy;
        port = 0;
        if (strncmp(host, URL_HTTPS_PREFIX, strlen(URL_HTTPS_PREFIX)) == 0) {
            host += strlen(URL_HTTPS_PREFIX);
            if (strchr(host, ':') == NULL)
                port = 443;
        }
        else {
            if (strncmp(host, URL_HTTP_PREFIX, strlen(URL_HTTP_PREFIX)) == 0)
                host += strlen(URL_HTTP_PREFIX);
            if (strchr(host, ':') == NULL)
                port = 80;
        }
    }
    cbio = BIO_new_connect(host);
    if (cbio == NULL)
        goto end;
    if (port != 0) {
        snprintf(buf, sizeof(buf), "%d", port);
        (void)BIO_set_conn_port(cbio, buf);
    }

 end:
    return cbio;
}

static OCSP_REQ_CTX *CMP_sendreq_new(BIO *io, const char *host,
                                     const char *path, const OSSL_CMP_MSG *req,
                                     int maxline)
{
    OCSP_REQ_CTX *rctx = NULL;

    rctx = OCSP_REQ_CTX_new(io, maxline);
    if (rctx == NULL)
        return NULL;

    if (!OCSP_REQ_CTX_http(rctx, "POST", path))
        goto err;
    if (host != NULL)
        if (!OCSP_REQ_CTX_add1_header(rctx, "Host", host))
            goto err;
    if (!OCSP_REQ_CTX_add1_header(rctx, "Pragma", "no-cache"))
        goto err;

    if (req != NULL && !CMP_REQ_CTX_i2d(rctx, ASN1_ITEM_rptr(OSSL_CMP_MSG),
                                        (ASN1_VALUE *)req))
        goto err;

    return rctx;

 err:
    OCSP_REQ_CTX_free(rctx);
    return NULL;
}

/*
 * Exchange CMP request/response via HTTP on (non-)blocking BIO
 * returns 1 on success, 0 on error, -1 on BIO_should_retry
 */
static int CMP_http_nbio(OCSP_REQ_CTX *rctx, ASN1_VALUE **resp)
{
    return OCSP_REQ_CTX_nbio_d2i(rctx, resp, ASN1_ITEM_rptr(OSSL_CMP_MSG));
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
    OCSP_REQ_CTX *rctx;
    int rv;

    if ((rctx = CMP_sendreq_new(bio, host, path, req, -1)) == NULL)
        return -4;

    rv = bio_http(bio, rctx, CMP_http_nbio, (ASN1_VALUE **)resp, max_time);
 /* This indirectly calls ERR_clear_error(); */

    OCSP_REQ_CTX_free(rctx);

    return rv;
}

/*
 * Send the PKIMessage req and on success place the response in *res.
 * Any previous error is likely to be removed by ERR_clear_error().
 * returns pointer to the response message on success, else NULL.
 */
OSSL_CMP_MSG *OSSL_CMP_MSG_http_perform(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req)
{
    void *info;
    OSSL_CMP_MSG *res = NULL;
    int rv;
    char *path = NULL;
    size_t pos = 0, pathlen = 0;
    BIO *bio, *hbio = NULL;
    int err = ERR_R_MALLOC_FAILURE;
    time_t max_time;

    if (ctx == NULL || req == NULL ||
        ctx->server == NULL || ctx->serverPath == NULL || !ctx->serverPort){
        CMPerr(CMP_F_OSSL_CMP_MSG_HTTP_PERFORM, CMP_R_NULL_ARGUMENT);
        return NULL;
    }

    info = OSSL_CMP_CTX_get_http_cb_arg(ctx);
    max_time = ctx->msg_timeout > 0 ? time(NULL) + ctx->msg_timeout : 0;

    if ((hbio = CMP_new_http_bio(ctx)) == NULL)
        goto err;

    /* TODO: it looks like bio_connect() is superfluous except for maybe
       better error/timeout handling and reporting? Remove next 9 lines? */
    /* tentatively set error, which allows accumulating diagnostic info */
#if 1
    (void)ERR_set_mark();
    CMPerr(CMP_F_OSSL_CMP_MSG_HTTP_PERFORM, CMP_R_ERROR_CONNECTING);
    rv = bio_connect(hbio, ctx->msg_timeout);
    if (rv <= 0) {
        err = (rv == 0) ? CMP_R_CONNECT_TIMEOUT : CMP_R_ERROR_CONNECTING;
        goto err;
    } else {
        (void)ERR_pop_to_mark(); /* discard diagnostic info */
    }
#endif

    /* callback can be used to wrap or prepend TLS session */
    if (ctx->http_cb != NULL) {
        if ((bio = (*ctx->http_cb)(hbio, info, 1 /* connect */,
                                   info != NULL /* use_ssl */)) == NULL)
            goto err;
        hbio = bio;
    }

    pathlen = strlen(ctx->server) + strlen(ctx->serverPath) + 33;
    path = (char *)OPENSSL_malloc(pathlen);
    if (path == NULL)
        goto err;

    /*
     * Section 5.1.2 of RFC 1945 states that the absoluteURI form is only
     * allowed when using a proxy
     */
    if (ctx->http_cb == NULL /* no TLS */
        && ctx->proxy != NULL)
        pos = BIO_snprintf(path, pathlen-1, "http://%s:%d",
                           ctx->server, ctx->serverPort);

    /* make sure path includes a forward slash */
    if (ctx->serverPath[0] != '/')
        path[pos++] = '/';

    BIO_snprintf(path + pos, pathlen - pos - 1, "%s", ctx->serverPath);

    rv = CMP_sendreq(hbio, ctx->server, path, req, &res, max_time);
    OPENSSL_free(path);
    if (rv == -3)
        err = CMP_R_FAILED_TO_SEND_REQUEST;
    else if (rv == -2)
        err = CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE;
    else if (rv == -1)
        err = CMP_R_ERROR_DECODING_MESSAGE;
    else if (rv == 0) { /* timeout */
        err = CMP_R_READ_TIMEOUT;
    } else
        err = 0;

 err:
    if (err != 0) {
        if (ERR_GET_LIB(ERR_peek_error()) == ERR_LIB_SSL)
            err = CMP_R_TLS_ERROR;
        CMPerr(CMP_F_OSSL_CMP_MSG_HTTP_PERFORM, err);
        if (err == CMP_R_TLS_ERROR || err == CMP_R_CONNECT_TIMEOUT
                                   || err == CMP_R_ERROR_CONNECTING)
            add_conn_error_hint(ctx, ERR_peek_error());
    }

    if (ctx->http_cb && (*ctx->http_cb)(hbio, info, 0 /* disconnect */, ERR_peek_error()) == NULL)
        CMPerr(CMP_F_OSSL_CMP_MSG_HTTP_PERFORM, ERR_R_MALLOC_FAILURE);
    BIO_free_all(hbio); /* also frees any (e.g., SSL/TLS) BIOs linked with hbio
       and, like BIO_reset(hbio), calls SSL_shutdown() to notify/alert peer */

    return res;
}

/* adapted from apps/apps.c to include connection timeout */
int OSSL_CMP_load_cert_crl_http_timeout(const char *url, int req_timeout,
                                        X509 **pcert, X509_CRL **pcrl,
                                        BIO *bio_err)
{
    char *host = NULL;
    char *port = NULL;
    char *path = NULL;
    BIO *bio = NULL;
    OCSP_REQ_CTX *rctx = NULL;
    int use_ssl;
    int rv = 0;
    time_t max_time = req_timeout > 0 ? time(NULL) + req_timeout : 0;

    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl))
        goto err;
    if (use_ssl) {
        BIO_puts(bio_err, "https not supported for CRL fetching\n");
        goto err;
    }
    bio = BIO_new_connect(host);
    if (bio == NULL || !BIO_set_conn_port(bio, port))
        goto err;

    if (bio_connect(bio, req_timeout) <= 0)
        goto err;

    rctx = OCSP_REQ_CTX_new(bio, 1024);
    if (rctx == NULL)
        goto err;
    if (!OCSP_REQ_CTX_http(rctx, "GET", path))
        goto err;
    if (!OCSP_REQ_CTX_add1_header(rctx, "Host", host))
        goto err;

    rv = bio_http(bio, rctx,
         pcert != NULL ? (http_fn)X509_http_nbio : (http_fn)X509_CRL_http_nbio,
         pcert != NULL ? (ASN1_VALUE **)pcert : (ASN1_VALUE **)pcrl, max_time);

 err:
    OPENSSL_free(host);
    OPENSSL_free(path);
    OPENSSL_free(port);
    BIO_free_all(bio);
    OCSP_REQ_CTX_free(rctx);
    if (rv != 1) {
        BIO_printf(bio_err, "%s loading %s from '%s'\n",
                   rv == 0 ? "timeout" : rv == -1 ?
                           "parse Error" : "transfer error",
                   pcert != NULL ? "certificate" : "CRL", url);
        ERR_print_errors(bio_err);
    }
    return rv;
}

#endif /* !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK) */
