/*
 * Copyright 2001-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <stdio.h>
#include <stdlib.h>
#include "crypto/ctype.h"
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/httperr.h>
#include <openssl/buffer.h>
#include <openssl/http.h>
#include "internal/sockets.h"

/* Stateful HTTP request code, supporting blocking and non-blocking I/O */

/* Opaque HTTP request status structure */

struct http_req_ctx_st {
    int state;                  /* Current I/O state */
    unsigned char *iobuf;       /* Line buffer */
    int iobuflen;               /* Line buffer length */
    BIO *io;                    /* BIO to perform I/O with */
    BIO *mem;                   /* Memory BIO response is built into */
    unsigned long asn1_len;     /* ASN1 length of response */
    unsigned long max_resp_len; /* Maximum length of response */
};

#define HTTP_MAX_RESP_LENGTH    (100 * 1024)
#define HTTP_MAX_LINE_LEN       4096;

/* HTTP states */

/* If set no reading should be performed */
#define OHS_NOREAD              0x1000
/* Error condition */
#define OHS_ERROR               (0 | OHS_NOREAD)
/* First line being read */
#define OHS_FIRSTLINE           1
/* MIME headers being read */
#define OHS_HEADERS             2
/* HTTP initial header (tag + length) being read */
#define OHS_ASN1_HEADER         3
/* HTTP content octets being read */
#define OHS_ASN1_CONTENT        4
/* First call: ready to start I/O */
#define OHS_ASN1_WRITE_INIT     (5 | OHS_NOREAD)
/* Request being sent */
#define OHS_ASN1_WRITE          (6 | OHS_NOREAD)
/* Request being flushed */
#define OHS_ASN1_FLUSH          (7 | OHS_NOREAD)
/* Completed */
#define OHS_DONE                (8 | OHS_NOREAD)
/* Headers set, no final \r\n included */
#define OHS_HTTP_HEADER         (9 | OHS_NOREAD)

static int parse_http_line1(char *line);

HTTP_REQ_CTX *HTTP_REQ_CTX_new(BIO *io, int maxline)
{
    HTTP_REQ_CTX *rctx = OPENSSL_zalloc(sizeof(*rctx));

    if (rctx == NULL)
        return NULL;
    rctx->state = OHS_ERROR;
    rctx->max_resp_len = HTTP_MAX_RESP_LENGTH;
    rctx->mem = BIO_new(BIO_s_mem());
    rctx->io = io;
    if (maxline > 0)
        rctx->iobuflen = maxline;
    else
        rctx->iobuflen = HTTP_MAX_LINE_LEN;
    rctx->iobuf = OPENSSL_malloc(rctx->iobuflen);
    if (rctx->iobuf == NULL || rctx->mem == NULL) {
        HTTP_REQ_CTX_free(rctx);
        return NULL;
    }
    return rctx;
}

void HTTP_REQ_CTX_free(HTTP_REQ_CTX *rctx)
{
    if (!rctx)
        return;
    BIO_free(rctx->mem);
    OPENSSL_free(rctx->iobuf);
    OPENSSL_free(rctx);
}

BIO *HTTP_REQ_CTX_get0_mem_bio(HTTP_REQ_CTX *rctx)
{
    return rctx->mem;
}

void HTTP_set_max_response_length(HTTP_REQ_CTX *rctx, unsigned long len)
{
    if (len == 0)
        rctx->max_resp_len = HTTP_MAX_RESP_LENGTH;
    else
        rctx->max_resp_len = len;
}

int HTTP_REQ_CTX_i2d(HTTP_REQ_CTX *rctx, const char *content_type,
                     const ASN1_ITEM *it, ASN1_VALUE *req)
{
    static const char req_hdr[] =
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n\r\n";
    int reqlen = ASN1_item_i2d(req, NULL, it);
    if (BIO_printf(rctx->mem, req_hdr, content_type, reqlen) <= 0)
        return 0;
    if (ASN1_item_i2d_bio(it, rctx->mem, req) <= 0)
        return 0;
    rctx->state = OHS_ASN1_WRITE_INIT;
    return 1;
}

int HTTP_REQ_CTX_nbio_d2i(HTTP_REQ_CTX *rctx,
                          ASN1_VALUE **pval, const ASN1_ITEM *it)
{
    int rv, len;
    const unsigned char *p;

    rv = HTTP_REQ_CTX_nbio(rctx);
    if (rv != 1)
        return rv;

    len = BIO_get_mem_data(rctx->mem, &p);
    *pval = ASN1_item_d2i(NULL, &p, len, it);
    if (*pval == NULL) {
        rctx->state = OHS_ERROR;
        return 0;
    }
    return 1;
}

int HTTP_REQ_CTX_http(HTTP_REQ_CTX *rctx, const char *op, const char *path)
{
    static const char http_hdr[] = "%s %s HTTP/1.0\r\n";

    if (path == NULL)
        path = "/";

    if (BIO_printf(rctx->mem, http_hdr, op, path) <= 0)
        return 0;
    rctx->state = OHS_HTTP_HEADER;
    return 1;
}

int HTTP_REQ_CTX_add1_header(HTTP_REQ_CTX *rctx,
                             const char *name, const char *value)
{
    if (!name)
        return 0;
    if (BIO_puts(rctx->mem, name) <= 0)
        return 0;
    if (value) {
        if (BIO_write(rctx->mem, ": ", 2) != 2)
            return 0;
        if (BIO_puts(rctx->mem, value) <= 0)
            return 0;
    }
    if (BIO_write(rctx->mem, "\r\n", 2) != 2)
        return 0;
    rctx->state = OHS_HTTP_HEADER;
    return 1;
}

HTTP_REQ_CTX *HTTP_sendreq_new(BIO *io, const char *path,
                               const char *content_type, const ASN1_ITEM *it,
                               ASN1_VALUE *req, int maxline)
{

    HTTP_REQ_CTX *rctx = NULL;
    rctx = HTTP_REQ_CTX_new(io, maxline);
    if (rctx == NULL)
        return NULL;

    if (!HTTP_REQ_CTX_http(rctx, "POST", path))
        goto err;

    if (req && !HTTP_REQ_CTX_i2d(rctx, content_type, it, req))
        goto err;

    return rctx;

 err:
    HTTP_REQ_CTX_free(rctx);
    return NULL;
}

/*
 * Parse the HTTP response. This will look like this: "HTTP/1.0 200 OK". We
 * need to obtain the numeric code and (optional) informational message.
 */

static int parse_http_line1(char *line)
{
    int retcode;
    char *p, *q, *r;
    /* Skip to first white space (passed protocol info) */

    for (p = line; *p && !ossl_isspace(*p); p++)
        continue;
    if (*p == '\0') {
        HTTPerr(HTTP_F_PARSE_HTTP_LINE1, HTTP_R_SERVER_RESPONSE_PARSE_ERROR);
        return 0;
    }

    /* Skip past white space to start of response code */
    while (*p && ossl_isspace(*p))
        p++;

    if (*p == '\0') {
        HTTPerr(HTTP_F_PARSE_HTTP_LINE1, HTTP_R_SERVER_RESPONSE_PARSE_ERROR);
        return 0;
    }

    /* Find end of response code: first whitespace after start of code */
    for (q = p; *q && !ossl_isspace(*q); q++)
        continue;

    if (*q == '\0') {
        HTTPerr(HTTP_F_PARSE_HTTP_LINE1, HTTP_R_SERVER_RESPONSE_PARSE_ERROR);
        return 0;
    }

    /* Set end of response code and start of message */
    *q++ = 0;

    /* Attempt to parse numeric code */
    retcode = strtoul(p, &r, 10);

    if (*r)
        return 0;

    /* Skip over any leading white space in message */
    while (*q && ossl_isspace(*q))
        q++;

    if (*q) {
        /*
         * Finally zap any trailing white space in message (include CRLF)
         */

        /* We know q has a non white space character so this is OK */
        for (r = q + strlen(q) - 1; ossl_isspace(*r); r--)
            *r = 0;
    }
    if (retcode != 200) {
        HTTPerr(HTTP_F_PARSE_HTTP_LINE1, HTTP_R_SERVER_RESPONSE_ERROR);
        if (*q == '\0')
            ERR_add_error_data(2, "Code=", p);
        else
            ERR_add_error_data(4, "Code=", p, ",Reason=", q);
        return 0;
    }

    return 1;

}

int HTTP_REQ_CTX_nbio(HTTP_REQ_CTX *rctx)
{
    int i, n;
    const unsigned char *p;

 next_io:
    if (!(rctx->state & OHS_NOREAD)) {
        n = BIO_read(rctx->io, rctx->iobuf, rctx->iobuflen);

        if (n <= 0) {
            if (BIO_should_retry(rctx->io))
                return -1;
            return 0;
        }

        /* Write data to memory BIO */

        if (BIO_write(rctx->mem, rctx->iobuf, n) != n)
            return 0;
    }

    switch (rctx->state) {
    case OHS_HTTP_HEADER:
        /* Last operation was adding headers: need a final \r\n */
        if (BIO_write(rctx->mem, "\r\n", 2) != 2) {
            rctx->state = OHS_ERROR;
            return 0;
        }
        rctx->state = OHS_ASN1_WRITE_INIT;

        /* fall thru */
    case OHS_ASN1_WRITE_INIT:
        rctx->asn1_len = BIO_get_mem_data(rctx->mem, NULL);
        rctx->state = OHS_ASN1_WRITE;

        /* fall thru */
    case OHS_ASN1_WRITE:
        n = BIO_get_mem_data(rctx->mem, &p);

        i = BIO_write(rctx->io, p + (n - rctx->asn1_len), rctx->asn1_len);

        if (i <= 0) {
            if (BIO_should_retry(rctx->io))
                return -1;
            rctx->state = OHS_ERROR;
            return 0;
        }

        rctx->asn1_len -= i;

        if (rctx->asn1_len > 0)
            goto next_io;

        rctx->state = OHS_ASN1_FLUSH;

        (void)BIO_reset(rctx->mem);

        /* fall thru */
    case OHS_ASN1_FLUSH:

        i = BIO_flush(rctx->io);

        if (i > 0) {
            rctx->state = OHS_FIRSTLINE;
            goto next_io;
        }

        if (BIO_should_retry(rctx->io))
            return -1;

        rctx->state = OHS_ERROR;
        return 0;

    case OHS_ERROR:
        return 0;

    case OHS_FIRSTLINE:
    case OHS_HEADERS:

        /* Attempt to read a line in */

 next_line:
        /*
         * Due to &%^*$" memory BIO behaviour with BIO_gets we have to check
         * there's a complete line in there before calling BIO_gets or we'll
         * just get a partial read.
         */
        n = BIO_get_mem_data(rctx->mem, &p);
        if ((n <= 0) || !memchr(p, '\n', n)) {
            if (n >= rctx->iobuflen) {
                rctx->state = OHS_ERROR;
                return 0;
            }
            goto next_io;
        }
        n = BIO_gets(rctx->mem, (char *)rctx->iobuf, rctx->iobuflen);

        if (n <= 0) {
            if (BIO_should_retry(rctx->mem))
                goto next_io;
            rctx->state = OHS_ERROR;
            return 0;
        }

        /* Don't allow excessive lines */
        if (n == rctx->iobuflen) {
            rctx->state = OHS_ERROR;
            return 0;
        }

        /* First line */
        if (rctx->state == OHS_FIRSTLINE) {
            if (parse_http_line1((char *)rctx->iobuf)) {
                rctx->state = OHS_HEADERS;
                goto next_line;
            } else {
                rctx->state = OHS_ERROR;
                return 0;
            }
        } else {
            /* Look for blank line: end of headers */
            for (p = rctx->iobuf; *p; p++) {
                if ((*p != '\r') && (*p != '\n'))
                    break;
            }
            if (*p)
                goto next_line;

            rctx->state = OHS_ASN1_HEADER;

        }

        /* Fall thru */

    case OHS_ASN1_HEADER:
        /*
         * Now reading ASN1 header: can read at least 2 bytes which is enough
         * for ASN1 SEQUENCE header and either length field or at least the
         * length of the length field.
         */
        n = BIO_get_mem_data(rctx->mem, &p);
        if (n < 2)
            goto next_io;

        /* Check it is an ASN1 SEQUENCE */
        if (*p++ != (V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED)) {
            rctx->state = OHS_ERROR;
            return 0;
        }

        /* Check out length field */
        if (*p & 0x80) {
            /*
             * If MSB set on initial length octet we can now always read 6
             * octets: make sure we have them.
             */
            if (n < 6)
                goto next_io;
            n = *p & 0x7F;
            /* Not NDEF or excessive length */
            if (!n || (n > 4)) {
                rctx->state = OHS_ERROR;
                return 0;
            }
            p++;
            rctx->asn1_len = 0;
            for (i = 0; i < n; i++) {
                rctx->asn1_len <<= 8;
                rctx->asn1_len |= *p++;
            }

            if (rctx->asn1_len > rctx->max_resp_len) {
                rctx->state = OHS_ERROR;
                return 0;
            }

            rctx->asn1_len += n + 2;
        } else
            rctx->asn1_len = *p + 2;

        rctx->state = OHS_ASN1_CONTENT;

        /* Fall thru */

    case OHS_ASN1_CONTENT:
        n = BIO_get_mem_data(rctx->mem, NULL);
        if (n < (int)rctx->asn1_len)
            goto next_io;

        rctx->state = OHS_DONE;
        return 1;

    case OHS_DONE:
        return 1;

    }

    return 0;

}

#if !defined(OPENSSL_NO_SOCK)

/* adapted from apps/s_client.c; TODO DvO: call this code from there */
# undef BUFSIZZ
# define BUFSIZZ 1024*8
# define HTTP_PREFIX "HTTP/"
# define HTTP_VERSION "1." /* or, e.g., "1.1" */
# define HTTP_VERSION_MAX_LEN 3
int HTTP_proxy_connect(BIO *bio, const char *server, int port, long timeout,
                       BIO *bio_err, const char *prog)
{
    char *mbuf = OPENSSL_malloc(BUFSIZZ);
    char *mbufp;
    int mbuf_len = 0;
    int rv;
    int ret = 0;
    BIO *fbio = BIO_new(BIO_f_buffer());
    time_t max_time = timeout > 0 ? time(NULL) + timeout : 0;

    if (mbuf == NULL || fbio == NULL) {
        BIO_printf(bio_err, "%s: out of memory", prog);
        goto end;
    }
    BIO_push(fbio, bio);
    /* CONNECT seems only to be specified for HTTP/1.1 in RFC 2817/7231 */
    BIO_printf(fbio, "CONNECT %s:%d "HTTP_PREFIX"1.1\r\n", server, port);

    /*
     * Workaround for broken proxies which would otherwise close
     * the connection when entering tunnel mode (eg Squid 2.6)
     */
    BIO_printf(fbio, "Proxy-Connection: Keep-Alive\r\n");

#ifdef OSSL_CMP_SUPPORT_PROXYUSER /* TODO, is not yet supported */
    /* Support for basic (base64) proxy authentication */
    if (proxyuser != NULL) {
        size_t l;
        char *proxyauth, *proxyauthenc;

        l = strlen(proxyuser);
        if (proxypass != NULL)
            l += strlen(proxypass);
        proxyauth = OPENSSL_malloc(l + 2);
        BIO_snprintf(proxyauth, l + 2, "%s:%s", proxyuser,
                     (proxypass != NULL) ? proxypass : "");
        proxyauthenc = base64encode(proxyauth, strlen(proxyauth));
        BIO_printf(fbio, "Proxy-Authorization: Basic %s\r\n", proxyauthenc);
        OPENSSL_clear_free(proxyauth, strlen(proxyauth));
        OPENSSL_clear_free(proxyauthenc, strlen(proxyauthenc));
    }
#endif
    BIO_printf(fbio, "\r\n");
 flush_retry:
    if (!BIO_flush(fbio)) {
        /* potentially needs to be retried if BIO is non-blocking */
        if (BIO_should_retry(fbio))
            goto flush_retry;
    }
 retry:
    rv = BIO_wait(fbio, max_time - time(NULL));
    if (rv <= 0) {
        BIO_printf(bio_err, "%s: HTTP CONNECT %s\n", prog,
                   rv == 0 ? "timed out" : "failed waiting for data");
        goto end;
    }

    mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
    /* as the BIO doesn't block, we need to wait that the first line comes in */
    if (mbuf_len < (int)strlen(HTTP_PREFIX""HTTP_VERSION" 200"))
        goto retry;

    /* RFC 7231 4.3.6: any 2xx status code is valid */
    if (strncmp(mbuf, HTTP_PREFIX, strlen(HTTP_PREFIX) != 0)) {
        BIO_printf(bio_err, "%s: HTTP CONNECT failed, non-HTTP response\n",
                   prog);
        goto end;
    }
    mbufp = mbuf + strlen(HTTP_PREFIX);
    if (strncmp(mbufp, HTTP_VERSION, strlen(HTTP_VERSION)) != 0) {
        BIO_printf(bio_err, "%s: HTTP CONNECT failed, bad HTTP version %.*s\n",
                   prog, HTTP_VERSION_MAX_LEN, mbufp);
        goto end;
    }
    mbufp += HTTP_VERSION_MAX_LEN;
    if (strncmp(mbufp, " 2", strlen(" 2")) != 0) {
        mbufp += 1;
        BIO_printf(bio_err, "%s: HTTP CONNECT failed: %.*s ",
                   prog, (int)(mbuf_len - (mbufp - mbuf)), mbufp);
        goto end;
    }

    /*
     * TODO: this does not necessarily catch the case when the full HTTP
     * response came in in more than a single TCP message
     * Read past all following headers
     */
    do
        mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
    while (mbuf_len > 2);

    ret = 1;
 end:
    if (fbio != NULL) {
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
    }
    OPENSSL_free(mbuf);
    return ret;
}

#endif /* !defined(OPENSSL_NO_SOCK) */
