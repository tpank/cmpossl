/*
 * Copyright 2001-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <stdio.h>
#include <stdlib.h>
#include "internal/ctype.h"
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#include <openssl/buffer.h>

/* TODO move all socket-related stuff to better place as is independent of OCSP */
#ifndef OPENSSL_NO_SOCK

# ifndef openssl_fdset /* also defined in apps/apps.h */
#  ifdef OPENSSL_SYSNAME_WIN32
#   define openssl_fdset(a,b) FD_SET((unsigned int)a, b)
#  else
#   define openssl_fdset(a,b) FD_SET(a, b)
#  endif
# endif

/* returns < 0 on error, 0 on timeout, > 0 on success */
int OSSL_socket_wait(int fd, int for_read, int timeout)
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

/* returns < 0 on error, 0 on timeout, > 0 on success */
int OSSL_BIO_wait(BIO *bio, int timeout)
{
    int fd;
    if (BIO_get_fd(bio, &fd) <= 0)
        return -1;
    return OSSL_socket_wait(fd, BIO_should_read(bio), timeout);
}

/* returns -1 on timeout, 0 on other error, 1 on success */
int OSSL_BIO_do_connect(BIO *bio, time_t max_time)
{
    int blocking;
    int rv;
    blocking = max_time == 0;

/* https://www.openssl.org/docs/man1.1.0/crypto/BIO_should_io_special.html */
    if (!blocking)
        BIO_set_nbio(bio, 1);
 retry: /* it does not help here to set SSL_MODE_AUTO_RETRY */
    rv = BIO_do_connect(bio); /* This indirectly calls ERR_clear_error(); */
    if (rv <= 0 && (errno == ETIMEDOUT ||
                    ERR_GET_REASON(ERR_peek_error()) == ETIMEDOUT)) {
    /* if blocking, despite blocking BIO, BIO_do_connect() timed out, else if
       non-blocking, BIO_do_connect() timed out early with rv==-1 && errno==0 */
        ERR_clear_error();
        (void)BIO_reset(bio); /* otherwise blocking next connect() may crash and
                                 non-blocking next BIO_do_connect() will fail */
        goto retry;
    }
    if (rv <= 0 && BIO_should_retry(bio)) {
        if (blocking || (rv = OSSL_BIO_wait(bio, (int)(max_time - time(NULL)))) > 0)
            goto retry;
    }
    return rv;
}

#endif /* OPENSSL_NO_SOCK */
/* end TODO move all socket-related stuff to better place as is independent of OCSP */

/* TODO move all generic HTTP stuff to better place as it is independent of OCSP.
 * Error output like OCSP_F PARSE_HTTP_LINE1 and OCSP_R_RESPONSE_PARSE_ERROR
 * can be quite misleadng when this HTTP client code is used for other purposes.
 */
/*
 * Parse the HTTP response. This will look like this: "HTTP/1.0 200 OK". We
 * need to obtain the numeric code and (optional) informational message.
 * Return HTTP status code or 0 on parse error
 */

/* Stateful ASN.1 request/response code, supporting non-blocking I/O */

/* Opaque ASN.1 request/response status structure */

struct ocsp_req_ctx_st {
    int state;                  /* Current I/O state */
    unsigned char *iobuf;       /* Line buffer */
    int iobuflen;               /* Line buffer length */
    BIO *io;                    /* BIO to perform I/O with */
    BIO *mem;                   /* Memory BIO response is built into */
    unsigned long asn1_len;     /* ASN1 length of response */
    unsigned long max_resp_len; /* Maximum length of response */
    time_t max_time;            /* Time when to report eror, or 0 for blocking */
};

#define OCSP_MAX_RESP_LENGTH    (100 * 1024)
#define OCSP_MAX_LINE_LEN       4096;

/* OCSP states */

/* If set no reading should be performed */
#define OHS_NOREAD              0x1000
/* Error condition */
#define OHS_ERROR               (0 | OHS_NOREAD)
/* First line being read */
#define OHS_FIRSTLINE           1
/* MIME headers being read */
#define OHS_HEADERS             2
/* OCSP initial header (tag + length) being read */
#define OHS_ASN1_HEADER         3
/* OCSP content octets being read */
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

OCSP_REQ_CTX *OCSP_REQ_CTX_new(BIO *io, int maxline, int timeout)
{
    OCSP_REQ_CTX *rctx = OPENSSL_zalloc(sizeof(*rctx));

    if (rctx == NULL) {
        OCSPerr(OCSP_F_OCSP_REQ_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    rctx->state = OHS_ERROR;
    rctx->max_resp_len = OCSP_MAX_RESP_LENGTH;
    rctx->mem = BIO_new(BIO_s_mem());
    rctx->io = io;
    rctx->iobuflen = maxline > 0 ? maxline : OCSP_MAX_LINE_LEN;
    rctx->max_time = timeout > 0 ? time(NULL) + timeout : 0/* infinite */;
    rctx->iobuf = OPENSSL_malloc(rctx->iobuflen);
    if (rctx->iobuf == NULL || rctx->mem == NULL) {
        OCSP_REQ_CTX_free(rctx);
        OCSPerr(OCSP_F_OCSP_REQ_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return rctx;
}

void OCSP_REQ_CTX_free(OCSP_REQ_CTX *rctx)
{
    if (!rctx)
        return;
    BIO_free(rctx->mem);
    OPENSSL_free(rctx->iobuf);
    OPENSSL_free(rctx);
}

BIO *OCSP_REQ_CTX_get0_mem_bio(OCSP_REQ_CTX *rctx)
{
    return rctx->mem;
}

void OCSP_set_max_response_length(OCSP_REQ_CTX *rctx, unsigned long len)
{
    if (len == 0)
        rctx->max_resp_len = OCSP_MAX_RESP_LENGTH;
    else
        rctx->max_resp_len = len;
}

int OCSP_REQ_CTX_i2d(OCSP_REQ_CTX *rctx, const char *req_hdr,
                     const ASN1_ITEM *it, ASN1_VALUE *val)
{
    int reqlen = ASN1_item_i2d(val, NULL, it);
    if (BIO_printf(rctx->mem, req_hdr, reqlen) <= 0) {
        OCSPerr(OCSP_F_OCSP_REQ_CTX_I2D, OCSP_R_PUT_HTTP_HEADER);
        return 0;
    }
    if (ASN1_item_i2d_bio(it, rctx->mem, val) <= 0) {
        OCSPerr(OCSP_F_OCSP_REQ_CTX_I2D, OCSP_R_PUT_HTTP_BODY);
        return 0;
    }
    rctx->state = OHS_ASN1_WRITE_INIT;
    return 1;
}

/* Convert ASN.1 (DER) encoded response to given internal format */
ASN1_VALUE *OCSP_REQ_CTX_d2i(OCSP_REQ_CTX *rctx, const ASN1_ITEM *it)
{
    const unsigned char *p;
    ASN1_VALUE *val;
    long len = BIO_get_mem_data(rctx->mem, &p);
    val = ASN1_item_d2i(NULL, &p, len, it);
    if (val == NULL) {
        rctx->state = OHS_ERROR;
        OCSPerr(OCSP_F_OCSP_REQ_CTX_D2I, OCSP_R_RESPONSE_PARSE_ERROR);
    }
    return val;
}

int OCSP_REQ_CTX_add1_http(OCSP_REQ_CTX *rctx, const char *op, const char *path)
{
    static const char http_hdr[] = "%s %s HTTP/1.0\r\n";

    if (!path)
        path = "/";

    if (BIO_printf(rctx->mem, http_hdr, op, path) <= 0) {
        OCSPerr(OCSP_F_OCSP_REQ_CTX_ADD1_HTTP, OCSP_R_PUT_HTTP_HEADER);
        return 0;
    }
    rctx->state = OHS_HTTP_HEADER;
    return 1;
}

int OCSP_REQ_CTX_add1_header(OCSP_REQ_CTX *rctx,
                             const char *name, const char *value)
{
    if (!name)
        return 0;
    if (BIO_puts(rctx->mem, name) <= 0)
        goto err;
    if (value) {
        if (BIO_write(rctx->mem, ": ", 2) != 2)
            goto err;
        if (BIO_puts(rctx->mem, value) <= 0)
            goto err;
    }
    if (BIO_write(rctx->mem, "\r\n", 2) != 2)
        goto err;

    rctx->state = OHS_HTTP_HEADER;
    return 1;

 err:
    OCSPerr(OCSP_F_OCSP_REQ_CTX_ADD1_HEADER, OCSP_R_PUT_HTTP_HEADER);
    return 0;
}

static int parse_http_line1(char *line)
{
    int retcode;
    char *p, *q, *r;
    /* Skip to first white space (passed protocol info) */

    for (p = line; *p && !ossl_isspace(*p); p++)
        continue;
    if (!*p) {
        OCSPerr(OCSP_F_PARSE_HTTP_LINE1, OCSP_R_RESPONSE_PARSE_ERROR);
        return 0;
    }

    /* Skip past white space to start of response code */
    while (*p && ossl_isspace(*p))
        p++;

    if (!*p) {
        OCSPerr(OCSP_F_PARSE_HTTP_LINE1, OCSP_R_RESPONSE_PARSE_ERROR);
        return 0;
    }

    /* Find end of response code: first whitespace after start of code */
    for (q = p; *q && !ossl_isspace(*q); q++)
        continue;

    if (!*q) {
        OCSPerr(OCSP_F_PARSE_HTTP_LINE1, OCSP_R_RESPONSE_PARSE_ERROR);
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
        /* Finally zap any trailing white space in message (include CRLF) */

        /* We know q has a non white space character so this is OK */
        for (r = q + strlen(q) - 1; ossl_isspace(*r); r--)
            *r = 0;
    }
    if (retcode != 200) {
        OCSPerr(OCSP_F_PARSE_HTTP_LINE1, OCSP_R_SERVER_RESPONSE_ERROR);
        if (!*q)
            ERR_add_error_data(2, "Code=", p);
        else
            ERR_add_error_data(4, "Code=", p, ",Reason=", q);
    }

    return retcode;
}

/* Return HTTP code if >200, 0 on other error, -1: should retry, 1: success */
int OCSP_REQ_CTX_nbio(OCSP_REQ_CTX *rctx)
{
    int i, n;
    const unsigned char *p;
 next_io:
    if (!(rctx->state & OHS_NOREAD)) {
        n = BIO_read(rctx->io, rctx->iobuf, rctx->iobuflen);

        if (n <= 0) {
            if (BIO_should_retry(rctx->io))
                return -1;
            OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, OCSP_R_HTTP_READ_ERROR);
            return 0;
        }

        /* Write data to memory BIO */
        if (BIO_write(rctx->mem, rctx->iobuf, n) != n) {
            OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, OCSP_R_HTTP_WRITE_ERROR);
            return 0;
        }
    }

    switch (rctx->state) {
    case OHS_HTTP_HEADER:
        /* Last operation was adding headers: need a final \r\n */
        if (BIO_write(rctx->mem, "\r\n", 2) != 2) {
            rctx->state = OHS_ERROR;
            OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, OCSP_R_HTTP_WRITE_ERROR);
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
            OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, OCSP_R_HTTP_WRITE_ERROR);
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
        OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, OCSP_R_HTTP_WRITE_ERROR);
        return 0;

    case OHS_ERROR:
        OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, ERR_R_INTERNAL_ERROR);
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
                OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, OCSP_R_HTTP_LINE_TOO_LARGE);
                return 0;
            }
            goto next_io;
        }
        n = BIO_gets(rctx->mem, (char *)rctx->iobuf, rctx->iobuflen);

        if (n <= 0) {
            if (BIO_should_retry(rctx->mem))
                goto next_io;
            rctx->state = OHS_ERROR;
            OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, OCSP_R_HTTP_READ_ERROR);
            return 0;
        }

        /* Don't allow excessive lines */
        if (n == rctx->iobuflen) {
            rctx->state = OHS_ERROR;
            OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, OCSP_R_HTTP_LINE_TOO_LARGE);
            return 0;
        }

        /* First line */
        if (rctx->state == OHS_FIRSTLINE) {
            int rc = parse_http_line1((char *)rctx->iobuf);
            if (rc == 200) {
                rctx->state = OHS_HEADERS;
                goto next_line;
            } else {
                rctx->state = OHS_ERROR;
                return rc;
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
            OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, OCSP_R_RESPONSE_PARSE_ERROR);
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
            /* Not NDEF */
            if (!n) {
                rctx->state = OHS_ERROR;
                OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, OCSP_R_RESPONSE_PARSE_ERROR);
                return 0;
            }
            /* excessive length */
            if (n > 4) {
                rctx->state = OHS_ERROR;
                OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, OCSP_R_HTTP_BODY_TOO_LARGE);
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
                OCSPerr(OCSP_F_OCSP_REQ_CTX_NBIO, OCSP_R_HTTP_BODY_TOO_LARGE);
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

/*
 * Exchange ASN.1 request and response via HTTP.
 * Return HTTP status code if > 200, 0 on other error, or 1: success
 * (implies HTTP code 200) and then provide the response via the *resp argument
 */
int OCSP_REQ_CTX_sendreq(OCSP_REQ_CTX *rctx)
{
    int rc, rv = 0;
    int blocking = rctx->max_time == 0;

    /* TODO: it looks like BIO_do_connect() is superfluous except for maybe
       better error/timeout handling and reporting? Remove next 8 lines? */
    rv = OSSL_BIO_do_connect(rctx->io, rctx->max_time);
    if (rv <= 0) {
        if (rv == -1) {
            OCSPerr(OCSP_F_OCSP_REQ_CTX_SENDREQ, OCSP_R_CONNECT_TIMEOUT);
            rv = 0;
        }
        return rv;
    }

    do {
        rv = OCSP_REQ_CTX_nbio(rctx);
        if (rv != -1)
            break;
        /* else BIO_should_retry was true */
        if (!blocking) {
            rc = OSSL_BIO_wait(rctx->io, (int)(rctx->max_time - time(NULL)));
            if (rc <= 0) { /* error or timeout */
                rv = (rc < 0) ? 0 /* unspecified error */ : -1; /* timeout */
                break;
            }
        }
    } while (rv == -1); /* BIO_should_retry was true */

    if (rv == -1) {
        OCSPerr(OCSP_F_OCSP_REQ_CTX_SENDREQ, OCSP_R_REQUEST_TIMEOUT);
        rv = 0;
    }
    return rv;
}
/* end TODO move all generic HTTP stuff to better place as it is independent of OCSP */

int OCSP_REQ_CTX_set1_req(OCSP_REQ_CTX *rctx, OCSP_REQUEST *req)
{
    static const char ocsp_req_hdr[] =
        "Content-Type: application/ocsp-request\r\n"
        "Content-Length: %d\r\n\r\n";
    return OCSP_REQ_CTX_i2d(rctx, ocsp_req_hdr, ASN1_ITEM_rptr(OCSP_REQUEST),
                            (ASN1_VALUE *)req);
}

/* TODO this function can now be made static */
OCSP_REQ_CTX *OCSP_sendreq_new(BIO *io, const char *path, OCSP_REQUEST *req,
                               int maxline, int timeout)
{

    OCSP_REQ_CTX *rctx = NULL;
    rctx = OCSP_REQ_CTX_new(io, maxline, timeout);
    if (rctx == NULL)
        return NULL;

    if (!OCSP_REQ_CTX_add1_http(rctx, "POST", path))
        goto err;

    if (req && !OCSP_REQ_CTX_set1_req(rctx, req))
        goto err;

    return rctx;

 err:
    OCSP_REQ_CTX_free(rctx);
    return NULL;
}

/* Return HTTP code if >200, 0 on other error, -1: should retry, 1: success */
/* TODO remove? Note that it is now unused */
int OCSP_sendreq_nbio(OCSP_REQ_CTX *rctx, OCSP_RESPONSE **presp)
{
    int rv = OCSP_REQ_CTX_sendreq(rctx);
    if (rv == 1 && (*presp = OCSP_REQ_CTX_D2I(rctx, OCSP_RESPONSE)) == NULL)
        rv = 0;
    return rv;
}



/* Blocking OCSP request handler: now a special case of non-blocking I/O */
/* Note that OCSP_sendreq_bio was unused and contained a busy loop :-( and
   is now supeseded by OCSP_query_responder(b, NULL, path, NULL, req, -1) */

OCSP_RESPONSE *OCSP_query_responder(BIO *cbio, const char *host,
                                    const char *path,
                                    const STACK_OF(CONF_VALUE) *headers,
                                    OCSP_REQUEST *req, int req_timeout)
{
    int rv;
    int i;
    int add_host = 1;
    OCSP_RESPONSE *rsp = NULL;
    OCSP_REQ_CTX *ctx = OCSP_sendreq_new(cbio, path, req, -1, req_timeout);
    if (ctx == NULL)
        return NULL;

    for (i = 0; i < sk_CONF_VALUE_num(headers); i++) {
        CONF_VALUE *hdr = sk_CONF_VALUE_value(headers, i);
        if (add_host == 1 && strcasecmp("host", hdr->name) == 0)
            add_host = 0;
        if (!OCSP_REQ_CTX_add1_header(ctx, hdr->name, hdr->value))
            goto err;
    }

    if (add_host == 1 && host != NULL &&
        OCSP_REQ_CTX_add1_header(ctx, "Host", host) == 0)
        goto err;

    rv = OCSP_REQ_CTX_sendreq(ctx);
    if (rv == 1)
        rsp = OCSP_REQ_CTX_D2I(ctx, OCSP_RESPONSE);
 err:
    OCSP_REQ_CTX_free(ctx);

    return rsp;
}
