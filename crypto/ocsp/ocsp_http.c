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

#include <openssl/ocsp.h>
#include <openssl/http.h>

#ifndef OPENSSL_NO_OCSP

HTTP_REQ_CTX *OCSP_sendreq_new(BIO *io, const char *path, OCSP_REQUEST *req,
                               int maxline)
{
    return HTTP_sendreq_new(io, path,
                            NULL, NULL, /* no proxy used */
                            "application/ocsp-request",
                            ASN1_ITEM_rptr(OCSP_REQUEST), (ASN1_VALUE *)req,
                            maxline);
}

int OCSP_REQ_CTX_set1_req(HTTP_REQ_CTX *rctx, const OCSP_REQUEST *req)
{
    return HTTP_REQ_CTX_i2d(rctx, "application/ocsp-request",
                            ASN1_ITEM_rptr(OCSP_REQUEST), (ASN1_VALUE *)req);
}

# if !defined(OPENSSL_NO_SOCK)

int OCSP_sendreq(OCSP_RESPONSE **presp, HTTP_REQ_CTX *rctx, time_t max_time)
{
    *presp = (OCSP_RESPONSE *)
        HTTP_REQ_CTX_sendreq_d2i(rctx, max_time, ASN1_ITEM_rptr(OCSP_RESPONSE));
    return *presp != NULL;
}

OCSP_RESPONSE *OCSP_sendreq_bio(BIO *b, const char *path, OCSP_REQUEST *req)
{
    OCSP_RESPONSE *resp = NULL;
    HTTP_REQ_CTX *ctx;
    int rv;

    ctx = OCSP_sendreq_new(b, path, req, -1 /* default max resp line length */);
    if (ctx == NULL)
        return NULL;

    rv = OCSP_sendreq(&resp, ctx, 0 /* max_time */);

    /* this indirectly calls ERR_clear_error(): */
    HTTP_REQ_CTX_free(ctx);

    return rv == 1 ? resp : NULL;
}
# endif

#endif
