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

int OCSP_REQ_CTX_set1_req(HTTP_REQ_CTX *rctx, OCSP_REQUEST *req)
{
    return HTTP_REQ_CTX_i2d(rctx, "application/ocsp-request",
                            ASN1_ITEM_rptr(OCSP_REQUEST), (ASN1_VALUE *)req);
}

HTTP_REQ_CTX *OCSP_sendreq_new(BIO *io, const char *path, OCSP_REQUEST *req,
                               int maxline)
{
    return HTTP_sendreq_new(io, path, "application/ocsp-request",
                            ASN1_ITEM_rptr(OCSP_REQUEST), (ASN1_VALUE *)req,
                            maxline);
}

int OCSP_sendreq_nbio(OCSP_RESPONSE **presp, HTTP_REQ_CTX *rctx)
{
    return HTTP_REQ_CTX_nbio_d2i(rctx,
                                 (ASN1_VALUE **)presp,
                                 ASN1_ITEM_rptr(OCSP_RESPONSE));
}

/* Blocking HTTP request handler: now a special case of non-blocking I/O */

OCSP_RESPONSE *OCSP_sendreq_bio(BIO *b, const char *path, OCSP_REQUEST *req)
{
    OCSP_RESPONSE *resp = NULL;
    HTTP_REQ_CTX *ctx;
    int rv;

    ctx = OCSP_sendreq_new(b, path, req, -1);

    if (ctx == NULL)
        return NULL;

    do {
        rv = OCSP_sendreq_nbio(&resp, ctx);
    } while ((rv == -1) && BIO_should_retry(b));

    HTTP_REQ_CTX_free(ctx);

    if (rv)
        return resp;

    return NULL;
}

#endif
