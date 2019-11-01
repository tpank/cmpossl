/*
 * Copyright 2000-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HTTP_H
# define OPENSSL_HTTP_H
# pragma once

# include <openssl/macros.h>
# if !OPENSSL_API_3
#  define HEADER_HTTP_H
# endif

# include <openssl/bio.h>
# include <openssl/asn1.h>

# ifdef  __cplusplus
extern "C" {
# endif

int HTTP_parse_url(const char *url, char **phost, char **pport, char **ppath,
                   int *pssl);

int HTTP_REQ_CTX_nbio(HTTP_REQ_CTX *rctx);
HTTP_REQ_CTX *HTTP_REQ_CTX_new(BIO *io, int maxline);
void HTTP_REQ_CTX_free(HTTP_REQ_CTX *rctx);
void HTTP_set_max_response_length(HTTP_REQ_CTX *rctx, unsigned long len);
int HTTP_REQ_CTX_i2d(HTTP_REQ_CTX *rctx, const char *content_type,
                     const ASN1_ITEM *it, ASN1_VALUE *req);
int HTTP_REQ_CTX_nbio_d2i(HTTP_REQ_CTX *rctx, ASN1_VALUE **pval,
                          const ASN1_ITEM *it);
BIO *HTTP_REQ_CTX_get0_mem_bio(HTTP_REQ_CTX *rctx);
int HTTP_REQ_CTX_http(HTTP_REQ_CTX *rctx, const char *op, const char *path);
int HTTP_REQ_CTX_add1_header(HTTP_REQ_CTX *rctx,
                             const char *name, const char *value);
HTTP_REQ_CTX *HTTP_sendreq_new(BIO *io, const char *path,
                               const char *content_type, const ASN1_ITEM *it,
                               ASN1_VALUE *req, int maxline);
int HTTP_proxy_connect(BIO *bio, const char *server, int port, long timeout,
                       BIO *bio_err, const char *prog);

# ifdef  __cplusplus
}
# endif
#endif /* !defined OPENSSL_HTTP_H */
