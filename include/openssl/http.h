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

# include <openssl/opensslconf.h>

# include <openssl/bio.h>
# include <openssl/asn1.h>
# include <openssl/conf.h>

# ifdef  __cplusplus
extern "C" {
# endif

int HTTP_parse_url(const char *url, char **phost, char **pport, char **ppath,
                   int *pssl);
/* TODO: unexport this (undocumented and actually just internal) function? */
OSSL_HTTP_REQ_CTX *OSSL_HTTP_REQ_CTX_new(BIO *io, long timeout, int maxline);
/* TODO: unexport this (documented but) meanwhile just internal function? */
void OSSL_HTTP_REQ_CTX_free(OSSL_HTTP_REQ_CTX *rctx);
/* TODO: unexport this (undocumented and actually just internal) function? */
BIO *OSSL_HTTP_REQ_CTX_get0_mem_bio(OSSL_HTTP_REQ_CTX *rctx);
/* TODO: unexport this (documented but) meanwhile just internal function? */
void OSSL_HTTP_REQ_CTX_set_max_response_length(OSSL_HTTP_REQ_CTX *rctx,
                                               unsigned long len);
/* TODO: unexport this (undocumented and actually just internal) function? */
int OSSL_HTTP_REQ_CTX_header(OSSL_HTTP_REQ_CTX *rctx, const char *op,
                             const char *path,
                             const char *server, const char *port);
/* TODO: unexport this (documented but) meanwhile just internal function? */
int OSSL_HTTP_REQ_CTX_add1_header(OSSL_HTTP_REQ_CTX *rctx,
                                  const char *name, const char *value);
/* TODO: unexport this (undocumented and actually just internal) function? */
int OSSL_HTTP_REQ_CTX_i2d(OSSL_HTTP_REQ_CTX *rctx, const char *content_type,
                          const ASN1_ITEM *it, ASN1_VALUE *req);
/* TODO: unexport this (undocumented and actually just internal) function? */
int OSSL_HTTP_REQ_CTX_nbio(OSSL_HTTP_REQ_CTX *rctx);
# ifndef OPENSSL_NO_SOCK
/* TODO: unexport this (undocumented and actually just internal) function? */
ASN1_VALUE *OSSL_HTTP_REQ_CTX_sendreq_d2i(OSSL_HTTP_REQ_CTX *rctx,
                                          const ASN1_ITEM *it);
typedef BIO *(*HTTP_bio_cb_t) (void *ctx, BIO *bio, unsigned long detail);
ASN1_VALUE *OSSL_HTTP_post_asn1(const char *host, const char *port,
                                HTTP_bio_cb_t bio_update_fn, void *arg,
                                const char *path,
                                const char *proxy, const char *proxy_port,
                                const STACK_OF(CONF_VALUE) *headers,
                                const char *content_type,
                                ASN1_VALUE *req, const ASN1_ITEM *req_it,
                                int timeout, int maxline,
                                const ASN1_ITEM *rsp_it);
ASN1_VALUE *OSSL_HTTP_get_asn1(const char *url,
                               const char *proxy, const char *proxy_port,
                               int timeout, const ASN1_ITEM *it);
int OSSL_HTTP_proxy_connect(BIO *bio, const char *server, const char *port,
                            const char *proxyuser, const char *proxypass,
                            long timeout, BIO *bio_err, const char *prog);
# endif

# ifdef  __cplusplus
}
# endif
#endif /* !defined OPENSSL_HTTP_H */
