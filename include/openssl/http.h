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
# ifndef OPENSSL_NO_SOCK
BIO *HTTP_new_bio(const char *server, const char *server_port,
                  const char *proxy, const char *proxy_port);
# endif

HTTP_REQ_CTX *HTTP_sendreq_new(BIO *bio, const char *path,
                               const char *server, const char *port,
                               const STACK_OF(CONF_VALUE) *headers,
                               const char *host,
                               const char *content_type, const ASN1_ITEM *it,
                               ASN1_VALUE *req, long timeout, int maxline);
/* TODO: unexport this (undocumented and actually just internal) function? */
HTTP_REQ_CTX *HTTP_REQ_CTX_new(BIO *io, long timeout, int maxline);
void HTTP_REQ_CTX_free(HTTP_REQ_CTX *rctx);
/* TODO: unexport this (undocumented and actually just internal) function? */
BIO *HTTP_REQ_CTX_get0_mem_bio(HTTP_REQ_CTX *rctx);
void HTTP_REQ_CTX_set_max_resp_len(HTTP_REQ_CTX *rctx, unsigned long len);
int HTTP_REQ_CTX_http(HTTP_REQ_CTX *rctx, const char *op, const char *path,
                      const char *server, const char *port);
int HTTP_REQ_CTX_add1_header(HTTP_REQ_CTX *rctx,
                             const char *name, const char *value);
/* TODO: unexport this (undocumented and actually just internal) function? */
int HTTP_REQ_CTX_i2d(HTTP_REQ_CTX *rctx, const char *content_type,
                     const ASN1_ITEM *it, ASN1_VALUE *req);
/* TODO: unexport this (undocumented and actually just internal) function? */
int HTTP_REQ_CTX_nbio(HTTP_REQ_CTX *rctx);
# ifndef OPENSSL_NO_SOCK
/* TODO: unexport this (undocumented and actually just internal) function? */
ASN1_VALUE *HTTP_REQ_CTX_sendreq_d2i(HTTP_REQ_CTX *rctx, const ASN1_ITEM *it);
ASN1_VALUE *HTTP_sendreq_bio(BIO *bio, const char *server,
                             const char *port, const char *path,
                             const STACK_OF(CONF_VALUE) *headers,
                             const char *host, const char *content_type,
                             ASN1_VALUE *req, const ASN1_ITEM *req_it,
                             int timeout, int maxline, const ASN1_ITEM *rsp_it);
ASN1_VALUE *HTTP_get_asn1(const char *url,
                          const char *proxy, const char *proxy_port,
                          int timeout, const ASN1_ITEM *it);
int HTTP_proxy_connect(BIO *bio, const char *server, const char *port,
                       const char *proxyuser, const char *proxypass,
                       long timeout, BIO *bio_err, const char *prog);
# endif

# ifdef  __cplusplus
}
# endif
#endif /* !defined OPENSSL_HTTP_H */
