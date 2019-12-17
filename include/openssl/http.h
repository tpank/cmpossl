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


# ifdef __cplusplus
extern "C" {
# endif

typedef BIO *(*HTTP_bio_cb_t) (BIO *bio, void *arg, int connect, int detail);
# ifndef OPENSSL_NO_SOCK
ASN1_VALUE *OSSL_HTTP_get_asn1(const char *url,
                               const char *proxy, const char *proxy_port,
                               HTTP_bio_cb_t bio_update_fn, void *arg,
                               const STACK_OF(CONF_VALUE) *headers,
                               int maxline, unsigned long max_resp_len,
                               long timeout, const ASN1_ITEM *it);
ASN1_VALUE *OSSL_HTTP_post_asn1(const char *server, const char *port,
                                const char *path, int use_ssl,
                                const char *proxy, const char *proxy_port,
                                HTTP_bio_cb_t bio_update_fn, void *arg,
                                const STACK_OF(CONF_VALUE) *headers,
                                const char *content_type,
                                ASN1_VALUE *req, const ASN1_ITEM *req_it,
                                int maxline, unsigned long max_resp_len,
                                long timeout, const ASN1_ITEM *rsp_it);
int OSSL_HTTP_proxy_connect(BIO *bio, const char *server, const char *port,
                            const char *proxyuser, const char *proxypass,
                            long timeout, BIO *bio_err, const char *prog);
# endif
int OSSL_HTTP_parse_url(const char *url, char **phost, char **pport,
                        char **ppath, int *pssl);

/*
 * The following functions are used only internally but are kept public under
 * their original name (with prefix "OCSP_") just for backward compatibility.
 */
# ifndef OPENSSL_NO_OCSP
/* The parameters of this fn, which never was documented, have been changed: */
OCSP_REQ_CTX *OCSP_REQ_CTX_new(BIO *io, int method_GET, int maxline,
                               unsigned long max_resp_len, long timeout);
void OCSP_REQ_CTX_free(OCSP_REQ_CTX *rctx);
BIO *OCSP_REQ_CTX_get0_mem_bio(OCSP_REQ_CTX *rctx);
void OCSP_set_max_response_length(OCSP_REQ_CTX *rctx, unsigned long len);
/* The parameters of this fn, which never was documented, have been changed: */
int OCSP_REQ_CTX_http(OCSP_REQ_CTX *rctx,
                      const char *server, const char *port, const char *path);
int OCSP_REQ_CTX_add1_header(OCSP_REQ_CTX *rctx,
                             const char *name, const char *value);
/* The parameters of this fn, which never was documented, have been extended: */
int OCSP_REQ_CTX_i2d(OCSP_REQ_CTX *rctx, const char *content_type,
                     const ASN1_ITEM *it, ASN1_VALUE *req);
int OCSP_REQ_CTX_nbio(OCSP_REQ_CTX *rctx);
#  ifndef OPENSSL_NO_SOCK
/* The type of this fn, which never was documented, has been changed: */
ASN1_VALUE *OCSP_REQ_CTX_nbio_d2i(OCSP_REQ_CTX *rctx, const ASN1_ITEM *it);
#  endif
# endif

# ifdef  __cplusplus
}
# endif
#endif /* !defined OPENSSL_HTTP_H */
