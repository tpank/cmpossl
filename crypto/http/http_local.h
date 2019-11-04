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

#ifndef OSSL_CRYPTO_HTTP_LOCAL_H
# define OSSL_CRYPTO_HTTP_LOCAL_H

OSSL_HTTP_REQ_CTX *HTTP_sendreq_new(BIO *bio, const char *path,
                                    const char *server, const char *port,
                                    const STACK_OF(CONF_VALUE) *headers,
                                    const char *host, const char *content_type,
                                    const ASN1_ITEM *it, ASN1_VALUE *req,
                                    long timeout, int maxline);
ASN1_VALUE *HTTP_sendreq_bio(BIO *bio,
                             HTTP_bio_cb_t bio_update_fn, void *arg,
                             const char *server, const char *port,
                             const char *path,
                             const STACK_OF(CONF_VALUE) *headers,
                             const char *host, const char *content_type,
                             ASN1_VALUE *req, const ASN1_ITEM *req_it,
                             int timeout, int maxline,
                             const ASN1_ITEM *rsp_it);

#endif /* !defined OSSL_CRYPTO_HTTP_LOCAL_H */
