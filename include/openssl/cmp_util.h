/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

#ifndef OSSL_HEADER_CMP_UTIL_H
# define OSSL_HEADER_CMP_UTIL_H

# include <openssl/x509.h>

int OSSL_CMP_sk_X509_add1_cert (STACK_OF(X509) *sk, X509 *cert,
                                int not_duplicate, int prepend);
int OSSL_CMP_sk_X509_add1_certs(STACK_OF(X509) *sk, const STACK_OF(X509) *certs,
                                int no_self_signed, int no_duplicates);
X509_EXTENSIONS *OSSL_CMP_X509_EXTENSIONS_dup(const X509_EXTENSIONS *e);
int OSSL_CMP_ASN1_OCTET_STRING_set1(ASN1_OCTET_STRING **tgt,
                                    const ASN1_OCTET_STRING *src);
int OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(ASN1_OCTET_STRING **tgt,
                                          const unsigned char *bytes,
                                          size_t len);

#endif /* !defined OSSL_HEADER_CMP_UTIL_H */
