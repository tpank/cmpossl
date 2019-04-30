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

/* generic helper functions */

#include <openssl/cmp_util.h>
#include <openssl/err.h>
#include <openssl/cmperr.h>
#include <openssl/x509v3.h>

/*-
 * Append/prepend cert to given list, optionally only if not already contained
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_sk_X509_add1_cert(STACK_OF(X509) *sk, X509 *cert,
                               int not_duplicate, int prepend)
{
    if (not_duplicate) {
        /* not using sk_X509_set_cmp_func() and sk_X509_find()
           because this re-orders the certs on the stack */
        int i;
        for (i = 0; i < sk_X509_num(sk); i++)
            if (X509_cmp(sk_X509_value(sk, i), cert) == 0)
                return 1;
    }
    if (!sk_X509_insert(sk, cert, prepend ? 0 : -1))
        return 0;
    return X509_up_ref(cert);
}

/*-
 * Append list of certificates from 'certs' to given list,
 * optionally only if not self-signed and
 * optionally only if not already contained.
 * The certs parameter may be NULL.
 * returns 1 on success, 0 on error
 */
int OSSL_CMP_sk_X509_add1_certs(STACK_OF(X509) *sk, const STACK_OF(X509) *certs,
                                int no_self_signed, int no_duplicates)
{
    int i;

    if (sk == NULL)
        return 0;

    if (certs == NULL)
        return 1;
    for (i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);
        if (!no_self_signed || X509_check_issued(cert, cert) != X509_V_OK) {
            if (!OSSL_CMP_sk_X509_add1_cert(sk, cert, no_duplicates, 0))
                return 0;
        }
    }
    return 1;
}

X509_EXTENSIONS *OSSL_CMP_X509_EXTENSIONS_dup(const X509_EXTENSIONS *extin)
{
    X509_EXTENSIONS *exts;
    int i;

    if (extin == NULL)
        return NULL;

    if ((exts = sk_X509_EXTENSION_new_null()) == NULL)
        return NULL;
    for (i = 0; i < sk_X509_EXTENSION_num(extin); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(extin, i);
        if (!sk_X509_EXTENSION_push(exts, X509_EXTENSION_dup(ext)))
        {
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            return NULL;
        }
    }
    return exts;
}

/*
 * free any previous value of the variable referenced via tgt
 * and assign either a copy of the src ASN1_OCTET_STRING or NULL.
 * returns 1 on success, 0 on error.
 */
int OSSL_CMP_ASN1_OCTET_STRING_set1(ASN1_OCTET_STRING **tgt,
                                    const ASN1_OCTET_STRING *src)
{
    if (tgt == NULL) {
        CMPerr(CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1, CMP_R_NULL_ARGUMENT);
        goto err;
    }
    if (*tgt == src) /* self-assignment */
        return 1;
    ASN1_OCTET_STRING_free(*tgt);

    if (src != NULL) {
        if (!(*tgt = ASN1_OCTET_STRING_dup(src))) {
            CMPerr(CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        *tgt = NULL;

    return 1;
 err:
    return 0;
}

/*
 * free any previous value of the variable referenced via tgt
 * and assign either a copy of the byte string (with given length) or NULL.
 * returns 1 on success, 0 on error.
 */
int OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(ASN1_OCTET_STRING **tgt,
                                          const unsigned char *bytes, size_t len)
{
    ASN1_OCTET_STRING *new = NULL;
    int res = 0;

    if (tgt == NULL) {
        CMPerr(CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1_BYTES, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    if (bytes != NULL) {
        if (!(new = ASN1_OCTET_STRING_new())
                || !(ASN1_OCTET_STRING_set(new, bytes, (int)len))) {
            CMPerr(CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1_BYTES,
                   ERR_R_MALLOC_FAILURE);
            goto err;
        }

    }
    res = OSSL_CMP_ASN1_OCTET_STRING_set1(tgt, new);

 err:
    ASN1_OCTET_STRING_free(new);
    return res;
}


