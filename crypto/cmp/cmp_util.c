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

#include <string.h>
#include <openssl/cmp_util.h>
#include <openssl/cmperr.h>
#include <openssl/x509v3.h>

#include "cmp_int.h"

/*
 * convenience functions for CMP-specific logging via the trace API
 */

int OSSL_CMP_log_open(void) /* is designed to be idempotent */
{
    BIO *bio_out = NULL;

    (void)OSSL_trace_set_verbosity(OSSL_TRACE_CATEGORY_CMP,
                                   OSSL_TRACE_LEVEL_INFO);
#ifndef OPENSSL_NO_STDIO
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    return bio_out != NULL
               && OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_CMP, bio_out);
#else
    return 1;
#endif
}

void OSSL_CMP_log_close(void) /* is designed to be idempotent */
{
    (void)OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_CMP, NULL);
}

/*
 * auxiliary function for incrementally reporting texts via the error queue
 */

void OSSL_CMP_add_error_txt(const char *separator, const char *txt)
{
    const char *file;
    int line;
    const char *data;
    int flags;
    unsigned long err = ERR_peek_last_error();

    if (separator == NULL)
        separator = "";
    if (err == 0)
        ERR_PUT_error(ERR_LIB_CMP, 0, err, "", 0);

#define MAX_DATA_LEN 4096-100 /* workaround for ERR_print_errors_cb() limit */
    do {
        const char *curr, *next;
        int len;
        char *tmp;

        ERR_peek_last_error_line_data(&file, &line, &data, &flags);
        if ((flags & ERR_TXT_STRING) == 0) {
            data = "";
            separator = "";
        }
        len = (int)strlen(data);
        curr = next = txt;
        while (*next != '\0'
                   && len + strlen(separator) + (next - txt) < MAX_DATA_LEN) {
            curr = next;
            if (*separator != '\0') {
                next = strstr(curr, separator);
                if (next != NULL)
                    next += strlen(separator);
                else
                    next = curr + strlen(curr);
            } else
                next = curr + 1;
        }
        if (*next != '\0') { /* split error msg if error data gets too long */
            if (curr != txt) {
                tmp = OPENSSL_strndup(txt, curr - txt);
                ERR_add_error_data(2, separator, tmp);
                OPENSSL_free(tmp);
            }
            ERR_PUT_error(ERR_LIB_CMP, 0 /* func */, err, file, line);
            txt = curr;
        } else {
            ERR_add_error_data(2, separator, txt);
            txt = next;
        }
    } while (*txt != '\0');
}

/* this is similar to ERR_print_errors_cb, but uses the CMP-specific cb type */
void OSSL_CMP_print_errors_cb(OSSL_cmp_log_cb_t log_fn)
{
    unsigned long err;
    char component[256];
    char msg[4096];
    const char *file, *data;
    int line, flags;

    if (log_fn == NULL) {
#ifndef OPENSSL_NO_STDIO
        BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

        ERR_print_errors(bio_err);
        BIO_free(bio_err);
#endif
        return;
    }

    while ((err = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        if (!(flags & ERR_TXT_STRING))
            data = NULL;
        BIO_snprintf(component, sizeof(component), "OpenSSL:%s",
                     /* ERR_lib_error_string(err), */
                     ERR_func_error_string(err));
        BIO_snprintf(msg, sizeof(msg), "%s%s%s", ERR_reason_error_string(err),
                     data == NULL ? "" : " : ", data == NULL ? "" : data);
        if (log_fn(component, file, line, OSSL_CMP_LOG_ERR, msg) <= 0)
            break;              /* abort outputting the error report */
    }
}

/*
 * functions manipulating lists of certificates etc.
 */

int OSSL_CMP_sk_X509_add1_cert(STACK_OF(X509) *sk, X509 *cert,
                               int not_duplicate, int prepend)
{
    if (not_duplicate) {
        /*
         * not using sk_X509_set_cmp_func() and sk_X509_find()
         * because this re-orders the certs on the stack
         */
        int i;

        for (i = 0; i < sk_X509_num(sk); i++) {
            if (X509_cmp(sk_X509_value(sk, i), cert) == 0)
                return 1;
        }
    }
    if (!sk_X509_insert(sk, cert, prepend ? 0 : -1))
        return 0;
    return X509_up_ref(cert);
}

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

int OSSL_CMP_X509_STORE_add1_certs(X509_STORE *store, STACK_OF(X509) *certs,
                                   int only_self_signed)
{
    int i;

    if (store == NULL)
        return 0;

    if (certs == NULL)
        return 1;
    for (i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);

        if (!only_self_signed || X509_check_issued(cert, cert) == X509_V_OK)
            if (!X509_STORE_add_cert(store, cert)) /* ups cert ref counter */
                return 0;
    }
    return 1;
}

STACK_OF(X509) *OSSL_CMP_X509_STORE_get1_certs(X509_STORE *store)
{
    int i;
    STACK_OF(X509) *sk;
    STACK_OF(X509_OBJECT) *objs;

    if (store == NULL)
        return NULL;
    if ((sk = sk_X509_new_null()) == NULL)
        return NULL;
    objs = X509_STORE_get0_objects(store);
    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        X509 *cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));
        if (cert != NULL) {
            if (!sk_X509_push(sk, cert)) {
                sk_X509_pop_free(sk, X509_free);
                return NULL;
            }
            X509_up_ref(cert);
        }
    }
    return sk;
}

X509_EXTENSIONS *CMP_X509_EXTENSIONS_dup(const X509_EXTENSIONS *exts)
{
    if (exts == NULL)
        return NULL;
    return sk_X509_EXTENSION_deep_copy(exts, X509_EXTENSION_dup,
                                       X509_EXTENSION_free);
}

int CMP_ASN1_OCTET_STRING_set1(ASN1_OCTET_STRING **tgt,
                               const ASN1_OCTET_STRING *src)
{
    if (tgt == NULL) {
        CMPerr(CMP_F_CMP_ASN1_OCTET_STRING_SET1, CMP_R_NULL_ARGUMENT);
        goto err;
    }
    if (*tgt == src) /* self-assignment */
        return 1;
    ASN1_OCTET_STRING_free(*tgt);

    if (src != NULL) {
        if ((*tgt = ASN1_OCTET_STRING_dup(src)) == NULL) {
            CMPerr(CMP_F_CMP_ASN1_OCTET_STRING_SET1, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else {
        *tgt = NULL;
    }

    return 1;
 err:
    return 0;
}

int CMP_ASN1_OCTET_STRING_set1_bytes(ASN1_OCTET_STRING **tgt,
                                     const unsigned char *bytes, int len)
{
    ASN1_OCTET_STRING *new = NULL;
    int res = 0;

    if (tgt == NULL) {
        CMPerr(CMP_F_CMP_ASN1_OCTET_STRING_SET1_BYTES, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    if (bytes != NULL) {
        if ((new = ASN1_OCTET_STRING_new()) == NULL
                || !(ASN1_OCTET_STRING_set(new, bytes, len))) {
            CMPerr(CMP_F_CMP_ASN1_OCTET_STRING_SET1_BYTES, ERR_R_MALLOC_FAILURE);
            goto err;
        }

    }
    res = CMP_ASN1_OCTET_STRING_set1(tgt, new);

 err:
    ASN1_OCTET_STRING_free(new);
    return res;
}
