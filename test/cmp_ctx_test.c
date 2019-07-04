/*
 * Copyright 2007-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2018
 * Copyright Siemens AG 2015-2018
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * CMP tests by Martin Peylo, Tobias Pankert, and David von Oheimb.
 */

#include "cmp_testlib.h"

typedef struct test_fixture {
    const char *test_case_name;
    OSSL_CMP_CTX *ctx;
} OSSL_CMP_CTX_TEST_FIXTURE;

static void tear_down(OSSL_CMP_CTX_TEST_FIXTURE *fixture)
{
    if (fixture != NULL)
        OSSL_CMP_CTX_free(fixture->ctx);
    OPENSSL_free(fixture);
}

static OSSL_CMP_CTX_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    OSSL_CMP_CTX_TEST_FIXTURE *fixture;

    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture)))
            || !TEST_ptr(fixture->ctx = OSSL_CMP_CTX_new())) {
        tear_down(fixture);
        return NULL;
    }
    fixture->test_case_name = test_case_name;
    return fixture;
}

static int execute_CTX_reqExtensions_have_SAN_test(OSSL_CMP_CTX_TEST_FIXTURE *
                                                   fixture)
{
    const int len = 16;
    unsigned char str[16/* len */];
    ASN1_OCTET_STRING *data = NULL;
    X509_EXTENSION *ext = NULL;
    X509_EXTENSIONS *exts = NULL;

    if (!TEST_false(OSSL_CMP_CTX_reqExtensions_have_SAN(fixture->ctx)))
        return 0;

    if (!TEST_int_eq(1, RAND_bytes(str, len))
            || !TEST_ptr(data = ASN1_OCTET_STRING_new())
            || !TEST_true(ASN1_OCTET_STRING_set(data, str, len))
            || !TEST_ptr(ext =
                         X509_EXTENSION_create_by_NID(NULL,
                                                      NID_subject_alt_name, 0,
                                                      data))
            || !TEST_ptr(exts = sk_X509_EXTENSION_new_null())
            || !TEST_true(sk_X509_EXTENSION_push(exts, ext))
            || !TEST_true(OSSL_CMP_CTX_set0_reqExtensions(fixture->ctx,
                                                          exts))) {
        ASN1_OCTET_STRING_free(data);
        X509_EXTENSION_free(ext);
        sk_X509_EXTENSION_free(exts);
        return 0;
    }
    ASN1_OCTET_STRING_free(data);
    return TEST_true(OSSL_CMP_CTX_reqExtensions_have_SAN(fixture->ctx));
}

static int test_CTX_reqExtensions_have_SAN(void)
{
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up);
    EXECUTE_TEST(execute_CTX_reqExtensions_have_SAN_test, tear_down);
    return result;
}

#ifndef OPENSSL_NO_TRACE
static int test_log_line;
static int test_log_ok = 0;
static int test_log_cb(const char *func, const char *file, int line,
                       OSSL_CMP_severity level, const char *msg)
{
    test_log_ok =
#ifndef PEDANTIC
        strcmp(func, "execute_cmp_ctx_log_cb_test") == 0 &&
#endif
        (strcmp(file, OPENSSL_FILE) == 0 || strcmp(file, "(no file)") == 0)
        && (line == test_log_line || line == 0)
        && (level == OSSL_CMP_LOG_INFO || level == -1)
        && strcmp(msg, "CMP INFO: ok\n") == 0;
    return 1;
}

static int execute_cmp_ctx_log_cb_test(OSSL_CMP_CTX_TEST_FIXTURE *fixture)
{
    OSSL_TRACE(ALL, "this general trace message is not shown by default\n");
    OSSL_CMP_log_open();
    OSSL_CMP_log_open(); /* multiple calls should be harmless */
    OSSL_CMP_debug("this should be shown as CMP debug message");
    OSSL_CMP_warn("this should be shown as CMP warning message");
    if (TEST_true(OSSL_CMP_CTX_set_log_cb(fixture->ctx, test_log_cb))) {
        test_log_line = OPENSSL_LINE + 1;
        OSSL_CMP_log2(INFO, "%s%c", "o", 'k');
    }
    OSSL_CMP_log_close();
    OSSL_CMP_log_close(); /* multiple calls should be harmless */
    return test_log_ok;
}

static int test_cmp_ctx_log_cb(void)
{
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up);
    EXECUTE_TEST(execute_cmp_ctx_log_cb_test, tear_down);
    return result;
}
#endif

void cleanup_tests(void)
{
    return;
}

int setup_tests(void)
{
    ADD_TEST(test_CTX_reqExtensions_have_SAN);
#ifndef OPENSSL_NO_TRACE
    ADD_TEST(test_cmp_ctx_log_cb);
#endif

    return 1;
}
