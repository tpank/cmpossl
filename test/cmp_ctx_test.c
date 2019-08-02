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

#define DECLARE_SET0_GET0_BASE_TEST(METHODNAME, VALUETYPE, ALLOCATOR) \
\
static int execute_CTX_ ## METHODNAME ## _set0_get0 \
    (OSSL_CMP_CTX_TEST_FIXTURE * fixture) \
{ \
    VALUETYPE* firstValue= ALLOCATOR (); \
    if (OSSL_CMP_CTX_set0_ ## METHODNAME(NULL, firstValue)) { \
            TEST_error("%s: CTX != NULL not checked", fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    if (!OSSL_CMP_CTX_set0_ ## METHODNAME(fixture->ctx, firstValue)) { \
            TEST_error("%s: setting value failed", fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    if (OSSL_CMP_CTX_get0_ ## METHODNAME(fixture->ctx) != firstValue) { \
            TEST_error("%s: set/get firstValue did not match", \
                       fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    VALUETYPE* secondValue= ALLOCATOR (); \
    if (OSSL_CMP_CTX_set0_ ## METHODNAME(NULL, secondValue)) { \
             TEST_error("%s: CTX != NULL not checked", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     if (!OSSL_CMP_CTX_set0_ ## METHODNAME(fixture->ctx, secondValue)) { \
             TEST_error("%s: setting secondValue failed", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     if (OSSL_CMP_CTX_get0_ ## METHODNAME(fixture->ctx) != secondValue) { \
             TEST_error("%s: set/get secondValue did not match", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
    return 1; \
} \
\
static int test_CTX_ ## METHODNAME ## _set0_get0(void) \
{ \
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up); \
    EXECUTE_TEST(execute_CTX_ ## METHODNAME ## _set0_get0 , tear_down); \
    return result; \
} \

#define DECLARE_SET0_GET0_TEST(METHODNAME, VALUETYPE) \
    DECLARE_SET0_GET0_BASE_TEST(METHODNAME, VALUETYPE, VALUETYPE ## _new)

#define DECLARE_SET0_GET0_STACK_OF_TEST(METHODNAME, STACK_TYPE) \
    DECLARE_SET0_GET0_BASE_TEST(METHODNAME, STACK_OF(STACK_TYPE), \
                           sk_ ## STACK_TYPE ## _new_null)

#define DECLARE_SET1_GET0_BASE_TEST( \
                              METHODNAME, VALUETYPE, ALLOCATOR, DEALLOCATOR) \
\
static int execute_CTX_ ## METHODNAME ## _set1_get0 \
    (OSSL_CMP_CTX_TEST_FIXTURE * fixture) \
{ \
    VALUETYPE* firstValue= ALLOCATOR (); \
    if (OSSL_CMP_CTX_set1_ ## METHODNAME(NULL, firstValue)) { \
            TEST_error("%s: CTX != NULL not checked", fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    if (!OSSL_CMP_CTX_set1_ ## METHODNAME(fixture->ctx, firstValue)) { \
            TEST_error("%s: setting value failed", fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    VALUETYPE* firstGetValue = OSSL_CMP_CTX_get0_ ## METHODNAME(fixture->ctx); \
    if (firstGetValue == firstValue) { \
            TEST_error("%s: first set did not copy the value as expected", \
                       fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    if (firstGetValue == NULL) { \
            TEST_error("%s: first set had no effect", \
                       fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    VALUETYPE* secondValue = ALLOCATOR (); \
    if (OSSL_CMP_CTX_set1_ ## METHODNAME(NULL, secondValue)) { \
             TEST_error("%s: CTX != NULL not checked", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     if (!OSSL_CMP_CTX_set1_ ## METHODNAME(fixture->ctx, secondValue)) { \
             TEST_error("%s: setting secondValue failed", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     VALUETYPE* secondGetValue = OSSL_CMP_CTX_get0_ ## METHODNAME(fixture->ctx); \
     if (secondGetValue == NULL) { \
             TEST_error("%s: first set reset to NULL", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     if (secondGetValue == secondValue) { \
             TEST_error("%s: second set did not copy the value as expected", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     DEALLOCATOR (firstValue); \
     DEALLOCATOR (secondValue); \
    return 1; \
} \
\
static int test_CTX_ ## METHODNAME ## _set1_get0(void) \
{ \
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up); \
    EXECUTE_TEST(execute_CTX_ ## METHODNAME ## _set1_get0 , tear_down); \
    return result; \
} \

#define DECLARE_SET1_GET0_TEST(METHODNAME, VALUETYPE) \
    DECLARE_SET1_GET0_BASE_TEST(METHODNAME, VALUETYPE, \
                           VALUETYPE ## _new, VALUETYPE ## _free)

#define DECLARE_SET1_GET0_STACK_OF_TEST(METHODNAME, STACK_TYPE) \
    DECLARE_SET1_GET0_BASE_TEST(METHODNAME, STACK_OF(STACK_TYPE), \
                           sk_ ## STACK_TYPE ## _new_null, \
                           sk_ ## STACK_TYPE ## _free)

#define DECLARE_SET1_GET1_BASE_TEST( \
                              METHODNAME, VALUETYPE, ALLOCATOR, DEALLOCATOR) \
\
static int execute_CTX_ ## METHODNAME ## _set1_get1 \
    (OSSL_CMP_CTX_TEST_FIXTURE * fixture) \
{ \
    VALUETYPE* firstValue= ALLOCATOR (); \
    if (OSSL_CMP_CTX_set1_ ## METHODNAME(NULL, firstValue)) { \
            TEST_error("%s: CTX != NULL not checked", fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    if (!OSSL_CMP_CTX_set1_ ## METHODNAME(fixture->ctx, firstValue)) { \
            TEST_error("%s: setting value failed", fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    VALUETYPE* firstGetValue = OSSL_CMP_CTX_get1_ ## METHODNAME(fixture->ctx); \
    if (firstGetValue == firstValue) { \
            TEST_error("%s: first set did not copy the value as expected", \
                       fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    if (firstGetValue == NULL) { \
            TEST_error("%s: first set had no effect", \
                       fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    VALUETYPE* secondValue = ALLOCATOR (); \
    if (OSSL_CMP_CTX_set1_ ## METHODNAME(NULL, secondValue)) { \
             TEST_error("%s: CTX != NULL not checked", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     if (!OSSL_CMP_CTX_set1_ ## METHODNAME(fixture->ctx, secondValue)) { \
             TEST_error("%s: setting secondValue failed", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     VALUETYPE* secondGetValue = OSSL_CMP_CTX_get1_ ## METHODNAME(fixture->ctx); \
     if (secondGetValue == NULL) { \
             TEST_error("%s: first set reset to NULL", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     if (secondGetValue == secondValue) { \
             TEST_error("%s: second set did not copy the value as expected", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     if (secondGetValue == firstGetValue) { \
             TEST_error("%s: first get return same as second get", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     VALUETYPE* thirdGetValue = OSSL_CMP_CTX_get1_ ## METHODNAME(fixture->ctx); \
      if (thirdGetValue == secondGetValue) { \
              TEST_error("%s: third get did not create a new copy", \
                         fixture->test_case_name); \
              return 0; \
     } \
     ERR_clear_error(); \
     DEALLOCATOR (firstValue); \
     DEALLOCATOR (secondValue); \
     DEALLOCATOR (firstGetValue); \
     DEALLOCATOR (secondGetValue); \
     DEALLOCATOR (thirdGetValue); \
     ERR_clear_error(); \
    return 1; \
} \
\
static int test_CTX_ ## METHODNAME ## _set1_get1(void) \
{ \
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up); \
    EXECUTE_TEST(execute_CTX_ ## METHODNAME ## _set1_get1 , tear_down); \
    return result; \
} \

#define DECLARE_SET1_GET1_TEST(METHODNAME, VALUETYPE) \
    DECLARE_SET1_GET1_BASE_TEST(METHODNAME, VALUETYPE, \
                           VALUETYPE ## _new, VALUETYPE ## _free)

#define DECLARE_SET1_GET1_STACK_OF_TEST(METHODNAME, STACK_TYPE) \
    DECLARE_SET1_GET1_BASE_TEST(METHODNAME, STACK_OF(STACK_TYPE), \
                           sk_ ## STACK_TYPE ## _new_null, \
                           sk_ ## STACK_TYPE ## _free)

#define DECLARE_SET0_BASE_TEST(METHODNAME, VALUETYPE, ALLOCATOR) \
\
static int execute_CTX_ ## METHODNAME ## _set0 \
    (OSSL_CMP_CTX_TEST_FIXTURE * fixture) \
{ \
    VALUETYPE* firstValue = ALLOCATOR (); \
    if (OSSL_CMP_CTX_set0_ ## METHODNAME(NULL, firstValue)) { \
            TEST_error("%s: CTX != NULL not checked", fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    if (!OSSL_CMP_CTX_set0_ ## METHODNAME(fixture->ctx, firstValue)) { \
            TEST_error("%s: setting value failed", fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    VALUETYPE* secondValue= ALLOCATOR (); \
    if (OSSL_CMP_CTX_set0_ ## METHODNAME(NULL, secondValue)) { \
             TEST_error("%s: CTX != NULL not checked", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     if (!OSSL_CMP_CTX_set0_ ## METHODNAME(fixture->ctx, secondValue)) { \
             TEST_error("%s: setting secondValue failed", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
    return 1; \
} \
\
static int test_CTX_ ## METHODNAME ## _set0(void) \
{ \
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up); \
    EXECUTE_TEST(execute_CTX_ ## METHODNAME ## _set0 , tear_down); \
    return result; \
} \

#define DECLARE_SET0_TEST(METHODNAME, VALUETYPE) \
    DECLARE_SET0_BASE_TEST(METHODNAME, VALUETYPE, VALUETYPE ## _new)

#define DECLARE_SET0_STACK_OF_TEST(METHODNAME, STACK_TYPE) \
    DECLARE_SET0_BASE_TEST(METHODNAME, STACK_OF(STACK_TYPE), \
                           sk_ ## STACK_TYPE ## _new_null)

#define DECLARE_SET1_BASE_TEST(METHODNAME, VALUETYPE, ALLOCATOR, DEALLOCATOR)\
\
static int execute_CTX_ ## METHODNAME ## _set1 \
    (OSSL_CMP_CTX_TEST_FIXTURE * fixture) \
{ \
    VALUETYPE* firstValue= ALLOCATOR (); \
    if (OSSL_CMP_CTX_set1_ ## METHODNAME(NULL, firstValue)) { \
            TEST_error("%s: CTX != NULL not checked", fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    if (!OSSL_CMP_CTX_set1_ ## METHODNAME(fixture->ctx, firstValue)) { \
            TEST_error("%s: setting value failed", fixture->test_case_name); \
            return 0; \
    } \
    ERR_clear_error(); \
    VALUETYPE* secondValue= ALLOCATOR (); \
    if (OSSL_CMP_CTX_set1_ ## METHODNAME(NULL, secondValue)) { \
             TEST_error("%s: CTX != NULL not checked", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     if (!OSSL_CMP_CTX_set1_ ## METHODNAME(fixture->ctx, secondValue)) { \
             TEST_error("%s: setting secondValue failed", \
                        fixture->test_case_name); \
             return 0; \
     } \
     ERR_clear_error(); \
     DEALLOCATOR (firstValue); \
     DEALLOCATOR (secondValue); \
    return 1; \
} \
static int test_CTX_ ## METHODNAME ## _set1(void) \
{ \
    SETUP_TEST_FIXTURE(OSSL_CMP_CTX_TEST_FIXTURE, set_up); \
    EXECUTE_TEST(execute_CTX_ ## METHODNAME ## _set1 , tear_down); \
    return result; \
} \

#define DECLARE_SET1_TEST(METHODNAME, VALUETYPE) \
    DECLARE_SET1_BASE_TEST(METHODNAME, VALUETYPE, \
                           VALUETYPE ## _new, VALUETYPE ## _free)

#define DECLARE_SET1_STACK_OF_TEST(METHODNAME, STACK_TYPE) \
    DECLARE_SET1_BASE_TEST(METHODNAME, STACK_OF(STACK_TYPE), \
                           sk_ ## STACK_TYPE ## _new_null, \
                           sk_ ## STACK_TYPE ## _free)

void cleanup_tests(void)
{
    return;
}

static char* char_new(void) {
    return OPENSSL_strdup("a silly test string");
}

static void char_free(char* val) {
    OPENSSL_free(val);
}

DECLARE_SET0_GET0_TEST(trustedStore, X509_STORE)
DECLARE_SET0_TEST(trustedStore, X509_STORE)
DECLARE_SET1_STACK_OF_TEST(untrusted_certs, X509)
DECLARE_SET1_GET0_STACK_OF_TEST(untrusted_certs, X509)
#define OSSL_CMP_CTX_set0_statusString ossl_cmp_ctx_set0_statusString
DECLARE_SET0_GET0_STACK_OF_TEST(statusString, ASN1_UTF8STRING)
#define OSSL_CMP_CTX_set0_validatedSrvCert ossl_cmp_ctx_set0_validatedSrvCert
DECLARE_SET0_TEST(validatedSrvCert, X509)
#define OSSL_CMP_CTX_set1_extraCertsIn ossl_cmp_ctx_set1_extraCertsIn
DECLARE_SET1_STACK_OF_TEST(extraCertsIn, X509)
DECLARE_SET1_GET1_STACK_OF_TEST(extraCertsIn, X509)
DECLARE_SET1_STACK_OF_TEST(extraCertsOut, X509)
#define OSSL_CMP_CTX_set1_caPubs ossl_cmp_ctx_set1_caPubs
DECLARE_SET1_STACK_OF_TEST(caPubs, X509)
DECLARE_SET1_GET1_STACK_OF_TEST(caPubs, X509)
DECLARE_SET1_TEST(srvCert, X509)
#define OSSL_CMP_CTX_set1_recipNonce ossl_cmp_ctx_set1_recipNonce
#define OSSL_CMP_CTX_get0_recipNonce ossl_cmp_ctx_get0_recipNonce
DECLARE_SET1_GET0_TEST(recipNonce, ASN1_OCTET_STRING)
DECLARE_SET1_TEST(expected_sender, X509_NAME)
DECLARE_SET1_TEST(issuer, X509_NAME)
DECLARE_SET1_TEST(subjectName, X509_NAME)
DECLARE_SET1_STACK_OF_TEST(reqExtensions, X509_EXTENSION)
DECLARE_SET0_STACK_OF_TEST(reqExtensions, X509_EXTENSION)
DECLARE_SET1_TEST(clCert, X509)
DECLARE_SET1_TEST(oldClCert, X509)
#ifdef ISSUE_9504_RESOLVED
/* this test fails, see https://github.com/openssl/openssl/issues/9504 */
DECLARE_SET1_TEST(p10CSR, X509_REQ)
#endif
#define OSSL_CMP_CTX_set0_newClCert ossl_cmp_ctx_set0_newClCert
#define OSSL_CMP_CTX_set0_newClCert ossl_cmp_ctx_set0_newClCert
DECLARE_SET0_GET0_TEST(newClCert, X509)
DECLARE_SET0_TEST(newClCert, X509)
DECLARE_SET0_TEST(pkey, EVP_PKEY)
DECLARE_SET1_TEST(pkey, EVP_PKEY)
DECLARE_SET1_GET0_TEST(transactionID, ASN1_OCTET_STRING)
DECLARE_SET1_TEST(recipient, X509_NAME)
#define OSSL_CMP_CTX_get0_last_senderNonce ossl_cmp_ctx_get0_last_senderNonce
DECLARE_SET1_GET0_TEST(last_senderNonce, ASN1_OCTET_STRING)
DECLARE_SET1_TEST(proxyName, char)
DECLARE_SET1_TEST(serverName, char)
DECLARE_SET1_TEST(serverPath, char)
#define OSSL_CMP_CTX_set1_failInfoCode ossl_cmp_ctx_set_failInfoCode
DECLARE_SET1_TEST(failInfoCode, ASN1_BIT_STRING)

int setup_tests(void)
{
    ADD_TEST(test_CTX_trustedStore_set0_get0);
    ADD_TEST(test_CTX_trustedStore_set0);
    ADD_TEST(test_CTX_untrusted_certs_set1_get0);
    ADD_TEST(test_CTX_untrusted_certs_set1);
    ADD_TEST(test_CTX_statusString_set0_get0);
    ADD_TEST(test_CTX_validatedSrvCert_set0);
    ADD_TEST(test_CTX_extraCertsIn_set1);
    ADD_TEST(test_CTX_extraCertsIn_set1_get1);
    ADD_TEST(test_CTX_extraCertsOut_set1);
    ADD_TEST(test_CTX_caPubs_set1);
    ADD_TEST(test_CTX_caPubs_set1_get1);
    ADD_TEST(test_CTX_srvCert_set1);
    ADD_TEST(test_CTX_recipient_set1);
    ADD_TEST(test_CTX_expected_sender_set1);
    ADD_TEST(test_CTX_issuer_set1);
    ADD_TEST(test_CTX_subjectName_set1);
    ADD_TEST(test_CTX_reqExtensions_have_SAN);
    ADD_TEST(test_CTX_reqExtensions_set1);
    ADD_TEST(test_CTX_reqExtensions_set0);
    ADD_TEST(test_CTX_newClCert_set0);
    ADD_TEST(test_CTX_pkey_set0);
    ADD_TEST(test_CTX_clCert_set1);
    ADD_TEST(test_CTX_oldClCert_set1);
#ifdef ISSUE_9504_RESOLVED
    ADD_TEST(test_CTX_p10CSR_set1);
#endif
    ADD_TEST(test_CTX_newClCert_set0_get0);
    ADD_TEST(test_CTX_pkey_set0);
    ADD_TEST(test_CTX_pkey_set1);
//    ADD_TEST(test_CTX_newPkey_set0);
//    ADD_TEST(test_CTX_newPkey_set1);
    ADD_TEST(test_CTX_transactionID_set1_get0);
    ADD_TEST(test_CTX_recipNonce_set1_get0);
    ADD_TEST(test_CTX_last_senderNonce_set1_get0);
    ADD_TEST(test_CTX_proxyName_set1);
    ADD_TEST(test_CTX_serverName_set1);
    ADD_TEST(test_CTX_serverPath_set1);
    ADD_TEST(test_CTX_failInfoCode_set1);

#ifndef OPENSSL_NO_TRACE
    ADD_TEST(test_cmp_ctx_log_cb);
#endif

    return 1;
}
