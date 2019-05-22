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
    int pkistatus;
    int pkifailure;
    char *text;                 /* Not freed by tear_down */

} CMP_STATUS_TEST_FIXTURE;

static CMP_STATUS_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    CMP_STATUS_TEST_FIXTURE *fixture;
    int setup_ok = 0;

    /* Allocate memory owned by the fixture, exit on error */
    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture))))
        goto err;
    fixture->test_case_name = test_case_name;
    setup_ok = 1;
 err:
    if (!setup_ok) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return fixture;
}

static void tear_down(CMP_STATUS_TEST_FIXTURE *fixture)
{
    OPENSSL_free(fixture);
}


/*
 * Tests PKIStatusInfo creation and get-functions
 */
static int execute_PKISI_test(CMP_STATUS_TEST_FIXTURE *fixture)
{
    OSSL_CMP_PKISI *si = NULL;
    ASN1_UTF8STRING *statusString = NULL;
    int res = 0, i;

    if (!TEST_ptr(si =
                  OSSL_CMP_statusInfo_new(fixture->pkistatus,
                                          fixture->pkifailure, fixture->text)))
        goto end;
    if (!TEST_int_eq(fixture->pkistatus,
                     OSSL_CMP_PKISI_get_PKIStatus(si))
            || !TEST_int_eq(fixture->pkifailure,
                            OSSL_CMP_PKISI_get_PKIFailureInfo(si)))
        goto end;
    for (i = 0; i <= OSSL_CMP_PKIFAILUREINFO_MAX; i++)
        if (!TEST_int_eq(fixture->pkifailure >> i & 1,
                         OSSL_CMP_PKISI_PKIFailureInfo_check(si, i)))
            goto end;
    statusString =
        sk_ASN1_UTF8STRING_value(OSSL_CMP_PKISI_get0_statusString(si), 0);
    if (!TEST_ptr(statusString)
            || !TEST_str_eq(fixture->text, (char *)statusString->data))
        goto end;
    res = 1;
 end:
    OSSL_CMP_PKISI_free(si);
    return res;
}

static int test_PKISI(void)
{
    SETUP_TEST_FIXTURE(CMP_STATUS_TEST_FIXTURE, set_up);
    fixture->pkistatus = OSSL_CMP_PKISTATUS_revocationNotification;
    fixture->pkifailure = OSSL_CMP_CTX_FAILINFO_unsupportedVersion |
        OSSL_CMP_CTX_FAILINFO_badDataFormat;
    fixture->text = "test_pki_free_text";
    EXECUTE_TEST(execute_PKISI_test, tear_down);
    return result;
}



void cleanup_tests(void)
{
    return;
}

int setup_tests(void)
{
    ADD_TEST(test_PKISI);
    return 1;
}
