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


static const char *ir_unprotected_f;

static OSSL_CMP_MSG *ir_unprotected;
static unsigned char rand_data[OSSL_CMP_TRANSACTIONID_LENGTH];

typedef struct test_fixture {
    const char *test_case_name;
    int expected;
    OSSL_CMP_CTX *cmp_ctx;
    OSSL_CMP_MSG *msg;
    ASN1_OCTET_STRING *src_string;
    ASN1_OCTET_STRING *tgt_string;

} CMP_HDR_TEST_FIXTURE;

static CMP_HDR_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    CMP_HDR_TEST_FIXTURE *fixture;
    int setup_ok = 0;

    /* Allocate memory owned by the fixture, exit on error */
    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture))))
        goto err;
    fixture->test_case_name = test_case_name;
    if (!TEST_ptr(fixture->cmp_ctx = OSSL_CMP_CTX_new()))
        goto err;
    setup_ok = 1;
 err:
    if (!setup_ok) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return fixture;
}

static void tear_down(CMP_HDR_TEST_FIXTURE *fixture)
{
    OSSL_CMP_MSG_free(fixture->msg);
    OSSL_CMP_CTX_free(fixture->cmp_ctx);
    ASN1_OCTET_STRING_free(fixture->src_string);
    if (fixture->tgt_string != fixture->src_string)
        ASN1_OCTET_STRING_free(fixture->tgt_string);

    OPENSSL_free(fixture);
}


static int execute_HDR_init_test(CMP_HDR_TEST_FIXTURE *fixture)
{
    OSSL_CMP_PKIHEADER *header = NULL;
    ASN1_OCTET_STRING *header_nonce = NULL;
    ASN1_OCTET_STRING *ctx_nonce = NULL;
    int res = 0;

    if (!TEST_ptr(header = OSSL_CMP_PKIHEADER_new()))
        return 0;
    if (!TEST_int_eq(fixture->expected,
                     OSSL_CMP_HDR_init(fixture->cmp_ctx, header)))
        goto err;
    if (fixture->expected != 0) {
        if (!TEST_int_eq(OSSL_CMP_HDR_get_pvno(header), OSSL_CMP_PVNO)
                || !TEST_true(0 == ASN1_OCTET_STRING_cmp(
                       OSSL_CMP_HDR_get0_senderNonce(header),
                       CMP_CTX_get0_last_senderNonce(fixture->cmp_ctx)))
                || !TEST_true(0 ==  ASN1_OCTET_STRING_cmp(
                            OSSL_CMP_HDR_get0_transactionID(header),
                            OSSL_CMP_CTX_get0_transactionID(fixture->cmp_ctx))))
            goto err;
        header_nonce = OSSL_CMP_HDR_get0_recipNonce(header);
        ctx_nonce = CMP_CTX_get0_recipNonce(fixture->cmp_ctx);
        if (ctx_nonce != NULL
                 && (!TEST_ptr(header_nonce)
                         || !TEST_int_eq(0, ASN1_OCTET_STRING_cmp(header_nonce,
                                                                  ctx_nonce))))
            goto err;
    }

    res = 1;

 err:
    OSSL_CMP_PKIHEADER_free(header);
    return res;
}

static int test_HDR_init(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    unsigned char ref[CMP_TEST_REFVALUE_LENGTH];

    fixture->expected = 1;
    if (!TEST_int_eq(1, RAND_bytes(ref, sizeof(ref)))
           || !TEST_true(OSSL_CMP_CTX_set1_referenceValue(fixture->cmp_ctx, ref,
                                                          sizeof(ref)))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_HDR_init_test, tear_down);
    return result;
}

static int test_HDR_init_with_subject(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    X509_NAME *subject = NULL;

    fixture->expected = 1;
    if (!TEST_ptr(subject = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(subject, "CN",
                                                 V_ASN1_IA5STRING,
                                                 (unsigned char *)"Common Name",
                                                 -1, -1, -1))
        || !TEST_true(OSSL_CMP_CTX_set1_subjectName(fixture->cmp_ctx,
                                                    subject))) {
        tear_down(fixture);
        fixture = NULL;
    }
    X509_NAME_free(subject);
    EXECUTE_TEST(execute_HDR_init_test, tear_down);
    return result;
}

static int test_HDR_init_no_ref_no_subject(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 0;
    EXECUTE_TEST(execute_HDR_init_test, tear_down);
    return result;
}


static int
execute_HDR_set_and_check_implicitConfirm_test(CMP_HDR_TEST_FIXTURE
                                                           * fixture)
{
    OSSL_CMP_PKIHEADER *hdr = fixture->msg->header;

    return TEST_false(OSSL_CMP_HDR_check_implicitConfirm(hdr))
               && TEST_true(OSSL_CMP_HDR_set_implicitConfirm(hdr))
               && TEST_true(OSSL_CMP_HDR_check_implicitConfirm(hdr));
}

static int test_HDR_get_and_check_implicit_confirm(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    if (!TEST_ptr(fixture->msg = OSSL_CMP_MSG_dup(ir_unprotected))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_HDR_set_and_check_implicitConfirm_test, tear_down);
    return result;
}

static int test_HDR_set_and_check_implicit_confirm(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    if (!TEST_ptr(fixture->msg = OSSL_CMP_MSG_dup(ir_unprotected))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_HDR_set_and_check_implicitConfirm_test, tear_down);
    return result;
}

static int execute_CMP_ASN1_OCTET_STRING_set1_test(CMP_HDR_TEST_FIXTURE *
                                                   fixture)
{
    if (!TEST_int_eq(fixture->expected,
                     CMP_ASN1_OCTET_STRING_set1(&fixture->tgt_string,
                                                fixture->src_string)))
        return 0;
    if (fixture->expected != 0)
        return TEST_int_eq(0, ASN1_OCTET_STRING_cmp(fixture->tgt_string,
                                                    fixture->src_string));
    return 1;
}

static int test_ASN1_OCTET_STRING_set(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    if (!TEST_ptr(fixture->tgt_string = ASN1_OCTET_STRING_new())
            || !TEST_ptr(fixture->src_string = ASN1_OCTET_STRING_new())
            || !TEST_true(ASN1_OCTET_STRING_set(fixture->src_string,
                                                rand_data, sizeof(rand_data)))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_CMP_ASN1_OCTET_STRING_set1_test, tear_down);
    return result;
}

static int test_ASN1_OCTET_STRING_set_tgt_is_src(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    if (!TEST_ptr(fixture->src_string = ASN1_OCTET_STRING_new())
           || !(fixture->tgt_string = fixture->src_string)
           || !TEST_true(ASN1_OCTET_STRING_set(fixture->src_string, rand_data,
                                               sizeof(rand_data)))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_CMP_ASN1_OCTET_STRING_set1_test, tear_down);
    return result;
}




void cleanup_tests(void)
{
    OSSL_CMP_MSG_free(ir_unprotected);
    return;
}

int setup_tests(void)
{
    if (!TEST_ptr(ir_unprotected_f = test_get_argument(0))) {
        TEST_error("usage: cmp_hdr_test IR_unprotected.der\n");
        return 0;
    }
    if (!TEST_ptr(ir_unprotected = load_pkimsg(ir_unprotected_f)))
        return 0;


    /* Message header tests */
    ADD_TEST(test_HDR_init);
    ADD_TEST(test_HDR_init_with_subject);
    ADD_TEST(test_HDR_init_no_ref_no_subject);
    ADD_TEST(test_HDR_set_and_check_implicit_confirm);
    ADD_TEST(test_HDR_get_and_check_implicit_confirm);
    ADD_TEST(test_ASN1_OCTET_STRING_set);
    ADD_TEST(test_ASN1_OCTET_STRING_set_tgt_is_src);
    /* TODO make sure that total number of tests (here currently 24) is shown,
     also for other cmp_*text.c. Currently the test drivers always show 1. */

    return 1;
}
