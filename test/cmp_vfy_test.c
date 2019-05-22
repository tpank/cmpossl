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

static const char *server_f;
static const char *client_f;
static const char *endentity1_f;
static const char *endentity2_f;
static const char *root_f;
static const char *intermediate_f;
static const char *ir_protected_f;
static const char *ir_unprotected_f;
static const char *ir_rmprotection_f;
static const char *ip_waiting_f;

typedef struct test_fixture {
    const char *test_case_name;
    int expected;
    OSSL_CMP_CTX *cmp_ctx;
    OSSL_CMP_MSG *msg;
    X509 *cert;
    OSSL_cmp_allow_unprotected_cb_t allow_unprotected_cb;
    int callback_arg;
} CMP_VFY_TEST_FIXTURE;

static CMP_VFY_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    CMP_VFY_TEST_FIXTURE *fixture;
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

static void tear_down(CMP_VFY_TEST_FIXTURE *fixture)
{
    OSSL_CMP_MSG_free(fixture->msg);
    OSSL_CMP_CTX_free(fixture->cmp_ctx);
    OPENSSL_free(fixture);
}

static time_t test_time_valid = 0, test_time_future = 0;

static X509 *srvcert = NULL;
static X509 *clcert = NULL;
/* chain */
static X509 *endentity1 = NULL, *endentity2 = NULL,
    *intermediate = NULL, *root = NULL;

static unsigned char rand_data[OSSL_CMP_TRANSACTIONID_LENGTH];
static OSSL_CMP_MSG *ir_unprotected, *ir_rmprotection;

static int execute_validate_msg_test(CMP_VFY_TEST_FIXTURE *fixture)
{
    return TEST_int_eq(fixture->expected,
                       OSSL_CMP_validate_msg(fixture->cmp_ctx, fixture->msg));
}

static int execute_validate_cert_path_test(CMP_VFY_TEST_FIXTURE *fixture)
{
    X509_STORE *ts = OSSL_CMP_CTX_get0_trustedStore(fixture->cmp_ctx);

    return TEST_int_eq(fixture->expected,
                       OSSL_CMP_validate_cert_path(fixture->cmp_ctx,
                                                   ts, fixture->cert, 0));
}

static int test_validate_msg_mac_alg_protection(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* secret value belonging to cmp-test/CMP_IP_waitingStatus_PBM.der */
    const unsigned char sec_1[] =
        { '9', 'p', 'p', '8', '-', 'b', '3', '5', 'i', '-', 'X', 'd', '3',
        'Q', '-', 'u', 'd', 'N', 'R'
    };

    fixture->expected = 1;
    if (!TEST_true(OSSL_CMP_CTX_set1_secretValue(fixture->cmp_ctx, sec_1,
                                                 sizeof(sec_1)))
            || !TEST_ptr(fixture->msg = load_pkimsg(ip_waiting_f))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validate_msg_test, tear_down);
    return result;
}

static int test_validate_msg_mac_alg_protection_bad(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    const unsigned char sec_bad[] =
        { '9', 'p', 'p', '8', '-', 'b', '3', '5', 'i', '-', 'X', 'd', '3',
        'Q', '-', 'u', 'd', 'N', 'r'
    };
    fixture->expected = 0;

    if (!TEST_true(OSSL_CMP_CTX_set1_secretValue(fixture->cmp_ctx, sec_bad,
                                                 sizeof(sec_bad)))
            || !TEST_ptr(fixture->msg = load_pkimsg(ip_waiting_f))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validate_msg_test, tear_down);
    return result;
}

static int test_validate_msg_signature_trusted(int expired)
{
    X509_STORE *trusted = NULL;

    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->expected = !expired;
    trusted = OSSL_CMP_CTX_get0_trustedStore(fixture->cmp_ctx);
    if (!TEST_ptr(fixture->msg = load_pkimsg(ir_protected_f))
            || !TEST_true(trusted)
            || !TEST_true(X509_STORE_add_cert(trusted, srvcert))) {
        tear_down(fixture);
        fixture = NULL;
    } else {
        X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(trusted),
                                   expired ? test_time_future : test_time_valid);
    }
    EXECUTE_TEST(execute_validate_msg_test, tear_down);
    return result;
}

static int test_validate_msg_signature_trusted_ok(void)
{
    return test_validate_msg_signature_trusted(0);
}

static int test_validate_msg_signature_trusted_expired(void)
{
    return test_validate_msg_signature_trusted(1);
}

static int test_validate_msg_signature_srvcert_ok(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->expected = 1;
    if (!TEST_ptr(fixture->msg = load_pkimsg(ir_protected_f))
          || !TEST_true(OSSL_CMP_CTX_set1_srvCert(fixture->cmp_ctx, srvcert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validate_msg_test, tear_down);
    return result;
}

static int test_validate_msg_signature_srvcert_bad(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->expected = 0;
    if (!TEST_ptr(fixture->msg = load_pkimsg(ir_protected_f))
            || !TEST_true(OSSL_CMP_CTX_set1_srvCert(fixture->cmp_ctx, clcert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validate_msg_test, tear_down);
    return result;
}

static int test_validate_msg_signature_expected_sender(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->expected = 1;
    if (!TEST_ptr(fixture->msg = load_pkimsg(ir_protected_f))
            || !TEST_true(OSSL_CMP_CTX_set1_srvCert(fixture->cmp_ctx, srvcert))
        /* Set correct expected sender name*/
            || !TEST_true(OSSL_CMP_CTX_set1_expected_sender(fixture->cmp_ctx,
                                             X509_get_subject_name(srvcert)))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validate_msg_test, tear_down);
    return result;
}

static int test_validate_msg_signature_unexpected_sender(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->expected = 0;
    if (!TEST_ptr(fixture->msg = load_pkimsg(ir_protected_f))
            || !TEST_true(OSSL_CMP_CTX_set1_srvCert(fixture->cmp_ctx, srvcert))
        /* Set wrong expected sender name*/
            || !TEST_true(OSSL_CMP_CTX_set1_expected_sender(fixture->cmp_ctx,
                                                X509_get_subject_name(root)))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validate_msg_test, tear_down);
    return result;
}


static int test_validate_msg_unprotected_request(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->expected = 0;
    if (!TEST_ptr(fixture->msg = load_pkimsg(ir_unprotected_f))
          || !TEST_true(OSSL_CMP_CTX_set1_srvCert(fixture->cmp_ctx, srvcert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_validate_msg_test, tear_down);
    return result;
}

static int test_validate_cert_path_ok(void)
{
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE *trusted = NULL;

    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->cert = endentity2;
    fixture->expected = 1;
    trusted = OSSL_CMP_CTX_get0_trustedStore(fixture->cmp_ctx);
    if (!TEST_ptr(untrusted =
                  OSSL_CMP_CTX_get0_untrusted_certs(fixture->cmp_ctx))
            || !TEST_int_lt(0, STACK_OF_X509_push1(untrusted, endentity1))
            || !TEST_int_lt(0, STACK_OF_X509_push1(untrusted, intermediate))
            || !TEST_true(trusted)
            || !TEST_true(X509_STORE_add_cert(trusted, root))) {
        tear_down(fixture);
        fixture = NULL;
    } else {
        X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(trusted),
                                   test_time_valid);
    }
    EXECUTE_TEST(execute_validate_cert_path_test, tear_down);
    return result;
}

static int test_validate_cert_path_no_anchor(void)
{
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE *trusted = NULL;

    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->cert = endentity2;
    fixture->expected = 0;
    trusted = OSSL_CMP_CTX_get0_trustedStore(fixture->cmp_ctx);
    if (!TEST_ptr(untrusted =
                  OSSL_CMP_CTX_get0_untrusted_certs(fixture->cmp_ctx))
           || !TEST_int_lt(0, STACK_OF_X509_push1(untrusted, endentity1))
           || !TEST_int_lt(0, STACK_OF_X509_push1(untrusted, intermediate))
           || !TEST_true(trusted)
           /* Wrong anchor */
           || !TEST_true(X509_STORE_add_cert(trusted, srvcert))) {
        tear_down(fixture);
        fixture = NULL;
    } else {
        X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(trusted),
                                   test_time_valid);
    }
    EXECUTE_TEST(execute_validate_cert_path_test, tear_down);
    return result;
}

static int test_validate_cert_path_expired(void)
{
    STACK_OF(X509) *untrusted = NULL;
    X509_STORE *trusted = NULL;

    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->cert = endentity2;
    fixture->expected = 0;
    trusted = OSSL_CMP_CTX_get0_trustedStore(fixture->cmp_ctx);
    if (!TEST_ptr(untrusted =
                  OSSL_CMP_CTX_get0_untrusted_certs(fixture->cmp_ctx))
            || !TEST_int_lt(0, STACK_OF_X509_push1(untrusted, endentity1))
            || !TEST_int_lt(0, STACK_OF_X509_push1(untrusted, intermediate))
            || !TEST_true(trusted)
            || !TEST_true(X509_STORE_add_cert(trusted, root))) {
        tear_down(fixture);
        fixture = NULL;
    } else {
        X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(trusted),
                                   test_time_future);
    }
    EXECUTE_TEST(execute_validate_cert_path_test, tear_down);
    return result;
}

static int execute_MSG_check_received_test(CMP_VFY_TEST_FIXTURE *fixture)
{
    if (!TEST_int_eq(OSSL_CMP_MSG_check_received(fixture->cmp_ctx,
                                                 fixture->msg,
                                                 fixture->allow_unprotected_cb,
                                                 fixture->callback_arg),
                     fixture->expected))
        return 0;

    if (fixture->expected >= 0) {
        const OSSL_CMP_PKIHEADER *header = OSSL_CMP_MSG_get0_header(fixture->msg);
        if (!TEST_int_eq(0,
              ASN1_OCTET_STRING_cmp(OSSL_CMP_HDR_get0_senderNonce(header),
                                    CMP_CTX_get0_recipNonce(fixture->
                                                            cmp_ctx))))
            return 0;
        if (!TEST_int_eq(0,
           ASN1_OCTET_STRING_cmp(OSSL_CMP_HDR_get0_transactionID(header),
                                 OSSL_CMP_CTX_get0_transactionID(fixture->
                                                                 cmp_ctx))))
            return 0;
    }

    return 1;
}

static int allow_unprotected(const OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg,
                             int invalid_protection, int allow)
{
    return allow;
}

static int test_MSG_check_received_no_protection_no_cb(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->expected = -1;
    if (!TEST_ptr(fixture->msg = OSSL_CMP_MSG_dup(ir_unprotected))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_MSG_check_received_test, tear_down);
    return result;
}

static int test_MSG_check_received_no_protection_negative_cb(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->expected = -1;
    fixture->callback_arg = 0;
    fixture->allow_unprotected_cb = allow_unprotected;
    if (!TEST_ptr(fixture->msg = OSSL_CMP_MSG_dup(ir_unprotected))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_MSG_check_received_test, tear_down);
    return result;
}

static int test_MSG_check_received_no_protection_positive_cb(void)
{
    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->expected = OSSL_CMP_PKIBODY_IR;
    fixture->callback_arg = 1;
    fixture->allow_unprotected_cb = allow_unprotected;
    if (!TEST_ptr(fixture->msg = OSSL_CMP_MSG_dup(ir_unprotected))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_MSG_check_received_test, tear_down);
    return result;
}

static int test_MSG_check_received_check_transaction_id(void)
{
    /* Transaction id belonging to CMP_IR_unprotected.der */
    const unsigned char trans_id[OSSL_CMP_TRANSACTIONID_LENGTH] =
        { 0xDF, 0x5C, 0xDC, 0x01, 0xF8, 0x81, 0x6E, 0xA9,
        0x3E, 0x63, 0x94, 0x5B, 0xD3, 0x12, 0x1B, 0x65
    };
    ASN1_OCTET_STRING *trid = NULL;

    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->expected = OSSL_CMP_PKIBODY_IR;
    fixture->callback_arg = 1;
    fixture->allow_unprotected_cb = allow_unprotected;
    if (!TEST_ptr(fixture->msg = OSSL_CMP_MSG_dup(ir_unprotected))
       || !TEST_ptr(trid = ASN1_OCTET_STRING_new())
       || !TEST_true(ASN1_OCTET_STRING_set(trid, trans_id, sizeof(trans_id)))
       || !TEST_true(OSSL_CMP_CTX_set1_transactionID(fixture->cmp_ctx, trid))) {
        tear_down(fixture);
        fixture = NULL;
    }
    ASN1_OCTET_STRING_free(trid);
    EXECUTE_TEST(execute_MSG_check_received_test, tear_down);
    return result;
}

static int test_MSG_check_received_wrong_transaction_id(void)
{
    ASN1_OCTET_STRING *trid = NULL;

    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->expected = -1;
    fixture->callback_arg = 1;
    fixture->allow_unprotected_cb = allow_unprotected;
    if (!TEST_ptr(fixture->msg = OSSL_CMP_MSG_dup(ir_unprotected))
        || !TEST_ptr(trid = ASN1_OCTET_STRING_new())
        || !TEST_true(ASN1_OCTET_STRING_set(trid, rand_data, sizeof(rand_data)))
        || !TEST_true(OSSL_CMP_CTX_set1_transactionID(fixture->cmp_ctx, trid))) {
        tear_down(fixture);
        fixture = NULL;
    }
    ASN1_OCTET_STRING_free(trid);
    EXECUTE_TEST(execute_MSG_check_received_test, tear_down);
    return result;
}

static int test_MSG_check_received_wrong_recipient_nonce(void)
{
    ASN1_OCTET_STRING *snonce = NULL;

    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->expected = -1;
    fixture->callback_arg = 1;
    fixture->allow_unprotected_cb = allow_unprotected;
    if (!TEST_ptr(fixture->msg = OSSL_CMP_MSG_dup(ir_unprotected))
            || !TEST_ptr(snonce = ASN1_OCTET_STRING_new())
            || !TEST_true(ASN1_OCTET_STRING_set(snonce, rand_data,
                                                sizeof(rand_data)))
            || !TEST_true(OSSL_CMP_CTX_set1_last_senderNonce(fixture->cmp_ctx,
                                                             snonce))) {
        tear_down(fixture);
        fixture = NULL;
    }
    ASN1_OCTET_STRING_free(snonce);
    EXECUTE_TEST(execute_MSG_check_received_test, tear_down);
    return result;
}

static int test_MSG_check_received_check_recipient_nonce(void)
{
    /* Recipient nonce belonging to CMP_IP_ir_rmprotection.der */
    const unsigned char rec_nonce[OSSL_CMP_SENDERNONCE_LENGTH] =
        { 0x48, 0xF1, 0x71, 0x1F, 0xE5, 0xAF, 0x1C, 0x8B,
        0x21, 0x97, 0x5C, 0x84, 0x74, 0x49, 0xBA, 0x32
    };
    ASN1_OCTET_STRING *snonce = NULL;

    SETUP_TEST_FIXTURE(CMP_VFY_TEST_FIXTURE, set_up);
    fixture->expected = OSSL_CMP_PKIBODY_IP;
    fixture->callback_arg = 1;
    fixture->allow_unprotected_cb = allow_unprotected;
    if (!TEST_ptr(fixture->msg = OSSL_CMP_MSG_dup(ir_rmprotection))
            || !TEST_ptr(snonce = ASN1_OCTET_STRING_new())
            || !TEST_true(ASN1_OCTET_STRING_set(snonce, rec_nonce,
                                                sizeof(rec_nonce)))
            || !TEST_true(OSSL_CMP_CTX_set1_last_senderNonce(fixture->cmp_ctx,
                                                             snonce))) {
        tear_down(fixture);
        fixture = NULL;
    }
    ASN1_OCTET_STRING_free(snonce);
    EXECUTE_TEST(execute_MSG_check_received_test, tear_down);
    return result;
}

void cleanup_tests(void)
{
    X509_free(srvcert);
    X509_free(clcert);
    X509_free(endentity1);
    X509_free(endentity2);
    X509_free(intermediate);
    X509_free(root);
    OSSL_CMP_MSG_free(ir_unprotected);
    OSSL_CMP_MSG_free(ir_rmprotection);
    return;
}

int setup_tests(void)
{
    /* Set test time stamps */
    struct tm ts = { 0 };

    ts.tm_year = 2018 - 1900;
    ts.tm_mon = 1;              /* February */
    ts.tm_mday = 18;
    test_time_valid = mktime(&ts); /* February 18th 2018 */
    ts.tm_year += 10;           /* February 18th 2028 */
    test_time_future = mktime(&ts);

    if (!TEST_ptr(server_f = test_get_argument(0))
            || !TEST_ptr(client_f = test_get_argument(1))
            || !TEST_ptr(endentity1_f = test_get_argument(2))
            || !TEST_ptr(endentity2_f = test_get_argument(3))
            || !TEST_ptr(root_f = test_get_argument(4))
            || !TEST_ptr(intermediate_f = test_get_argument(5))
            || !TEST_ptr(ir_protected_f = test_get_argument(6))
            || !TEST_ptr(ir_unprotected_f = test_get_argument(7))
            || !TEST_ptr(ip_waiting_f = test_get_argument(8))
            || !TEST_ptr(ir_rmprotection_f = test_get_argument(9))) {
        TEST_error("usage: cmp_vfy_test server.crt client.crt "
                   "EndEntity1.crt EndEntity2.crt "
                   "Root_CA.crt Intermediate_CA.crt "
                   "CMP_IR_protected.der CMP_IR_unprotected.der "
                   "IP_waitingStatus_PBM.der IR_rmprotection.der\n");
        return 0;
    }

    /* Load certificates for cert chain */
    if (!TEST_ptr(endentity1 = load_pem_cert(endentity1_f))
            || !TEST_ptr(endentity2 = load_pem_cert(endentity2_f))
            || !TEST_ptr(root = load_pem_cert(root_f))
            || !TEST_ptr(intermediate = load_pem_cert(intermediate_f)))
        return 0;

    /* Load certificates for message validation */
    if (!TEST_ptr(srvcert = load_pem_cert(server_f))
            || !TEST_ptr(clcert = load_pem_cert(client_f)))
        return 0;
    if(!TEST_int_eq(1, RAND_bytes(rand_data, OSSL_CMP_TRANSACTIONID_LENGTH)))
        return 0;
    if (!TEST_ptr(ir_unprotected = load_pkimsg(ir_unprotected_f))
            || !TEST_ptr(ir_rmprotection = load_pkimsg(ir_rmprotection_f)))
        return 0;
    /* Message validation tests */
    ADD_TEST(test_validate_msg_signature_trusted_ok);
    ADD_TEST(test_validate_msg_signature_trusted_expired);
    ADD_TEST(test_validate_msg_signature_srvcert_ok);
    ADD_TEST(test_validate_msg_signature_srvcert_bad);
    ADD_TEST(test_validate_msg_signature_expected_sender);
    ADD_TEST(test_validate_msg_signature_unexpected_sender);
    ADD_TEST(test_validate_msg_unprotected_request);
    ADD_TEST(test_validate_msg_mac_alg_protection);
    ADD_TEST(test_validate_msg_mac_alg_protection_bad);

    /* Cert path validation tests */
    ADD_TEST(test_validate_cert_path_ok);
    ADD_TEST(test_validate_cert_path_expired);
    ADD_TEST(test_validate_cert_path_no_anchor);

    ADD_TEST(test_MSG_check_received_no_protection_no_cb);
    ADD_TEST(test_MSG_check_received_no_protection_negative_cb);
    ADD_TEST(test_MSG_check_received_no_protection_positive_cb);
    ADD_TEST(test_MSG_check_received_check_transaction_id);
    ADD_TEST(test_MSG_check_received_wrong_transaction_id);
    ADD_TEST(test_MSG_check_received_check_recipient_nonce);
    ADD_TEST(test_MSG_check_received_wrong_recipient_nonce);


    return 1;
}
