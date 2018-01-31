/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Tobias Pankert, Siemens AG
 */

#include "cmptestlib.h"

typedef struct test_fixture {
    const char *test_case_name;
    CMP_CTX *cmp_ctx;
    /* for msg create tests */
    int bodytype;
    int err_code;
    /* for protection tests */
    CMP_PKIMESSAGE *msg;
    int expected;               /* expected outcome */
    CMP_PKISTATUSINFO *si;      /* for error and response messages */
    CMP_PKIFREETEXT *free_text; /* for error message creation */
} CMP_MSG_TEST_FIXTURE;

static CMP_MSG_TEST_FIXTURE *set_up(const char *const test_case_name)
{
    CMP_MSG_TEST_FIXTURE *fixture;
    int setup_ok = 0;
    /* Allocate memory owned by the fixture, exit on error */
    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture))))
        goto err;
    fixture->test_case_name = test_case_name;

    if (!TEST_ptr(fixture->cmp_ctx = CMP_CTX_create()) ||
        !TEST_true(CMP_CTX_set_option(fixture->cmp_ctx,
                                      CMP_CTX_OPT_UNPROTECTED_SEND, 1)))
        goto err;

    setup_ok = 1;
 err:
    if (!setup_ok) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return fixture;
}

static void tear_down(CMP_MSG_TEST_FIXTURE *fixture)
{
    /* ERR_print_errors_fp(stderr);
       Free any memory owned by the fixture, etc. */
    CMP_CTX_delete(fixture->cmp_ctx);
    CMP_PKIMESSAGE_free(fixture->msg);
    /* TODO Wait for API consolidation */
    CMP_PKISTATUSINFO_free(fixture->si);
    sk_ASN1_UTF8STRING_pop_free(fixture->free_text, ASN1_UTF8STRING_free);
    OPENSSL_free(fixture);
}

static EVP_PKEY *newkey = NULL;
static X509 *cert = NULL;

#define EXECUTE_MSG_CREATION_TEST(expr) \
do { \
    CMP_PKIMESSAGE *msg = NULL; \
    int good = fixture->expected ? \
            TEST_ptr(msg = expr) && TEST_true(valid_asn1_encoding(msg)) : \
            TEST_ptr_null(msg = expr); \
    CMP_PKIMESSAGE_free(msg); \
    return good; \
} while(0)

/* The following tests call a cmp message creation function.
 * if fixture->expected != 0:
 *         returns 1 if the message is created and syntactically correct.
 * if fixture->expected == 0
 *         returns 1 if message creation returns NULL                         */
static int execute_certreq_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(CMP_certreq_new(fixture->cmp_ctx,
                                              fixture->bodytype,
                                              fixture->err_code));
}

static int execute_errormsg_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(CMP_error_new(fixture->cmp_ctx, fixture->si,
                                            fixture->err_code,
                                            fixture->free_text, 0));
}

static int execute_rr_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(CMP_rr_new(fixture->cmp_ctx));
}

static int execute_certconf_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(CMP_certConf_new
                              (fixture->cmp_ctx, fixture->err_code, NULL));
}

static int execute_genm_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(CMP_genm_new(fixture->cmp_ctx));
}

static int execute_pollreq_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(CMP_pollReq_new(fixture->cmp_ctx, 4711));
}

static int execute_pkimessage_create_test(CMP_MSG_TEST_FIXTURE *fixture)
{
    EXECUTE_MSG_CREATION_TEST(CMP_PKIMESSAGE_create
                              (fixture->cmp_ctx, fixture->bodytype));
}

static int test_cmp_create_ir_protection_set()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    unsigned char data[16];
    const size_t size = sizeof(data) / 2;
    unsigned char *ref = data;
    unsigned char *sec = data + size;
    fixture->bodytype = V_CMP_PKIBODY_IR;
    fixture->err_code = CMP_R_ERROR_CREATING_IR;
    fixture->expected = 1;
    if (!TEST_int_gt(RAND_bytes(data, sizeof(data)), 0) ||
        !TEST_true(CMP_CTX_set_option(fixture->cmp_ctx,
                                      CMP_CTX_OPT_UNPROTECTED_SEND, 0)) ||
        !TEST_true(CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey)) ||
        !TEST_true(CMP_CTX_set1_referenceValue(fixture->cmp_ctx, ref, size)) ||
        !TEST_true(CMP_CTX_set1_secretValue(fixture->cmp_ctx, sec, size))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_ir_protection_fails()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = V_CMP_PKIBODY_IR;
    fixture->err_code = CMP_R_ERROR_CREATING_IR;
    fixture->expected = 0;
    if (!TEST_true(CMP_CTX_set1_pkey(fixture->cmp_ctx, newkey)) ||
        !TEST_true(CMP_CTX_set_option(fixture->cmp_ctx,
                                      CMP_CTX_OPT_UNPROTECTED_SEND, 0)) ||
        !TEST_true(CMP_CTX_set1_clCert(fixture->cmp_ctx, cert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_cr_without_key()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = V_CMP_PKIBODY_CR;
    fixture->err_code = CMP_R_ERROR_CREATING_CR;
    fixture->expected = 0;
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_cr()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = V_CMP_PKIBODY_CR;
    fixture->err_code = CMP_R_ERROR_CREATING_CR;
    fixture->expected = 1;
    if (!TEST_true(CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_certreq_with_invalid_bodytype()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = V_CMP_PKIBODY_RR;
    fixture->err_code = CMP_R_ERROR_CREATING_IR;
    fixture->expected = 0;
    if (!TEST_true(CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_p10cr()
{
    X509_REQ *p10cr = NULL;

    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = V_CMP_PKIBODY_P10CR;
    fixture->err_code = CMP_R_ERROR_CREATING_P10CR;
    fixture->expected = 1;
    if (!TEST_ptr(p10cr = load_csr("../cmp-test/pkcs10.der")) ||
        !TEST_true(CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey)) ||
        !TEST_true(CMP_CTX_set1_p10CSR(fixture->cmp_ctx, p10cr))) {
        tear_down(fixture);
        fixture = NULL;
    }
    X509_REQ_free(p10cr);
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_p10cr_null()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = V_CMP_PKIBODY_P10CR;
    fixture->err_code = CMP_R_ERROR_CREATING_P10CR;
    fixture->expected = 0;
    if (!TEST_true(CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_kur()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->bodytype = V_CMP_PKIBODY_KUR;
    fixture->err_code = CMP_R_ERROR_CREATING_KUR;
    fixture->expected = 1;
    if (!TEST_true(CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey)) ||
        !TEST_true(CMP_CTX_set1_oldClCert(fixture->cmp_ctx, cert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_kur_without_oldcert()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    /* Do test case-specific set up; set expected return values and
     * side effects */
    fixture->bodytype = V_CMP_PKIBODY_KUR;
    fixture->err_code = CMP_R_ERROR_CREATING_KUR;
    fixture->expected = 0;
    if (!TEST_true(CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_certconf()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->err_code = 12345;  /* TODO hardcoded */
    fixture->expected = 1;
    if (!TEST_true(CMP_CTX_set1_newClCert(fixture->cmp_ctx, cert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certconf_create_test, tear_down);
    return result;
}

static int test_cmp_create_certconf_without_newclcert()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->err_code = 12345;  /* TODO hardcoded */
    fixture->expected = 0;
    if (!TEST_true(CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_certconf_create_test, tear_down);
    return result;
}

static int test_cmp_create_error_msg()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->si = CMP_statusInfo_new(CMP_PKISTATUS_rejection,
                                     CMP_PKIFAILUREINFO_systemFailure, NULL);
    fixture->err_code = -1;
    fixture->free_text = NULL;
    fixture->expected = 1;      /* Expected: Message creation is successful */
    if (!TEST_true(CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_errormsg_create_test, tear_down);
    return result;
}

static int test_cmp_create_error_msg_without_si()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->si = NULL;
    fixture->err_code = -1;
    fixture->free_text = NULL;
    fixture->expected = 0;      /* Expected: Message creation fails */
    if (!TEST_true(CMP_CTX_set1_newPkey(fixture->cmp_ctx, newkey))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_errormsg_create_test, tear_down);
    return result;
}

static int test_cmp_create_pollreq()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_pollreq_create_test, tear_down);
    return result;
}

static int test_cmp_create_rr()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    if (!TEST_true(CMP_CTX_set1_oldClCert(fixture->cmp_ctx, cert))) {
        tear_down(fixture);
        fixture = NULL;
    }
    EXECUTE_TEST(execute_rr_create_test, tear_down);
    return result;
}

static int test_cmp_create_rr_without_oldcert()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    fixture->expected = 0;
    EXECUTE_TEST(execute_rr_create_test, tear_down);
    return result;
}

static int test_cmp_create_genm()
{
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);
    CMP_INFOTYPEANDVALUE *itv = NULL;

    CMP_CTX_set_option(fixture->cmp_ctx, CMP_CTX_OPT_UNPROTECTED_SEND, 1);
    fixture->expected = 1;
    if (!TEST_ptr
        (itv = CMP_ITAV_new(OBJ_nid2obj(NID_id_it_implicitConfirm), NULL))
        || !TEST_true(CMP_CTX_genm_itav_push0(fixture->cmp_ctx, itv))) {
        CMP_INFOTYPEANDVALUE_free(itv);
        tear_down(fixture);
        fixture = NULL;
    }

    EXECUTE_TEST(execute_genm_create_test, tear_down);
    return result;
}

static int test_cmp_pkimessage_create(int bodytype)
{
    X509_REQ *p10cr = NULL;
    SETUP_TEST_FIXTURE(CMP_MSG_TEST_FIXTURE, set_up);

    switch (fixture->bodytype = bodytype) {
    case V_CMP_PKIBODY_P10CR:
        fixture->expected = 1;
        if (!TEST_true(CMP_CTX_set1_p10CSR(fixture->cmp_ctx,
                                           p10cr =
                                           load_csr
                                           ("../cmp-test/pkcs10.der")))) {
            tear_down(fixture);
            fixture = NULL;
        }
        X509_REQ_free(p10cr);
        break;
    case V_CMP_PKIBODY_IR:
    case V_CMP_PKIBODY_IP:
    case V_CMP_PKIBODY_CR:
    case V_CMP_PKIBODY_CP:
    case V_CMP_PKIBODY_KUR:
    case V_CMP_PKIBODY_KUP:
    case V_CMP_PKIBODY_RR:
    case V_CMP_PKIBODY_RP:
    case V_CMP_PKIBODY_PKICONF:
    case V_CMP_PKIBODY_GENM:
    case V_CMP_PKIBODY_GENP:
    case V_CMP_PKIBODY_ERROR:
    case V_CMP_PKIBODY_CERTCONF:
    case V_CMP_PKIBODY_POLLREQ:
    case V_CMP_PKIBODY_POLLREP:
        fixture->expected = 1;
        break;
    default:
        fixture->expected = 0;
        break;
    }

    EXECUTE_TEST(execute_pkimessage_create_test, tear_down);
    return result;
}

int setup_tests(void)
{

    if (!TEST_ptr(newkey = gen_rsa()) ||
        !TEST_ptr(cert =
                  load_pem_cert("../cmp-test/openssl_cmp_test_server.crt")))
        return 0;

    /* Message creation tests */
    ADD_TEST(test_cmp_create_certreq_with_invalid_bodytype);
    ADD_TEST(test_cmp_create_ir_protection_fails);
    ADD_TEST(test_cmp_create_ir_protection_set);
    ADD_TEST(test_cmp_create_error_msg);
    ADD_TEST(test_cmp_create_error_msg_without_si);
    ADD_TEST(test_cmp_create_certconf);
    ADD_TEST(test_cmp_create_certconf_without_newclcert);
    ADD_TEST(test_cmp_create_kur);
    ADD_TEST(test_cmp_create_kur_without_oldcert);
    ADD_TEST(test_cmp_create_cr);
    ADD_TEST(test_cmp_create_cr_without_key);
    ADD_TEST(test_cmp_create_p10cr);
    ADD_TEST(test_cmp_create_p10cr_null);
    ADD_TEST(test_cmp_create_pollreq);
    ADD_TEST(test_cmp_create_rr);
    ADD_TEST(test_cmp_create_rr_without_oldcert);
    ADD_TEST(test_cmp_create_genm);
    ADD_ALL_TESTS_NOSUBTEST(test_cmp_pkimessage_create,
                            V_CMP_PKIBODY_POLLREP + 1);

    return 1;
}

void cleanup_tests(void)
{
    EVP_PKEY_free(newkey);
    X509_free(cert);
}
