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

#include "cmp_testlib.h"

static unsigned char rand_data[OSSL_CMP_TRANSACTIONID_LENGTH];

typedef struct test_fixture {
    const char *test_case_name;
    int expected;
    OSSL_CMP_CTX *cmp_ctx;
    OSSL_CMP_PKIHEADER *hdr;
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
    if (!TEST_ptr(fixture->hdr = OSSL_CMP_PKIHEADER_new()))
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
    OSSL_CMP_PKIHEADER_free(fixture->hdr);
    OSSL_CMP_CTX_free(fixture->cmp_ctx);
    ASN1_OCTET_STRING_free(fixture->src_string);
    if (fixture->tgt_string != fixture->src_string)
        ASN1_OCTET_STRING_free(fixture->tgt_string);

    OPENSSL_free(fixture);
}


static int execute_HDR_set_get_pvno_test(CMP_HDR_TEST_FIXTURE *fixture)
{
    int pvno = 77;

    if (!TEST_int_eq(ossl_cmp_hdr_set_pvno(fixture->hdr, pvno), 1)) {
        return 0;
    };
    if (!TEST_int_eq(ossl_cmp_hdr_get_pvno(fixture->hdr), pvno)) {
         return 0;
     };
    return 1;
}

static int test_HDR_set_get_pvno(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_HDR_set_get_pvno_test, tear_down);
    return result;
}

static int execute_HDR_get0_senderNonce_test(CMP_HDR_TEST_FIXTURE *fixture)
{
    X509_NAME *sender = X509_NAME_new();

    X509_NAME_add_entry_by_txt(sender, "CN",
          MBSTRING_ASC, (unsigned char*)"A common sender name", -1, -1, 0);
    if (!TEST_int_eq(OSSL_CMP_CTX_set1_subjectName(fixture->cmp_ctx, sender),
                     1)) {
        return 0;
    };
    if (!TEST_int_eq(ossl_cmp_hdr_init(fixture->cmp_ctx, fixture->hdr),
                     1)) {
        return 0;
    };
    if (!TEST_int_eq(ASN1_OCTET_STRING_cmp(fixture->cmp_ctx->senderNonce,
                                           ossl_cmp_hdr_get0_senderNonce(
                                                       fixture->hdr)), 0)) {
        return 0;
    };
    X509_NAME_free(sender);
    return 1;
}

static int test_HDR_get0_senderNonce(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_HDR_get0_senderNonce_test, tear_down);
    return result;
}

static int execute_HDR_set1_sender_test(CMP_HDR_TEST_FIXTURE *fixture)
{
    X509_NAME *x509name = X509_NAME_new();

    X509_NAME_add_entry_by_txt(x509name, "CN",
          MBSTRING_ASC, (unsigned char*)"A common sender name", -1, -1, 0);
    if (!TEST_int_eq(ossl_cmp_hdr_set1_sender(fixture->hdr, x509name), 1)) {
        return 0;
    };
    if (!TEST_int_eq(fixture->hdr->sender->type, GEN_DIRNAME)) {
        return 0;
    }
    if (!TEST_int_eq(
            X509_NAME_cmp(fixture->hdr->sender->d.directoryName, x509name),
                          0)) {
        return 0;
    }
    X509_NAME_free(x509name);
    return 1;
}

static int test_HDR_set1_sender(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_HDR_set1_sender_test, tear_down);
    return result;
}

static int execute_HDR_set1_recipient_test(CMP_HDR_TEST_FIXTURE *fixture)
{
    X509_NAME *x509name = X509_NAME_new();

    X509_NAME_add_entry_by_txt(x509name, "CN",
          MBSTRING_ASC, (unsigned char*)"A common recipient name", -1, -1, 0);
    if (!TEST_int_eq(ossl_cmp_hdr_set1_recipient(fixture->hdr, x509name), 1)) {
        return 0;
    };
    if (!TEST_int_eq(fixture->hdr->recipient->type, GEN_DIRNAME)) {
        return 0;
    }
    if (!TEST_int_eq(
            X509_NAME_cmp(fixture->hdr->recipient->d.directoryName, x509name),
                          0)) {
        return 0;
    }
    X509_NAME_free(x509name);
    return 1;
}

static int test_HDR_set1_recipient(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_HDR_set1_recipient_test, tear_down);
    return result;
}

static int execute_HDR_update_messageTime_test(CMP_HDR_TEST_FIXTURE *fixture)
{
    struct tm tm;
    time_t t1, t2, now;
    double diffSecs;

    if (!TEST_int_eq(ossl_cmp_hdr_update_messageTime(fixture->hdr), 1)) {
        return 0;
    };
    if (!TEST_int_eq(ASN1_TIME_to_tm(fixture->hdr->messageTime, &tm), 1)) {
        return 0;
    };
    t1 = mktime(&tm);
    now = time(NULL);
    t2 = mktime(gmtime(&now));
    diffSecs = difftime(t1, t2);
    if (!TEST_true(diffSecs > -2.0 && diffSecs < +2.0)) {
        return 0;
    }

    return 1;
}

static int test_HDR_update_messageTime(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_HDR_update_messageTime_test, tear_down);
    return result;
}

static int execute_HDR_set1_senderKID_test(CMP_HDR_TEST_FIXTURE *fixture)
{
    ASN1_OCTET_STRING* senderKID = ASN1_OCTET_STRING_new();

    ASN1_OCTET_STRING_set(senderKID, rand_data, sizeof(rand_data));
    if (!TEST_int_eq(ossl_cmp_hdr_set1_senderKID(fixture->hdr, senderKID), 1)) {
        return 0;
    };
    if (!TEST_int_eq(
            ASN1_OCTET_STRING_cmp(fixture->hdr->senderKID, senderKID), 0)) {
        return 0;
    }
    ASN1_OCTET_STRING_free(senderKID);
    return 1;
}

static int test_HDR_set1_senderKID(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_HDR_set1_senderKID_test, tear_down);
    return result;
}

static int execute_HDR_push0_freeText_test(CMP_HDR_TEST_FIXTURE *fixture)
{
    ASN1_UTF8STRING* text = ASN1_UTF8STRING_new();

    if (!TEST_ptr(text)) {
        return 0;
    }
    if (!ASN1_STRING_set(text, "A free text", -1)) {
        return 0;
    }
    if (!TEST_int_eq(
            ossl_cmp_hdr_push0_freeText(fixture->hdr, text), 1)) {
        return 0;
    };
    if (!TEST_true(text == sk_ASN1_UTF8STRING_value(
            fixture->hdr->freeText, 0))) {
        return 0;
    }
    return 1;
}

static int test_HDR_push0_freeText(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_HDR_push0_freeText_test, tear_down);
    return result;
}

static int execute_HDR_push1_freeText_test(CMP_HDR_TEST_FIXTURE *fixture)
{
    ASN1_UTF8STRING* text = ASN1_UTF8STRING_new();

    if (!TEST_ptr(text)) {
        return 0;
    }
    if (!ASN1_STRING_set(text, "A free text", -1)) {
        return 0;
    }
    if (!TEST_int_eq(
            ossl_cmp_hdr_push1_freeText(fixture->hdr, text), 1)) {
        return 0;
    };
    if (!TEST_int_eq(ASN1_STRING_cmp(
            sk_ASN1_UTF8STRING_value(fixture->hdr->freeText, 0), text), 0)) {
        return 0;
    }
    ASN1_UTF8STRING_free(text);
    return 1;
}

static int test_HDR_push1_freeText(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_HDR_push1_freeText_test, tear_down);
    return result;
}

static int
execute_HDR_generalInfo_push0_item_test(CMP_HDR_TEST_FIXTURE *fixture)
{
    OSSL_CMP_ITAV *itav = OSSL_CMP_ITAV_new();

    if (!TEST_int_eq(
            ossl_cmp_hdr_generalInfo_push0_item(fixture->hdr, itav), 1)) {
        return 0;
    };
    if (!TEST_true(itav == sk_OSSL_CMP_ITAV_value(
            fixture->hdr->generalInfo, 0))) {
        return 0;
    }
    return 1;
}

static int test_HDR_generalInfo_push0_item(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_HDR_generalInfo_push0_item_test, tear_down);
    return result;
}

static int
execute_HDR_generalInfo_push1_items_test(CMP_HDR_TEST_FIXTURE *fixture)
{
    const char oid[] = "1.2.3.4";
    char buf[20];
    OSSL_CMP_ITAV *itav;
    STACK_OF(OSSL_CMP_ITAV) *itavs = NULL;
    ASN1_INTEGER *asn1int=ASN1_INTEGER_new();
    ASN1_TYPE *val = ASN1_TYPE_new();

    ASN1_INTEGER_set(asn1int, 88);
    ASN1_TYPE_set(val, V_ASN1_INTEGER, asn1int);
    itav = OSSL_CMP_ITAV_create(OBJ_txt2obj(oid, 1), val);
    OSSL_CMP_ITAV_push0_stack_item(&itavs, itav);

    if (!TEST_int_eq(
        ossl_cmp_hdr_generalInfo_push1_items(fixture->hdr, itavs), 1)) {
        return 0;
    };
    OBJ_obj2txt(buf, sizeof(buf), OSSL_CMP_ITAV_get0_type(
            sk_OSSL_CMP_ITAV_value(fixture->hdr->generalInfo, 0)), 0);
    if (!TEST_int_eq(memcmp(oid, buf, sizeof(oid)), 0)) {
        return 0;
    }
    if (!TEST_int_eq(ASN1_TYPE_cmp(itav->infoValue.other,
                                   OSSL_CMP_ITAV_get0_value(
            sk_OSSL_CMP_ITAV_value(fixture->hdr->generalInfo, 0))), 0)) {
        return 0;
    }
    OSSL_CMP_ITAV_free(itav);
    return 1;
}

static int test_HDR_generalInfo_push1_items(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    fixture->expected = 1;
    EXECUTE_TEST(execute_HDR_generalInfo_push1_items_test, tear_down);
    return result;
}

static int
execute_HDR_set_and_check_implicitConfirm_test(CMP_HDR_TEST_FIXTURE
                                               * fixture)
{
    return TEST_false(ossl_cmp_hdr_check_implicitConfirm(fixture->hdr))
               && TEST_true(ossl_cmp_hdr_set_implicitConfirm(fixture->hdr))
               && TEST_true(ossl_cmp_hdr_check_implicitConfirm(fixture->hdr));
}

static int test_HDR_set_and_check_implicit_confirm(void)
{
    SETUP_TEST_FIXTURE(CMP_HDR_TEST_FIXTURE, set_up);
    EXECUTE_TEST(execute_HDR_set_and_check_implicitConfirm_test, tear_down);
    return result;
}

static int execute_CMP_ASN1_OCTET_STRING_set1_test(CMP_HDR_TEST_FIXTURE *
                                                   fixture)
{
    if (!TEST_int_eq(fixture->expected,
                     ossl_cmp_asn1_octet_string_set1(&fixture->tgt_string,
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
            || !TEST_true(ASN1_OCTET_STRING_set(fixture->src_string, rand_data,
                                                sizeof(rand_data)))) {
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

static int execute_HDR_init_test(CMP_HDR_TEST_FIXTURE *fixture)
{
    ASN1_OCTET_STRING *header_nonce = NULL;
    ASN1_OCTET_STRING *ctx_nonce = NULL;
    int res = 0;

    if (!TEST_int_eq(fixture->expected,
                     ossl_cmp_hdr_init(fixture->cmp_ctx, fixture->hdr)))
        goto err;
    if (fixture->expected != 0) {
        if (!TEST_int_eq(ossl_cmp_hdr_get_pvno(fixture->hdr), OSSL_CMP_PVNO)
                || !TEST_true(0 == ASN1_OCTET_STRING_cmp(
                        ossl_cmp_hdr_get0_senderNonce(fixture->hdr),
                        fixture->cmp_ctx->senderNonce))
                || !TEST_true(0 ==  ASN1_OCTET_STRING_cmp(
                            OSSL_CMP_HDR_get0_transactionID(fixture->hdr),
                            fixture->cmp_ctx->transactionID)))
            goto err;
        header_nonce = OSSL_CMP_HDR_get0_recipNonce(fixture->hdr);
        ctx_nonce = fixture->cmp_ctx->recipNonce;
        if (ctx_nonce != NULL
                 && (!TEST_ptr(header_nonce)
                         || !TEST_int_eq(0, ASN1_OCTET_STRING_cmp(header_nonce,
                                                                  ctx_nonce))))
            goto err;
    }

    res = 1;

 err:
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


void cleanup_tests(void)
{
    return;
}

int setup_tests(void)
{
    /* Message header tests */
    ADD_TEST(test_HDR_set_get_pvno);
    ADD_TEST(test_HDR_get0_senderNonce);
    ADD_TEST(test_HDR_set1_sender);
    ADD_TEST(test_HDR_set1_recipient);
    ADD_TEST(test_HDR_update_messageTime);
    ADD_TEST(test_HDR_set1_senderKID);
    ADD_TEST(test_HDR_push0_freeText);
    /* indirectly tests ossl_cmp_pkifreetext_push_str(): */
    ADD_TEST(test_HDR_push1_freeText);
    ADD_TEST(test_HDR_generalInfo_push0_item);
    ADD_TEST(test_HDR_generalInfo_push1_items);
    ADD_TEST(test_HDR_set_and_check_implicit_confirm);
    ADD_TEST(test_ASN1_OCTET_STRING_set); /* TODO move to cmp_asn_test.c */
    ADD_TEST(test_ASN1_OCTET_STRING_set_tgt_is_src); /* TODO move to cmp_asn_test.c */
    /* also tests public function OSSL_CMP_HDR_get0_transactionID(): */
    /* also tests public function OSSL_CMP_HDR_get0_recipNonce(): */
    /* also tests internal function ossl_cmp_hdr_get_pvno(): */
    ADD_TEST(test_HDR_init);
    ADD_TEST(test_HDR_init_with_subject);
    ADD_TEST(test_HDR_init_no_ref_no_subject);
    /* TODO make sure that total number of tests (here currently 24) is shown,
     also for other cmp_*text.c. Currently the test drivers always show 1. */

    return 1;
}
