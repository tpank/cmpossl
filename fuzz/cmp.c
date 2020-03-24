/*
 * Copyright 2007-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Test CMP DER parsing.
 */

#include <openssl/bio.h>
#include <openssl/cmp.h>
#include <openssl/err.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}

static OSSL_CMP_MSG *transfer_cb(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *req)
{
    return (OSSL_CMP_MSG *)OSSL_CMP_CTX_get_transfer_cb_arg(ctx);
}

static void cmp_client_process_response(OSSL_CMP_CTX *ctx, OSSL_CMP_MSG *msg)
{
    (void)OSSL_CMP_CTX_set_transfer_cb(ctx, transfer_cb);
    (void)OSSL_CMP_CTX_set_transfer_cb_arg(ctx, msg);
    (void)OSSL_CMP_exec_IR_ses(ctx);
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    OSSL_CMP_MSG *msg;
    BIO *in;

    if (len == 0)
        return 0;

    in = BIO_new(BIO_s_mem());
    OPENSSL_assert((size_t)BIO_write(in, buf, len) == len);
    msg = d2i_OSSL_CMP_MSG_bio(in, NULL);
    if (msg != NULL) {
        BIO *out = BIO_new(BIO_s_null());
        OSSL_CMP_SRV_CTX *srv_ctx = OSSL_CMP_SRV_CTX_new();
        OSSL_CMP_CTX *client_ctx = OSSL_CMP_CTX_new();

        i2d_OSSL_CMP_MSG_bio(out, msg);
        BIO_free(out);

        if (client_ctx != NULL)
            cmp_client_process_response(client_ctx, msg);
        if (srv_ctx != NULL)
            OSSL_CMP_MSG_free(OSSL_CMP_SRV_process_request(srv_ctx, msg));

        OSSL_CMP_CTX_free(client_ctx);
        OSSL_CMP_SRV_CTX_free(srv_ctx);
        OSSL_CMP_MSG_free(msg);
    }

    BIO_free(in);
    ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
}
