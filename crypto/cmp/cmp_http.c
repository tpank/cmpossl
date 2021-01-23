/*
 * Copyright 2007-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>

#include <openssl/asn1t.h>
#include <openssl/http.h>
#include "internal/sockets.h"

#include "openssl/cmp.h"
#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/cmp.h>
#include <openssl/err.h>

/*
 * Send the PKIMessage req and on success return the response, else NULL.
 * Any previous error queue entries will likely be removed by ERR_clear_error().
 */
OSSL_CMP_MSG *OSSL_CMP_MSG_http_perform(OSSL_CMP_CTX *ctx,
                                        const OSSL_CMP_MSG *req)
{
    char server_port[32] = { '\0' };
    STACK_OF(CONF_VALUE) *headers = NULL;
    const char *const content_type_pkix = "application/pkixcmp";
    int tls_used, type, keep_alive;
    OSSL_CMP_MSG *res = NULL;

    if (ctx == NULL || req == NULL) {
        ERR_raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT);
        return NULL;
    }

    if (!X509V3_add_value("Pragma", "no-cache", &headers))
        return NULL;
    if (ctx->serverPort != 0)
        BIO_snprintf(server_port, sizeof(server_port), "%d", ctx->serverPort);
    tls_used = OSSL_CMP_CTX_get_http_cb_arg(ctx) != NULL;
    if (ctx->http_ctx == NULL)
        ossl_cmp_log3(DEBUG, ctx, "connecting to CMP server %s:%s%s",
                      ctx->server, server_port, tls_used ? " using TLS" : "");

    type = req->body->type;
    keep_alive = ctx->keep_alive;
    if (keep_alive != 0
        /* Ask for persistent connection only if may need more round trips */
            && type != OSSL_CMP_PKIBODY_IR
            && type != OSSL_CMP_PKIBODY_CR
            && type != OSSL_CMP_PKIBODY_P10CR
            && type != OSSL_CMP_PKIBODY_KUR
            && type != OSSL_CMP_PKIBODY_POLLREQ)
        keep_alive = 0;

    res = (OSSL_CMP_MSG *)
        OSSL_HTTP_transfer_asn1(&ctx->http_ctx, ctx->server, server_port,
                                ctx->serverPath, tls_used,
                                ctx->proxy, ctx->no_proxy,
                                NULL /* bio */, NULL /* rbio */,
                                ctx->http_cb, OSSL_CMP_CTX_get_http_cb_arg(ctx),
                                0 /* max_line */, 0 /* max_resp_len */,
                                headers, content_type_pkix,
                                (const ASN1_VALUE *)req,
                                ASN1_ITEM_rptr(OSSL_CMP_MSG),
                                content_type_pkix, ASN1_ITEM_rptr(OSSL_CMP_MSG),
                                ctx->msg_timeout, keep_alive);

    if (ctx->http_ctx == NULL)
        ossl_cmp_debug(ctx, "disconnected from CMP server");
    /*
     * Note that on normal successful end of the transaction the connection
     * is not closed at this level, but this will be done by the CMP client
     * application via OSSL_CMP_CTX_free() or OSSL_CMP_CTX_reinit().
     */
    if (res != NULL)
        ossl_cmp_debug(ctx, "finished reading response from CMP server");
    sk_CONF_VALUE_pop_free(headers, X509V3_conf_free);
    return res;
}
