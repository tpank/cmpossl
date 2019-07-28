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
 * use trace API for CMP-specific logging, prefixed by "CMP " and severity
 */

int OSSL_CMP_log_open(void) /* is designed to be idempotent */
{
#ifndef OPENSSL_NO_STDIO
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (bio != NULL && OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_CMP, bio))
        return 1;
    BIO_free(bio);
#endif
    return 0;
}

void OSSL_CMP_log_close(void) /* is designed to be idempotent */
{
    (void)OSSL_trace_set_channel(OSSL_TRACE_CATEGORY_CMP, NULL);
}

static OSSL_CMP_severity parse_level(const char *level)
{
    const char *end_level = strchr(level, ':');
    const int len = end_level - level;

    if (end_level == NULL)
        return -1;

    if (strncmp(level, OSSL_CMP_LOG_PREFIX,
                strlen(OSSL_CMP_LOG_PREFIX)) == 0)
        level += strlen(OSSL_CMP_LOG_PREFIX);
    return
        strncmp(level, "EMERG", len) == 0 ? OSSL_CMP_LOG_EMERG :
        strncmp(level, "ALERT", len) == 0 ? OSSL_CMP_LOG_ALERT :
        strncmp(level, "CRIT", len) == 0 ? OSSL_CMP_LOG_CRIT :
        strncmp(level, "ERROR", len) == 0 ? OSSL_CMP_LOG_ERR :
        strncmp(level, "WARN", len) == 0 ? OSSL_CMP_LOG_WARNING :
        strncmp(level, "NOTE", len) == 0 ? OSSL_CMP_LOG_NOTICE :
        strncmp(level, "INFO", len) == 0 ? OSSL_CMP_LOG_INFO :
        strncmp(level, "DEBUG", len) == 0 ? OSSL_CMP_LOG_DEBUG :
        -1;
}

size_t ossl_cmp_log_trace_cb(const char *buf, size_t cnt,
                             int category, int cmd, void *vdata)
{
    OSSL_CMP_CTX *ctx = vdata;
    const char *func = buf;
    const char *file = buf == NULL ? NULL : strchr(buf, ':');

    if (buf == NULL || cnt == 0 || cmd != OSSL_TRACE_CTRL_WRITE || ctx == NULL) {
            CMPerr(0, CMP_R_INVALID_ARGS);
            return 0;
    }
    if (file != NULL) {
        const char *line = strchr(++file, ':');

        OPENSSL_free(ctx->log_func);
        OPENSSL_free(ctx->log_file);
        ctx->log_func = NULL;
        ctx->log_file = NULL;
        ctx->log_line = 0;
        ctx->log_level = -1;
        if ((ctx->log_level = parse_level(buf)) < 0 && line++ != NULL) {
            char *level = NULL;
            const long line_number = strtol(line, &level, 10);

            if (level > line && *(level++) == ':') {
                if ((ctx->log_level = parse_level(level)) >= 0) {
                    /* buf contains location info; remember it */
                    ctx->log_func = OPENSSL_strndup(func, file - 1 - func);
                    ctx->log_file = OPENSSL_strndup(file, line - 1 - file);
                    ctx->log_line = (int)line_number;
                    return cnt;
                }
            }
        }
    }

    /* buf contains message text; send it to callback */
    if (ctx->log_cb(ctx->log_func != NULL ? ctx->log_func : "(no func)",
                    ctx->log_file != NULL ? ctx->log_file : "(no file)",
                    ctx->log_line, ctx->log_level, buf))
        return cnt;
    return 0;
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

#define MAX_DATA_LEN (4096-100) /* workaround for ERR_print_errors_cb() limit */
    do {
        int prev_len;
        const char *curr, *next;
        char *tmp;

        ERR_peek_last_error_line_data(&file, &line, &data, &flags);
        if ((flags & ERR_TXT_STRING) == 0) {
            data = "";
            separator = "";
        }
        prev_len = (int)strlen(data) + strlen(separator);
        curr = next = txt;
        while (*next != '\0' && prev_len + (next - txt) < MAX_DATA_LEN) {
            curr = next;
            if (*separator != '\0') {
                next = strstr(curr, separator);
                if (next != NULL)
                    next += strlen(separator);
                else
                    next = curr + strlen(curr);
            } else {
                next = curr + 1;
            }
        }
        if (*next != '\0') { /* here this implies: next points beyond limit */
            /* split error msg at curr since error data would get too long */
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
                     ERR_lib_error_string(err));
        /* calling ERR_func_error_string(err) meanwhile has lost its benefit */
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

    if (sk == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
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

    if (store == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
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

    if (store == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if ((sk = sk_X509_new_null()) == NULL)
        return NULL;
    objs = X509_STORE_get0_objects(store);
    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        X509 *cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));

        if (cert != NULL) {
            if (!sk_X509_push(sk, cert) || !X509_up_ref(cert)) {
                sk_X509_pop_free(sk, X509_free);
                return NULL;
            }
        }
    }
    return sk;
}

/*-
 * Builds up the certificate chain of certs as high up as possible using
 * the given list of certs containing all possible intermediate certificates and
 * optionally the (possible) trust anchor(s). See also ssl_add_cert_chain().
 *
 * Intended use of this function is to find all the certificates above the trust
 * anchor needed to verify an EE's own certificate.  Those are supposed to be
 * included in the ExtraCerts field of every first sent message of a transaction
 * when MSG_SIG_ALG is utilized.
 *
 * NOTE: This allocates a stack and increments the reference count of each cert,
 * so when not needed any more the stack and all its elements should be freed.
 * NOTE: in case there is more than one possibility for the chain,
 * OpenSSL seems to take the first one, check X509_verify_cert() for details.
 *
 * returns a pointer to a stack of (up_ref'ed) X509 certificates containing:
 *      - the EE certificate given in the function arguments (cert)
 *      - all intermediate certificates up the chain toward the trust anchor
 *      - the (self-signed) trust anchor is not included
 *      returns NULL on error
 */
STACK_OF(X509) *ossl_cmp_build_cert_chain(STACK_OF(X509) *certs,
                                          X509 *cert)
{
    STACK_OF(X509) *chain = NULL, *result = NULL;
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *csc = NULL;

    if (certs == NULL || cert == NULL || store == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    csc = X509_STORE_CTX_new();
    if (csc == NULL)
        goto err;

    OSSL_CMP_X509_STORE_add1_certs(store, certs, 0);
    if (!X509_STORE_CTX_init(csc, store, cert, NULL))
        goto err;

    (void)ERR_set_mark();
    /*
     * ignore return value as it would fail without trust anchor given in store
     */
    (void)X509_verify_cert(csc);

    /* don't leave any new errors in the queue */
    (void)ERR_pop_to_mark();

    chain = X509_STORE_CTX_get0_chain(csc);

    /* result list to store the up_ref'ed not self-signed certificates */
    if ((result = sk_X509_new_null()) == NULL)
        goto err;
    OSSL_CMP_sk_X509_add1_certs(result, chain,
                                1 /* no self-signed */, 1 /* no duplicates */);

 err:
    X509_STORE_free(store);
    X509_STORE_CTX_free(csc);
    return result;
}

X509_EXTENSIONS *ossl_cmp_x509_extensions_dup(const X509_EXTENSIONS *exts)
{
    if (exts == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    return sk_X509_EXTENSION_deep_copy(exts, X509_EXTENSION_dup,
                                       X509_EXTENSION_free);
}

int ossl_cmp_asn1_octet_string_set1(ASN1_OCTET_STRING **tgt,
                                    const ASN1_OCTET_STRING *src)
{
    if (tgt == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (*tgt == src) /* self-assignment */
        return 1;
    ASN1_OCTET_STRING_free(*tgt);

    if (src != NULL) {
        if ((*tgt = ASN1_OCTET_STRING_dup(src)) == NULL)
            return 0;
    } else {
        *tgt = NULL;
    }

    return 1;
}

int ossl_cmp_asn1_octet_string_set1_bytes(ASN1_OCTET_STRING **tgt,
                                          const unsigned char *bytes, int len)
{
    ASN1_OCTET_STRING *new = NULL;

    if (tgt == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if (bytes != NULL) {
        if ((new = ASN1_OCTET_STRING_new()) == NULL
                || !(ASN1_OCTET_STRING_set(new, bytes, len))) {
            ASN1_OCTET_STRING_free(new);
            return 0;
        }
    }
    return ossl_cmp_asn1_octet_string_set1(tgt, new);
}

/*
 * returns the PKIStatus of the given PKIStatusInfo
 * returns -1 on error
 */
static int OSSL_CMP_PKISI_PKIStatus_get(OSSL_CMP_PKISI *si)
{
    if (si == NULL || si->status == NULL) {
        CMPerr(0, CMP_R_ERROR_PARSING_PKISTATUS);
        return -1;
    }
    return ossl_cmp_asn1_get_int(si->status);
}

/*
 * internal function
 *
 * convert PKIStatus to human-readable string
 *
 * returns pointer to character array containing a sting representing the
 * PKIStatus of the given PKIStatusInfo
 * returns NULL on error
 */
static char *CMP_PKISI_PKIStatus_get_string(OSSL_CMP_PKISI *si)
{
    int PKIStatus;

    if ((PKIStatus = OSSL_CMP_PKISI_PKIStatus_get(si)) < 0)
        return NULL;
    switch (PKIStatus) {
    case OSSL_CMP_PKISTATUS_accepted:
        return "PKIStatus: accepted";
    case OSSL_CMP_PKISTATUS_grantedWithMods:
        return "PKIStatus: granted with mods";
    case OSSL_CMP_PKISTATUS_rejection:
        return "PKIStatus: rejection";
    case OSSL_CMP_PKISTATUS_waiting:
        return "PKIStatus: waiting";
    case OSSL_CMP_PKISTATUS_revocationWarning:
        return "PKIStatus: revocation warning";
    case OSSL_CMP_PKISTATUS_revocationNotification:
        return "PKIStatus: revocation notification";
    case OSSL_CMP_PKISTATUS_keyUpdateWarning:
        return "PKIStatus: key update warning";
    default:
        CMPerr(0, CMP_R_ERROR_PARSING_PKISTATUS);
    }
    return NULL;
}

/*
 * internal function
 * convert PKIFailureInfo bit to human-readable string or empty string if not set
 *
 * returns pointer to static string
 * returns NULL on error
 */
static char *OSSL_CMP_PKIFAILUREINFO_get_string(OSSL_CMP_PKIFAILUREINFO *fi,
                                                int i)
{
    if (fi == NULL)
        return NULL;
    if (0 <= i && i <= OSSL_CMP_PKIFAILUREINFO_MAX) {
        if (ASN1_BIT_STRING_get_bit(fi, i)) {
            switch (i) {
            case OSSL_CMP_PKIFAILUREINFO_badAlg:
                return "PKIFailureInfo: badAlg";
            case OSSL_CMP_PKIFAILUREINFO_badMessageCheck:
                return "PKIFailureInfo: badMessageCheck";
            case OSSL_CMP_PKIFAILUREINFO_badRequest:
                return "PKIFailureInfo: badRequest";
            case OSSL_CMP_PKIFAILUREINFO_badTime:
                return "PKIFailureInfo: badTime";
            case OSSL_CMP_PKIFAILUREINFO_badCertId:
                return "PKIFailureInfo: badCertId";
            case OSSL_CMP_PKIFAILUREINFO_badDataFormat:
                return "PKIFailureInfo: badDataFormat";
            case OSSL_CMP_PKIFAILUREINFO_wrongAuthority:
                return "PKIFailureInfo: wrongAuthority";
            case OSSL_CMP_PKIFAILUREINFO_incorrectData:
                return "PKIFailureInfo: incorrectData";
            case OSSL_CMP_PKIFAILUREINFO_missingTimeStamp:
                return "PKIFailureInfo: missingTimeStamp";
            case OSSL_CMP_PKIFAILUREINFO_badPOP:
                return "PKIFailureInfo: badPOP";
            case OSSL_CMP_PKIFAILUREINFO_certRevoked:
                return "PKIFailureInfo: certRevoked";
            case OSSL_CMP_PKIFAILUREINFO_certConfirmed:
                return "PKIFailureInfo: certConfirmed";
            case OSSL_CMP_PKIFAILUREINFO_wrongIntegrity:
                return "PKIFailureInfo: wrongIntegrity";
            case OSSL_CMP_PKIFAILUREINFO_badRecipientNonce:
                return "PKIFailureInfo: badRecipientNonce";
            case OSSL_CMP_PKIFAILUREINFO_timeNotAvailable:
                return "PKIFailureInfo: timeNotAvailable";
            case OSSL_CMP_PKIFAILUREINFO_unacceptedPolicy:
                return "PKIFailureInfo: unacceptedPolicy";
            case OSSL_CMP_PKIFAILUREINFO_unacceptedExtension:
                return "PKIFailureInfo: unacceptedExtension";
            case OSSL_CMP_PKIFAILUREINFO_addInfoNotAvailable:
                return "PKIFailureInfo: addInfoNotAvailable";
            case OSSL_CMP_PKIFAILUREINFO_badSenderNonce:
                return "PKIFailureInfo: badSenderNonce";
            case OSSL_CMP_PKIFAILUREINFO_badCertTemplate:
                return "PKIFailureInfo: badCertTemplate";
            case OSSL_CMP_PKIFAILUREINFO_signerNotTrusted:
                return "PKIFailureInfo: signerNotTrusted";
            case OSSL_CMP_PKIFAILUREINFO_transactionIdInUse:
                return "PKIFailureInfo: transactionIdInUse";
            case OSSL_CMP_PKIFAILUREINFO_unsupportedVersion:
                return "PKIFailureInfo: unsupportedVersion";
            case OSSL_CMP_PKIFAILUREINFO_notAuthorized:
                return "PKIFailureInfo: notAuthorized";
            case OSSL_CMP_PKIFAILUREINFO_systemUnavail:
                return "PKIFailureInfo: systemUnavail";
            case OSSL_CMP_PKIFAILUREINFO_systemFailure:
                return "PKIFailureInfo: systemFailure";
            case OSSL_CMP_PKIFAILUREINFO_duplicateCertReq:
                return "PKIFailureInfo: duplicateCertReq";
            }
        } else {
            return ""; /* bit is not set */
        }
    }
    return NULL; /* illegal bit position */
}

/*
 * place human-readable error string created from PKIStatusInfo in given buffer
 * returns pointer to the same buffer containing the string, or NULL on error
 */
char *ossl_cmp_pkisi_snprint(OSSL_CMP_PKISI *si, char *buf, int bufsize)
{
    const char *status, *failure;
    int i;
    int n = 0;

    if (si == NULL) {
        CMPerr(0, CMP_R_NULL_ARGUMENT);
        return NULL;
    }
    if ((status = CMP_PKISI_PKIStatus_get_string(si)) == NULL)
        return NULL;
    BIO_snprintf(buf, bufsize, "%s; ", status);

    /* PKIFailure is optional and may be empty */
    if (si->failInfo != NULL) {
        for (i = 0; i <= OSSL_CMP_PKIFAILUREINFO_MAX; i++) {
            failure = OSSL_CMP_PKIFAILUREINFO_get_string(si->failInfo, i);
            if (failure == NULL)
                return NULL;
            if (failure[0] != '\0')
                BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf), "%s%s",
                             n > 0 ? ", " : "", failure);
            n += (int)strlen(failure);
        }
    }
    if (n == 0)
        BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf), "<no failure info>");

    /* StatusString sequence is optional and may be empty */
    n = sk_ASN1_UTF8STRING_num(si->statusString);
    if (n > 0) {
        BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf),
                     "; StatusString%s: ", n > 1 ? "s" : "");
        for (i = 0; i < n; i++) {
            ASN1_UTF8STRING *text = sk_ASN1_UTF8STRING_value(si->statusString, i);
            BIO_snprintf(buf+strlen(buf), bufsize-strlen(buf), "\"%s\"%s",
                         ASN1_STRING_get0_data(text), i < n-1 ? ", " : "");
        }
    }
    return buf;
}

