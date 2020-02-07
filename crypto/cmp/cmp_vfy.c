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
 * CMP implementation by Martin Peylo, Miikka Viljanen, and David von Oheimb.
 */

#include "cmp_local.h"

/* explicit #includes not strictly needed since implied by the above: */
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/*
 * internal function
 *
 * verify a message protected by signature according to section 5.1.3.3
 * (sha1+RSA/DSA or any other algorithm supported by OpenSSL)
 * returns 0 on error
 */
static int CMP_verify_signature(const OSSL_CMP_CTX *cmp_ctx,
                                const OSSL_CMP_MSG *msg, const X509 *cert)
{
    EVP_MD_CTX *ctx = NULL;
    CMP_PROTECTEDPART prot_part;
    int err = 1;
    int digest_nid, pk_nid;
    EVP_MD *digest = NULL;
    EVP_PKEY *pubkey = NULL;
    int l;
    size_t prot_part_der_len = 0;
    unsigned char *prot_part_der = NULL;

    if (cmp_ctx == NULL || msg == NULL || cert == NULL) {
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, CMP_R_NULL_ARGUMENT);
        return 0;
    }

    /* verify that keyUsage, if present, contains digitalSignature */
    if (!cmp_ctx->ignore_keyusage &&
        (X509_get_key_usage((X509 *)cert) & X509v3_KU_DIGITAL_SIGNATURE) == 0) {
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE,
               CMP_R_MISSING_KEY_USAGE_DIGITALSIGNATURE);
        err = 2;
        goto cert_err;
    }

    pubkey = X509_get_pubkey((X509 *)cert);
    if (pubkey == NULL) {
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, CMP_R_FAILED_EXTRACTING_PUBKEY);
        err = 2;
        goto cert_err;
    }

    /* create the DER representation of protected part */
    prot_part.header = msg->header;
    prot_part.body = msg->body;

    l = i2d_CMP_PROTECTEDPART(&prot_part, &prot_part_der);
    if (l < 0 || prot_part_der == NULL)
        goto cleanup;
    prot_part_der_len = (size_t) l;

    /* verify signature of protected part */
    if (!OBJ_find_sigid_algs(OBJ_obj2nid(msg->header->protectionAlg->algorithm),
                                         &digest_nid, &pk_nid) ||
        digest_nid == NID_undef ||
        pk_nid == NID_undef ||
        (digest = (EVP_MD *)EVP_get_digestbynid(digest_nid)) == NULL) {
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, CMP_R_ALGORITHM_NOT_SUPPORTED);
        err = 2;
        goto cleanup;
    }

    /* check msg->header->protectionAlg is consistent with public key type */
    if (EVP_PKEY_type(pk_nid) != EVP_PKEY_base_id(pubkey)) {
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, CMP_R_WRONG_ALGORITHM_OID);
        err = 2;
        goto cleanup;
    }

    if ((ctx = EVP_MD_CTX_create()) == NULL) {
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, ERR_R_MALLOC_FAILURE);
        goto cleanup;
    }
    err = (EVP_VerifyInit_ex(ctx, digest, NULL) &&
           EVP_VerifyUpdate(ctx, prot_part_der, prot_part_der_len) &&
           EVP_VerifyFinal(ctx, msg->protection->data,
                           msg->protection->length, pubkey) == 1)
        ? 0 : 2;

 cleanup:
    EVP_MD_CTX_destroy(ctx);
    OPENSSL_free(prot_part_der);
    EVP_PKEY_free(pubkey);

 cert_err:
    if (err == 2) { /* print diagnostics on cert verification error */
        X509_STORE *ts = cmp_ctx->trusted_store; /* may be empty, not NULL */
        X509_STORE_CTX *csc = X509_STORE_CTX_new();
        X509_STORE_CTX_verify_cb verify_cb = X509_STORE_get_verify_cb(ts);
        if (csc != NULL && verify_cb != NULL &&
            X509_STORE_CTX_init(csc, ts, NULL, NULL)) {
            X509_STORE_CTX_set_current_cert(csc, (X509 *)cert);
            X509_STORE_CTX_set_error_depth(csc, -1);
            X509_STORE_CTX_set_error(csc, X509_V_ERR_UNSPECIFIED);
            (void)(*verify_cb)(0, csc);
        }
        put_cert_verify_err(CMP_F_CMP_VERIFY_SIGNATURE,
                            CMP_R_ERROR_VALIDATING_PROTECTION);
        X509_STORE_CTX_free(csc);
    }
    return err == 0;
}

/*
 * internal function
 *
 * Verify a message protected with PBMAC
 */
static int CMP_verify_PBMAC(const OSSL_CMP_MSG *msg,
                            const ASN1_OCTET_STRING *secret)
{
    ASN1_BIT_STRING *protection = NULL;
    int valid = 0;

    /* generate expected protection for the message */
    if ((protection = CMP_calc_protection(msg, secret, NULL)) == NULL)
        goto err;               /* failed to generate protection string! */

    valid = ASN1_STRING_cmp((const ASN1_STRING *)protection,
                            (const ASN1_STRING *)msg->protection) == 0;
    ASN1_BIT_STRING_free(protection);
    if (!valid)
        CMPerr(CMP_F_CMP_VERIFY_PBMAC, CMP_R_WRONG_PBM_VALUE);

    return valid;
 err:
    return 0;
}

int OSSL_CMP_validate_cert_path(OSSL_CMP_CTX *ctx,
                                X509_STORE *trusted_store, X509 *cert)
{
    return ossl_cmp_validate_cert_path(ctx, trusted_store,
                                       ctx->untrusted_certs,
                                       cert, 0 /* defer_errors */);
}

/*
 * Attempt to validate certificate and path using given store of trusted certs
 * (possibly including CRLs and a cert verification callback function) and
 * non-trusted intermediate certs from the given ctx and extraCerts.
 * The defer_errors parameter needs to be set when used in a certConf callback
 * as any following certConf exchange will likely clear the OpenSSL error queue.
 * Returns 1 on successful validation and 0 otherwise.
 */
int ossl_cmp_validate_cert_path(OSSL_CMP_CTX *ctx,
                                X509_STORE *trusted_store,
                                const STACK_OF(X509) *extra_untrusted,
                                X509 *cert, int defer_errors)
{
    int valid = 0;
    X509_STORE_CTX *csc = NULL;
    STACK_OF(X509) *untrusted;

    if (ctx == NULL || trusted_store == NULL || cert == NULL) {
        CMPerr(CMP_F_OSSL_CMP_VALIDATE_CERT_PATH, CMP_R_NULL_ARGUMENT);
        goto end;
    }

    if ((csc = X509_STORE_CTX_new()) == NULL ||
        !X509_STORE_CTX_init(csc, (X509_STORE *)trusted_store, (X509 *)cert,
                             (STACK_OF(X509) *)ctx->untrusted_certs) ||
        ((untrusted = X509_STORE_CTX_get0_untrusted(csc)) == NULL) ||
        !OSSL_CMP_sk_X509_add1_certs(untrusted, extra_untrusted,
                                     0, 1/* no dups */)) {
        goto end;
    }

    valid = X509_verify_cert(csc) > 0;

    if (!valid && !defer_errors) {
        put_cert_verify_err(CMP_F_OSSL_CMP_VALIDATE_CERT_PATH,
                            CMP_R_POTENTIALLY_INVALID_CERTIFICATE);
    }

 end:
    X509_STORE_CTX_free(csc);
    return valid;
}

/*
 * helper functions for improving certificate verification error diagnostics
 */

static void print_cert(BIO *bio, const X509 *cert, unsigned long neg_cflags) {
    if (cert != NULL) {
        unsigned long flags = ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_ESC_QUOTE |
            XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN;

        BIO_printf(bio, "    certificate\n");
        X509_print_ex(bio, (X509 *)cert, flags, ~X509_FLAG_NO_SUBJECT);
        if (X509_check_issued((X509 *)cert, (X509 *)cert) == X509_V_OK) {
            BIO_printf(bio, "        self-issued\n");
        } else {
            BIO_printf(bio, " ");
            X509_print_ex(bio, (X509 *)cert, flags, ~X509_FLAG_NO_ISSUER);
        }
        X509_print_ex(bio, (X509 *)cert, flags,
                           ~(X509_FLAG_NO_SERIAL | X509_FLAG_NO_VALIDITY));
        if (X509_cmp_current_time(X509_get0_notBefore(cert)) > 0) {
            BIO_printf(bio, "        not yet valid\n");
        }
        if (X509_cmp_current_time(X509_get0_notAfter(cert)) < 0) {
            BIO_printf(bio, "        no more valid\n");
        }
        X509_print_ex(bio, (X509 *)cert, flags, ~(neg_cflags));
    } else {
        BIO_printf(bio, "    (no certificate)\n");
    }
}

static void print_certs(BIO *bio, const STACK_OF(X509) *certs) {
    if (certs != NULL && sk_X509_num(certs) > 0) {
        int i;

        for (i = 0; i < sk_X509_num(certs); i++) {
            X509 *cert = sk_X509_value(certs, i);
            if (cert != NULL) {
                print_cert(bio, cert, 0);
            }
        }
    } else {
        BIO_printf(bio, "    (no certificates)\n");
    }
}

static void print_store_certs(BIO *bio, X509_STORE *store) {
    if (store != NULL) {
        STACK_OF(X509) *certs = OSSL_CMP_X509_STORE_get1_certs(store);
        print_certs(bio, certs);
        sk_X509_pop_free(certs, X509_free);
    } else {
        BIO_printf(bio, "    (no certificate store)\n");
    }
}

/* needed because cert verify errors are threatened by ERR_clear_error() */
static BIO *cert_verify_err_bio = NULL;

static void clear_cert_verify_err(void) {
    BIO_free(cert_verify_err_bio);
    cert_verify_err_bio = NULL;
}

void put_cert_verify_err(int func, int err)
{
    if (err != 0) { /* cert verify error in callback */
        CMPerr(func, err);
        if (cert_verify_err_bio != NULL) {
            char *str;
            long len = BIO_get_mem_data(cert_verify_err_bio, &str);

            if (len > 0) {
                str[len-1] = '\0'; /* replace last '\n', terminating str */
                OSSL_CMP_add_error_line(str);
            }
        }
    }
    clear_cert_verify_err();
}

/*
 * This is a diagnostic function that may be registered using
 * X509_STORE_set_verify_cb(), such that it gets called by OpenSSL's
 * verify_cert() function at the end of a cert verification as an opportunity
 * to gather and output information regarding a (failing) cert verification,
 * and to possibly change the result of the verification (not done here).
 * The CLI also calls it on error while cert status checking using OCSP stapling
 * via a callback function set with SSL_CTX_set_tlsext_status_cb().
 * returns 0 if and only if the cert verification is considered failed.
 */
int OSSL_CMP_print_cert_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    if (ok == 0 && ctx != NULL) {
        int cert_error = X509_STORE_CTX_get_error(ctx);
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        X509 *cert = X509_STORE_CTX_get_current_cert(ctx);

        if (cert_verify_err_bio == NULL) {
            cert_verify_err_bio = BIO_new(BIO_s_mem()); /* may result in NULL */
        }
        if (depth < 0)
            BIO_printf(cert_verify_err_bio, "signature verification ");
        else
            BIO_printf(cert_verify_err_bio, "%s at depth=%d error=%d (%s)\n",
                       X509_STORE_CTX_get0_parent_ctx(ctx) != NULL ?
                       "CRL path validation" : "certificate verification",
                       depth, cert_error,
                       X509_verify_cert_error_string(cert_error));
        BIO_printf(cert_verify_err_bio, "failure for:\n");
        print_cert(cert_verify_err_bio, cert, X509_FLAG_NO_EXTENSIONS);
        if (cert_error == X509_V_ERR_CERT_UNTRUSTED ||
            cert_error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
            cert_error == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
            cert_error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ||
            cert_error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
            cert_error == X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER ||
            cert_error == X509_V_ERR_STORE_LOOKUP) {
            BIO_printf(cert_verify_err_bio, "non-trusted certs:\n");
            print_certs(cert_verify_err_bio, X509_STORE_CTX_get0_untrusted(ctx));
            BIO_printf(cert_verify_err_bio, "trust store:\n");
            print_store_certs(cert_verify_err_bio,
                              X509_STORE_CTX_get0_store(ctx));
        }
        put_cert_verify_err(CMP_F_OSSL_CMP_PRINT_CERT_VERIFY_CB,
                            CMP_R_POTENTIALLY_INVALID_CERTIFICATE);
#ifndef OPENSSL_NO_STDIO
        ERR_print_errors_fp(stdout);
#endif /* OPENSSL_NO_STDIO */
    }
#if 0
    /* TODO: we could check policies here too */
    if (cert_error == X509_V_OK && ok == 2)
        policies_print(NULL, ctx);
#endif

    return (ok);
}

/* return 0 if time should not be checked or reference time is within frame,
   or else 1 if it s past the end, or -1 if it is before the start */
int OSSL_CMP_cmp_timeframe(const ASN1_TIME *start,
                           const ASN1_TIME *end, X509_VERIFY_PARAM *vpm)
{
    time_t check_time, *ptime = NULL;
    unsigned long flags = vpm == NULL ? 0 :
                          X509_VERIFY_PARAM_get_flags((X509_VERIFY_PARAM*)vpm);

    if ((flags & X509_V_FLAG_USE_CHECK_TIME) != 0) {
        check_time = X509_VERIFY_PARAM_get_time(vpm);
        ptime = &check_time;
    } else if ((flags & X509_V_FLAG_NO_CHECK_TIME) != 0) {
        return 0; /* ok */
    }
    return (end   != NULL && X509_cmp_time(end  , ptime) < 0) ? +1 :
           (start != NULL && X509_cmp_time(start, ptime) > 0) ? -1 : 0;
}

static void add_name_mismatch_data(const char *error_prefix,
                                   OPENSSL_CMP_CONST X509_NAME *actual_name,
                                   OPENSSL_CMP_CONST X509_NAME *expected_name)
{
    char *expected = X509_NAME_oneline(expected_name, NULL, 0);
    char *actual = actual_name != NULL ? X509_NAME_oneline(actual_name, NULL, 0)
                                       : "(none)";
    if (error_prefix != NULL)
        OSSL_CMP_add_error_txt("\n", error_prefix);
    OSSL_CMP_add_error_txt("\n   actual = ", actual);
    OSSL_CMP_add_error_txt("\n expected = ", expected);
    OPENSSL_free(expected);
    OPENSSL_free(actual);
}

/* return 0 if skid != NULL and subject key ID is in cert but does not match */
static int check_kid(X509 *cert, const ASN1_OCTET_STRING *skid, int fn)
{
    if (skid != NULL) {
        const ASN1_OCTET_STRING *ckid = X509_get0_subject_key_id(cert);

        /* see if cert contains subject key identifier */
        if (ckid == NULL) {
            if (fn != 0)
                CMPerr(fn, CMP_R_UNEXPECTED_SENDER);
            OSSL_CMP_add_error_line("  missing Subject Key Identifier in certificate");
            return 1;
        }
        /* enforce that it matches senderKID */
        if (ASN1_OCTET_STRING_cmp(ckid, skid) != 0) {
#ifdef hex_to_string
            char *str;
#endif
            if (fn != 0)
                CMPerr(fn, CMP_R_UNEXPECTED_SENDER);
            OSSL_CMP_add_error_line("  certificate Subject Key Identifier does not match senderKID:");
#ifdef hex_to_string
            str = OPENSSL_buf2hexstr(ckid->data, ckid->length);
            OSSL_CMP_add_error_txt("      actual = ", str);
            OPENSSL_free(str);
            str = OPENSSL_buf2hexstr(skid->data, skid->length);
            OSSL_CMP_add_error_txt("    expected = ", str);
            OPENSSL_free(str);
#endif
            return 0;
        }
    }
    return 1;
}

/*
 * internal function
 *
 * Check if the given cert is acceptable as sender cert of the given message.
 * The subject DN must match, the subject key ID as well if present in the msg,
 * and the cert must be current (for checking this, the ctx should be given).
 * Note that cert revocation etc. is checked by ossl_cmp_validate_cert_path().
 * returns 0 on error or not acceptable, else 1
 */
static int cert_acceptable(OSSL_CMP_CTX *ctx, X509 *cert,
                           const OSSL_CMP_MSG *msg) {
    X509_NAME *sender_name = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    int time_cmp;

    vpm = ctx != NULL ? X509_STORE_get0_param(ctx->trusted_store) : NULL;
    if (cert == NULL || msg == NULL || (ctx != NULL && vpm == NULL))
        return 0; /* TODO better flag and handle this as fatal internal error */

    time_cmp = OSSL_CMP_cmp_timeframe(X509_get0_notBefore(cert),
                                      X509_get0_notAfter (cert), vpm);
    if (time_cmp != 0) {
        OSSL_CMP_add_error_line(time_cmp > 0 ? "  certificate expired"
                                             : "  certificate not yet valid");
        return 0;
    }

    if ((sender_name = msg->header->sender->d.directoryName) != NULL) {
        X509_NAME *name = X509_get_subject_name(cert);

        /* enforce that the right subject DN is there */
        if (name == NULL) {
            OSSL_CMP_add_error_line("  missing subject in certificate");
            return 0;
        }
        if (X509_NAME_cmp(name, sender_name) != 0) {
            add_name_mismatch_data("  certificate subject does not match sender:",
                                   name, sender_name);
            return 0;
        }
    }

    if (!check_kid(cert, msg->header->senderKID, 0))
        return 0;
    /* acceptable also if there is no senderKID in msg header */

    return 1;
}

/*
 * internal function
 */
static int validate_cert_and_msg(OSSL_CMP_CTX *ctx,
                                 X509 *cert, const OSSL_CMP_MSG *msg)
{
    return ossl_cmp_validate_cert_path(ctx, ctx->trusted_store,
                                       msg->extraCerts, cert, 0)
        && CMP_verify_signature(ctx, msg, cert);
}

/*
 * internal function
 *
 * Find in the list of certs all acceptable certs (see cert_acceptable()).
 * Return 2 if one of them is acceptable and valid and can successfully be used
 *          to verify the signature of the msg, setting ctx->validatedSrvCert
 * Return 1 else after adding them (except duplicates) to found_certs if given.
 * Return 0 on (argument or out of memory) error
 */
static int find_acceptable_certs(OSSL_CMP_CTX *ctx,
                                 STACK_OF(X509) *certs,
                                 const OSSL_CMP_MSG *msg,
                                 STACK_OF(X509) *found_certs)
{
    int i;

    for (i = 0; i < sk_X509_num(certs); i++) { /* certs may be NULL */
        X509 *cert = sk_X509_value(certs, i);
        char *str = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

        OSSL_CMP_add_error_txt(NULL, "\n considering cert with subject ");
        OSSL_CMP_add_error_txt(" = ", str);
        OPENSSL_free(str);
        str = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        OSSL_CMP_add_error_line(       "                   and issuer  ");
        OSSL_CMP_add_error_txt(" = ", str);
        OPENSSL_free(str);

        if (cert_acceptable(ctx, cert, msg)) {
            if (validate_cert_and_msg(ctx, cert, msg)) {
                /* store trusted srv cert for future msgs of same transaction */
                X509_up_ref(cert);
                ctx->validatedSrvCert = cert;
                return 2;
            }
            if (found_certs != NULL
                && !OSSL_CMP_sk_X509_add1_cert(found_certs, cert, 1/*no dups*/))
            return 0;
        }
    }
    return 1;
}

/*
 * internal function
 *
 * Find candidate server certificate(s) by using find_acceptable_certs()
 * looking for current certs with subject matching the msg sender name
 * and (if set in msg) a matching sender keyID = subject key ID.
 *
 * Traverse any extraCerts, any given untrusted certs, and certs in truststore.
 * Return 2 if one of them is acceptable and valid and can successfully be used
 *          to verify the signature of the msg.
 * Return 1 else after adding them (except duplicates) to found_certs if given.
 * Return 0 on (argument or out of memory) error
 */
static int find_server_cert(OSSL_CMP_CTX *ctx,
                            const OSSL_CMP_MSG *msg,
                            STACK_OF(X509) *found_certs)
{
    int ret;
    STACK_OF(X509) *trusted;

    ret = find_acceptable_certs(ctx, msg->extraCerts, msg, found_certs);
    if (ret != 1)
        return ret;
    OSSL_CMP_add_error_line("no suitable certificate found in extraCerts");

    ret = find_acceptable_certs(ctx, ctx->untrusted_certs, msg, found_certs);
    if (ret != 1)
        return ret;
    OSSL_CMP_add_error_line("no suitable certificate found in untrusted certs");

    trusted = OSSL_CMP_X509_STORE_get1_certs(ctx->trusted_store);
    ret = find_acceptable_certs(ctx, trusted, msg, found_certs);
    sk_X509_pop_free(trusted, X509_free);
    if (ret != 1)
        return ret;
    OSSL_CMP_add_error_line("no suitable certificate found in trust store");

    return 1;
}

/*
 * internal function
 *
 * Validate msg using some suitable server cert. Return value > 0 on success:
 * 4 for ctx->srvCert - if set, this this the only option
 * 3 for ctx->validatedSrvCert (i.e., the same server cert used before)
 * 2 for a cert found in extraCerts, ctx->untrusted_cert, or ctx->trusted_store
 * 1 like before but trusting a cert in extraCerts according to 3GPP TS 33.310
 * Return 0 on (argument or out of memory) error or unsuccessful outcome
 */
static int find_validate_srvcert_and_msg(OSSL_CMP_CTX *ctx,
                                         const OSSL_CMP_MSG *msg)
{
    X509 *scrt = NULL;
    GENERAL_NAME *sender = msg->header->sender;
    STACK_OF(X509) *found_crts = NULL;
    X509_STORE *extra_store = NULL;
    char *name;
    int i;
    int ret;

    if (sender == NULL || msg->body == NULL)
        return 0; /* other NULL cases already have been checked */
    if (sender->type != GEN_DIRNAME) {
        CMPerr(CMP_F_FIND_VALIDATE_SRVCERT_AND_MSG,
               CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED);
        return 0; /* FR#42: support for more than X509_NAME */
    }

    scrt = ctx->srvCert;
    if (scrt != NULL) /* do not validate cert path of this pinned cert */
        return CMP_verify_signature(ctx, msg, scrt) == 0 ? 0 : 4;

    /*
     * valid scrt, matching sender name, found earlier in transaction, will be
     * used for validating any further msgs where extraCerts may be left out
     */
    scrt = ctx->validatedSrvCert;
    (void)ERR_set_mark();
    if (ctx->validatedSrvCert != NULL &&
        validate_cert_and_msg(ctx, scrt, msg)) {
        (void)ERR_pop_to_mark();
        return 3;
    }

    (void)ERR_pop_to_mark();
    /* release any cached cert, which is no more acceptable */
    X509_free(ctx->validatedSrvCert);
    ctx->validatedSrvCert = NULL;

    /*
     * Prepare exceptional handling for 3GPP TS 33.310 section 9.5.4.3,
     * only to use for IP and if the ctx option is explicitly set:
     * use self-signed certificates from extraCerts as trust anchor to validate
     * scrt, provided they also can validate the newly enrolled certificate
     */
    if (ctx->permitTAInExtraCertsForIR
        && OSSL_CMP_MSG_get_bodytype(msg) == OSSL_CMP_PKIBODY_IP) {
        /*
         * verify that the newly enrolled certificate (which is assumed to have
         * rid == OSSL_CMP_CERTREQID) validates with the extraCerts as trusted
         */
        extra_store = X509_STORE_new(); /* does not include CRLs */
        if (extra_store == NULL
            || !OSSL_CMP_X509_STORE_add1_certs(extra_store, msg->extraCerts,
                                               1/* self-signed only */)) {
            return 0;
        } else {
            const OSSL_CMP_CERTRESPONSE *crep =
                CMP_CERTREPMESSAGE_certResponse_get0(msg->body->value.ip,
                                                     OSSL_CMP_CERTREQID);
            X509 *newcrt = CMP_CERTRESPONSE_get_certificate(ctx, crep);
            /*
             * TODO maybe better use get_cert_status() from cmp_ses.c,
             * which catches errors
             */
            (void)ERR_set_mark();
            ret = ossl_cmp_validate_cert_path(ctx, extra_store,
                                              msg->extraCerts, newcrt, 0);
            (void)ERR_pop_to_mark();
            X509_free(newcrt);
            if (ret) {
                /* sk_TYPE_find to use compfunc X509_cmp, not ptr comparison */
                if ((found_crts = sk_X509_new_null()) == NULL)
                    return 0;
            }
        }
    }

    /* tentatively set error, which allows accumulating diagnostic info */
    (void)ERR_set_mark();
    CMPerr(CMP_F_FIND_VALIDATE_SRVCERT_AND_MSG,
           CMP_R_NO_VALID_SERVER_CERT_FOUND);
    name = X509_NAME_oneline(sender->d.directoryName, NULL, 0);
    OSSL_CMP_add_error_txt(NULL, "\n");
    OSSL_CMP_add_error_txt("trying to match msg sender name = ", name);
    OPENSSL_free(name);

    /* find server cert (or at least candidates) from any available source */
    ret = find_server_cert(ctx, msg, found_crts);
    if (ret != 1)
        goto end;

    if (found_crts != NULL) { /* perform exceptional 3GPP TS 33.310 handling */
        OSSL_CMP_add_error_line("last resort: trying exceptional 3GPP TS 33.310 handling");
        for (i = 0; i < sk_X509_num(found_crts); i++) {
            scrt = sk_X509_value(found_crts, i);
            name = X509_NAME_oneline(X509_get_subject_name(scrt), NULL, 0);
            OSSL_CMP_add_error_line(" considering cert with subject");
            OSSL_CMP_add_error_txt(" = ", name);
            OPENSSL_free(name);
            if (ossl_cmp_validate_cert_path(ctx, extra_store,
                                            msg->extraCerts, scrt, 0))
                goto end; /* ret == 1 */
        }
    }
    ret = 0;

 end:
    if (ret != 0) {
        /* discard any diagnostic info on finding server cert */
        clear_cert_verify_err();
        (void)ERR_pop_to_mark();
    }
    sk_X509_pop_free(found_crts, X509_free);
    X509_STORE_free(extra_store);
    return ret;
}

/*
 * Validates the protection of the given PKIMessage using either password-
 * based mac (PBM) or a signature algorithm. In the case of signature algorithm,
 * the certificate can be provided in ctx->srvCert,
 * else it is taken from extraCerts, ctx->untrusted_certs, and
 * ctx->trusted_store and validated against ctx->trusted_store.
 *
 * If ctx->permitTAInExtraCertsForIR is true, the trust anchor may be taken from
 * the extraCerts field when a self-signed certificate is found there which can
 * be used to validate the enrolled certificate returned in IP.
 *  This is according to the need given in 3GPP TS 33.310.
 *
 * returns 1 on success, 0 on error or validation failed
 */
int OSSL_CMP_validate_msg(OSSL_CMP_CTX *ctx, const OSSL_CMP_MSG *msg)
{
    X509_ALGOR *alg;
    int nid = NID_undef, pk_nid = NID_undef;
    OPENSSL_CMP_CONST ASN1_OBJECT *algorOID = NULL;

    if (ctx == NULL || msg == NULL || msg->header == NULL) {
        CMPerr(CMP_F_OSSL_CMP_VALIDATE_MSG, CMP_R_NULL_ARGUMENT);
        return 0;
    }
    if ((alg = msg->header->protectionAlg) == NULL || /* unprotected message */
        msg->protection == NULL || msg->protection->data == NULL) {
        CMPerr(CMP_F_OSSL_CMP_VALIDATE_MSG, CMP_R_MISSING_PROTECTION);
        return 0;
    }

    /* determine the nid for the used protection algorithm */
    X509_ALGOR_get0(&algorOID, NULL, NULL, alg);
    nid = OBJ_obj2nid(algorOID);

    switch (nid) {
        /* 5.1.3.1.  Shared Secret Information */
    case NID_id_PasswordBasedMAC:
        if (CMP_verify_PBMAC(msg, ctx->secretValue)) {
            /*
             * RFC 4210, 5.3.2: 'Note that if the PKI Message Protection is
             * "shared secret information", then any certificate transported in
             * the caPubs field may be directly trusted as a root CA
             * certificate by the initiator.'
             */
            switch (OSSL_CMP_MSG_get_bodytype(msg)) {
            case OSSL_CMP_PKIBODY_IP:
            case OSSL_CMP_PKIBODY_CP:
            case OSSL_CMP_PKIBODY_KUP:
            case OSSL_CMP_PKIBODY_CCP:
                if (!OSSL_CMP_X509_STORE_add1_certs(ctx->trusted_store,
                                                    msg->body->value.ip->caPubs,
                                                    0)) /* value.ip is same for
                                                           cp, kup, and ccp */
                    /* allows self-signed and not self-signed certs */
                    break;
            }
            return 1;
        }
        break;

        /* TODO: 5.1.3.2.  DH Key Pairs --> GitHub issue#87 */
    case NID_id_DHBasedMac:
        CMPerr(CMP_F_OSSL_CMP_VALIDATE_MSG,
               CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC);
        break;

        /*
         * 5.1.3.3.  Signature */
        /* TODO: should that better white-list DSA/RSA etc.?
         * -> check all possible options from OpenSSL, should there be macro?
         */
    default:
        if (!OBJ_find_sigid_algs(OBJ_obj2nid(alg->algorithm), NULL, &pk_nid) ||
            pk_nid == NID_undef) {
            CMPerr(CMP_F_OSSL_CMP_VALIDATE_MSG, CMP_R_UNKNOWN_ALGORITHM_ID);
            break;
        }
        /* validate sender name of received msg */
        if (msg->header->sender->type != GEN_DIRNAME) {
            CMPerr(CMP_F_OSSL_CMP_VALIDATE_MSG,
                   CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED);
            break; /* FR#42: support for more than X509_NAME */
        }
        /*
         * Compare actual sender name of response with expected sender name.
         * Mitigates risk to accept misused certificate of an unauthorized
         * entity of a trusted hierarchy.
         */
        if (ctx->expected_sender != NULL) {
            /* set explicitly or subject of ctx->srvCert */
            X509_NAME *sender_name = msg->header->sender->d.directoryName;
            if (X509_NAME_cmp(ctx->expected_sender, sender_name) != 0) {
                CMPerr(CMP_F_OSSL_CMP_VALIDATE_MSG, CMP_R_UNEXPECTED_SENDER);
                add_name_mismatch_data("", sender_name, ctx->expected_sender);
                break;
            }
        }/* Note: if recipient was NULL-DN it could be learned here if needed */

        if (find_validate_srvcert_and_msg(ctx, msg) != 0)
            return 1;

        if (ctx->srvCert != NULL) /* add cert matching diagnostics */
            (void)cert_acceptable(ctx, ctx->srvCert, msg);

        CMPerr(CMP_F_OSSL_CMP_VALIDATE_MSG, CMP_R_NO_SUITABLE_SERVER_CERT);
        break;
    }
    return 0;
}


/*
 * callback validating that the new certificate can be verified, using
 * ctx->certConf_cb_arg, which has been initialized using opt_out_trusted, and
 * ctx->untrusted_certs, which at this point already contains ctx->extraCertsIn.
 * Returns 0 on acceptance, else a bit field reflecting PKIFailureInfo.
 * Quoting from RFC 4210 section 5.1. Overall PKI Message:
 *     The extraCerts field can contain certificates that may be useful to
 *     the recipient.  For example, this can be used by a CA or RA to
 *     present an end entity with certificates that it needs to verify its
 *     own new certificate (if, for example, the CA that issued the end
 *     entity's certificate is not a root CA for the end entity).  Note that
 *     this field does not necessarily contain a certification path; the
 *     recipient may have to sort, select from, or otherwise process the
 *     extra certificates in order to use them.
 * Note: While often handy, there is no hard requirement by CMP that
 * an EE must be able to validate the certificates it gets enrolled.
 */
int OSSL_CMP_certConf_cb(OSSL_CMP_CTX *ctx, X509 *cert, int fail_info,
                         const char **text)
{
    X509_STORE *out_trusted = OSSL_CMP_CTX_get_certConf_cb_arg(ctx);
    (void)text; /* make (artificial) use of var to prevent compiler warning */

    if (fail_info != 0) /* accept any error flagged by CMP core library */
        return fail_info;

    if (out_trusted != NULL &&
        !ossl_cmp_validate_cert_path(ctx, out_trusted, NULL, cert, 1))
        fail_info = 1 << OSSL_CMP_PKIFAILUREINFO_incorrectData;

    if (fail_info != 0) {
        char *str = X509_NAME_oneline(X509_get_subject_name((X509 *)cert),
                                      NULL, 0);
        OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR,
               "failed to validate newly enrolled certificate with subject: %s",
                        str);
        OPENSSL_free(str);
    }
    return fail_info;
}
