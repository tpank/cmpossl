/* crypto/cmp/cmp_vfy.c
 * Functions to verify CMP (RFC 4210) messages for OpenSSL
 */
/* ====================================================================
 * Originally written by Martin Peylo for the OpenSSL project.
 * <martin dot peylo at nsn dot com>
 * 2010-2012 Miikka Viljanen <mviljane@users.sourceforge.net>
 */
/* ====================================================================
 * Copyright (c) 2007-2010 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in
 *        the documentation and/or other materials provided with the
 *        distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *        software must display the following acknowledgment:
 *        "This product includes software developed by the OpenSSL Project
 *        for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *        endorse or promote products derived from this software without
 *        prior written permission. For written permission, please contact
 *        openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *        nor may "OpenSSL" appear in their names without prior written
 *        permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *        acknowledgment:
 *        "This product includes software developed by the OpenSSL Project
 *        for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.      IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2007-2014 Nokia Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by
 * Nokia for contribution to the OpenSSL project.
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/cmp.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "cmp_int.h"

/*
 * internal function
 *
 * verify a message protected by signature according to section 5.1.3.3
 * (sha1+RSA/DSA or any other algorithm supported by OpenSSL)
 * returns 0 on error
 */
static int CMP_verify_signature(const CMP_CTX *cmp_ctx,
                                const CMP_PKIMESSAGE *msg, const X509 *cert)
{
    EVP_MD_CTX *ctx = NULL;
    CMP_PROTECTEDPART prot_part;
    int ret = 0;
    int digest_NID;
    EVP_MD *digest = NULL;
    EVP_PKEY *pubkey = NULL;

    int l;
    size_t prot_part_der_len = 0;
    unsigned char *prot_part_der = NULL;

    if (msg == NULL || cert == NULL)
        goto param_err;

    /* verify that keyUsage, if present, contains digitalSignature */
    if (!cmp_ctx->ignore_keyusage &&
        !(X509_get_key_usage((X509 *)cert) & X509v3_KU_DIGITAL_SIGNATURE)) {
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, CMP_R_WRONG_KEY_USAGE);
            goto cert_err;
    }

    pubkey = X509_get_pubkey((X509 *)cert);
    if (pubkey == NULL) {
    param_err:
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, CMP_R_INVALID_KEY);
        return 0;
    }

    /* create the DER representation of protected part */
    prot_part.header = msg->header;
    prot_part.body = msg->body;

    l = i2d_CMP_PROTECTEDPART(&prot_part, &prot_part_der);
    if (l < 0 || prot_part_der == NULL)
        return 0;
    prot_part_der_len = (size_t) l;

    /* verify protection of protected part */
    if (!OBJ_find_sigid_algs(OBJ_obj2nid(msg->header->protectionAlg->algorithm),
                                         &digest_NID, NULL) ||
        (digest = (EVP_MD *)EVP_get_digestbynid(digest_NID)) == NULL) {
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, CMP_R_ALGORITHM_NOT_SUPPORTED);
        return 0;
    }

    if ((ctx = EVP_MD_CTX_create()) == NULL) {
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, CMP_R_OUT_OF_MEMORY);
        return 0;
    }
    ret = EVP_VerifyInit_ex(ctx, digest, NULL) &&
          EVP_VerifyUpdate(ctx, prot_part_der, prot_part_der_len) &&
          EVP_VerifyFinal(ctx, msg->protection->data,
                          msg->protection->length, pubkey) == 1;

    /* cleanup */
    EVP_MD_CTX_destroy(ctx);
    OPENSSL_free(prot_part_der);
    EVP_PKEY_free(pubkey);

    if (!ret) {
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, CMP_R_ERROR_VALIDATING_PROTECTION);
    }
 cert_err:
    if (!ret) {
        X509_STORE_CTX *csc = X509_STORE_CTX_new();
        X509_STORE_CTX_verify_cb verify_cb =
            X509_STORE_get_verify_cb(cmp_ctx->trusted_store);
        if (csc && verify_cb &&
            X509_STORE_CTX_init(csc, cmp_ctx->trusted_store, NULL, NULL)) {
            X509_STORE_CTX_set_current_cert(csc, (X509 *)cert);
            X509_STORE_CTX_set_error_depth(csc, -1);
            X509_STORE_CTX_set_error(csc, X509_V_ERR_UNSPECIFIED);
            (void)(*verify_cb)(0, csc); /* just print diagnostics on cert */
        }
        X509_STORE_CTX_free(csc);
    }
    return ret;
}

/*
 * internal function
 *
 * Verify a message protected with PBMAC
 */
static int CMP_verify_PBMAC(const CMP_PKIMESSAGE *msg,
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

/*
 * Attempt to validate certificate and path using given store of trusted certs
 * (possibly including CRLs and a cert verification callback function) and
 * non-trusted intermediate certs from the given ctx.
 * The defer_errors parameter needs to be set when used in a certConf callback
 * as any following certConf exchange will likely clear the OpenSSL error queue.
 * Returns 1 on successful validation and 0 otherwise.
 */
int CMP_validate_cert_path(const CMP_CTX *ctx, const X509_STORE *trusted_store,
                           const X509 *cert, int defer_errors)
{
    int valid = 0;
    X509_STORE_CTX *csc = NULL;

    if (ctx == NULL || trusted_store == NULL || cert == NULL) {
        CMPerr(CMP_F_CMP_VALIDATE_CERT_PATH, CMP_R_NULL_ARGUMENT);
        goto end;
    }

    if ((csc = X509_STORE_CTX_new()) == NULL ||
        !X509_STORE_CTX_init(csc, (X509_STORE *)trusted_store, (X509 *)cert,
                             (STACK_OF(X509) *)ctx->untrusted_certs)) {
        CMPerr(CMP_F_CMP_VALIDATE_CERT_PATH, CMP_R_OUT_OF_MEMORY);
        goto end;
    }

    valid = X509_verify_cert(csc) > 0;

    if (!valid && !defer_errors)
        put_cert_verify_err(CMP_F_CMP_VALIDATE_CERT_PATH);

 end:
    X509_STORE_CTX_free(csc);
    return valid;
}

/*
 * helper functions for improving certificate verification error diagnostics
 */

static void print_cert(BIO *bio, const X509 *cert, unsigned long neg_cflags) {
    if (cert) {
        unsigned long flags = ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_ESC_QUOTE |
            XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN;
        BIO_printf(bio, "    certificate\n");
        X509_print_ex(bio, (X509 *)cert, flags, ~X509_FLAG_NO_SUBJECT);
        if (X509_check_issued((X509 *)cert, (X509 *)cert) == X509_V_OK) {
            BIO_printf(bio, "        self-signed\n");
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
    if (certs && sk_X509_num(certs) > 0) {
        int i;
        for (i = 0; i < sk_X509_num(certs); i++) {
            X509 *cert = sk_X509_value(certs, i);
            if (cert) {
                print_cert(bio, cert, 0);
            }
        }
    } else {
        BIO_printf(bio, "    (no certificates)\n");
    }
}

static void print_store_certs(BIO *bio, X509_STORE *store) {
    if (store) {
        STACK_OF(X509) *certs = CMP_X509_STORE_get1_certs(store);
        print_certs(bio, certs);
        sk_X509_pop_free(certs, X509_free);
    } else {
        BIO_printf(bio, "    (no certificate store)\n");
    }
}

/* needed because cert verify errors are threatened by ERR_clear_error() */
static BIO *cert_verify_err_bio = NULL;

void put_cert_verify_err(int func)
{
    if (cert_verify_err_bio != NULL) { /* cert verify error in callback */
        char *str;
        long len = BIO_get_mem_data(cert_verify_err_bio, &str);
        CMPerr(func, CMP_R_INVALID_CERTIFICATE);
        if (len > 0) {
            str[len-1] = '\0'; /* replace last '\n', terminating str */
            CMP_add_error_line(str);
        }
        BIO_free(cert_verify_err_bio);
        cert_verify_err_bio = NULL;
    }
}

/*
 * This is a diagnostic function that may be registered using
 * X509_STORE_set_verify_cb(), such that it gets called by OpenSSL's
 * verify_cert() function at the end of a cert verification as an opportunity
 * to gather and output information regarding a (failing) cert verification,
 * and to possibly change the result of the verification (not done here).
 * returns 0 if and only if the cert verification is considered failed.
 */
int CMP_print_cert_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    if (ok == 0 && ctx != NULL) {
        int cert_error = X509_STORE_CTX_get_error(ctx);
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        X509 *cert = X509_STORE_CTX_get_current_cert(ctx);

        if (cert_verify_err_bio == NULL) {
            cert_verify_err_bio = BIO_new(BIO_s_mem()); /* may result in NULL */
        }
        BIO_printf(cert_verify_err_bio, "%s at depth=%d error=%d (%s)\n",
                   depth < 0 ? "signature verification" :
                   X509_STORE_CTX_get0_parent_ctx(ctx) ?
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
            BIO_printf(cert_verify_err_bio, "non-trusted store:\n");
            print_certs(cert_verify_err_bio, X509_STORE_CTX_get0_untrusted(ctx));
            BIO_printf(cert_verify_err_bio, "trust store:\n");
            print_store_certs(cert_verify_err_bio,
                              X509_STORE_CTX_get0_store(ctx));
        }
    }
# if 0
    /* TODO: we could check policies here too */
    if (cert_error == X509_V_OK && ok == 2)
        policies_print(NULL, ctx);
# endif

    return (ok);
}

/*
 * internal function
 *
 * Check if the given cert is acceptable as sender cert of the given message.
 * The subject DN must match, the subject key ID as well if present in the msg,
 * and the cert must not be expired (for checking this, the ts must be given).
 * returns 0 on error or not acceptable, else 1
 */
static int cert_acceptable(X509 *cert, const CMP_PKIMESSAGE *msg,
                           const X509_STORE *ts) {
    X509_NAME *sender_name = NULL;
    ASN1_OCTET_STRING *kid = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    time_t check_time, *ptime = NULL;

    vpm = ts ? X509_STORE_get0_param((X509_STORE *)ts) : NULL;
    if (cert == NULL || msg == NULL || ts == NULL || vpm == NULL)
        return 0; /* TODO better flag and handle this as fatal internal error */

    if (X509_VERIFY_PARAM_get_flags(vpm) & X509_V_FLAG_USE_CHECK_TIME) {
        check_time = X509_VERIFY_PARAM_get_time(vpm);
        ptime = &check_time;
    }
    if (!(X509_VERIFY_PARAM_get_flags(vpm) & X509_V_FLAG_NO_CHECK_TIME))
        if (X509_cmp_time(X509_get0_notAfter(cert), ptime) < 0) {
            CMP_add_error_data(" expired");
            return 0;
        }

    if ((sender_name = msg->header->sender->d.directoryName) != NULL) {
        X509_NAME *name = X509_get_subject_name(cert);

        /* enforce that the right subject DN is there */
        if (name == NULL) {
            CMP_add_error_data(" missing subject");
            return 0;
        }
        if (X509_NAME_cmp(name, sender_name) != 0) {
            CMP_add_error_data(" wrong subject");
            return 0;
        }
    }

    if ((kid = msg->header->senderKID) != NULL) {
        const ASN1_OCTET_STRING *ckid = X509_get0_subject_key_id(cert);

        /* enforce that the right subject key id is there */
        if (ckid == NULL) {
            CMP_add_error_data(" missing subject key ID");
            return 0;
        }
        if (ASN1_OCTET_STRING_cmp(ckid, kid) != 0) {
#if OPENSSL_VERSION_NUMBER >= 0x10100005L
            char *str;
#endif
            CMP_add_error_data(" wrong subject key");
#if OPENSSL_VERSION_NUMBER >= 0x10100005L
            str = OPENSSL_buf2hexstr(ckid->data, ckid->length);
            CMP_add_error_txt("\n    ID = ", str);
            OPENSSL_free(str);
            str = OPENSSL_buf2hexstr(kid->data, kid->length);
            CMP_add_error_txt("\n    vs.  ", str);
            OPENSSL_free(str);
#endif
            return 0;
        }
    }

    return 1; /* acceptable also if there is no identifier in msg header */
}

/*
 * internal function
 *
 * Find in the list of certs all acceptable certs (see cert_acceptable()).
 * Add them to sk (if not a duplicate to an existing one).
 * returns 0 on error else 1
 */
static int find_acceptable_certs(STACK_OF(X509) *certs,
    const CMP_PKIMESSAGE *msg, const X509_STORE *ts, STACK_OF(X509) *sk)
{
    int i;

    if (sk == NULL)
        return 0; /* maybe better flag and handle this as fatal error */

    for (i = 0; i < sk_X509_num(certs); i++) { /* certs may be NULL */
        X509 *cert = sk_X509_value(certs, i);
        char *str = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

        CMP_add_error_line("  considering cert with subject");
        CMP_add_error_txt(" = ", str);
        OPENSSL_free(str);

        if (!cert_acceptable(cert, msg, ts))
            continue;
        if (!CMP_sk_X509_add1_cert(sk, cert, 1/* no duplicates */))
            return 0;
    }

    return 1;
}

/*
 * internal function
 *
 * Find candidate server certificate(s) by using find_acceptable_certs()
 * looking for a non-expired cert with subject matching the msg sender name
 * and (if set in msg) a matching sender keyID = subject key ID.
 *
 * Considers given trusted store and any given untrusted certs, which should
 * include any extra certs from the received message msg.
 *
 * Returns exactly one if there is a single clear hit, else several candidates.
 * returns NULL on (out of memory) error
 */
static STACK_OF(X509) *find_server_cert(const X509_STORE *ts,
                    STACK_OF(X509) *untrusted, const CMP_PKIMESSAGE *msg)
{
    int ret;
    STACK_OF(X509) *trusted, *found_certs;

    if (ts == NULL || msg == NULL) /* untrusted may be NULL */
        return NULL; /* maybe better flag and handle this as fatal error */

    /* sk_TYPE_find to use compfunc X509_cmp, not ptr comparison */
    if ((found_certs = sk_X509_new_null()) == NULL)
        goto oom;

    trusted = CMP_X509_STORE_get1_certs(ts);
    ret = find_acceptable_certs(trusted, msg, ts, found_certs);
    sk_X509_pop_free(trusted, X509_free);
    if (!ret)
        goto oom;

    if (!find_acceptable_certs(untrusted, msg, ts, found_certs))
        goto oom;

    CMP_add_error_line(sk_X509_num(found_certs) ?
                       "found at least one matching server cert" :
                       "no matching server cert found");
    return found_certs;
oom:
    sk_X509_pop_free(found_certs, X509_free);
    return NULL;
}

/*
 * Exceptional handling for 3GPP TS 33.310, only to use for IP and if the ctx
 * option is explicitly set: use self-signed certificates from extraCerts as
 * trust anchor to validate server cert - provided it also can validate the
 * newly enrolled certificate
 */
static int srv_cert_valid_3gpp(CMP_CTX *ctx, const X509 *scrt,
                               const CMP_PKIMESSAGE *msg) {
    int valid = 0;
    X509_STORE *store = X509_STORE_new();
    if (store && /* store does not include CRLs */
        CMP_X509_STORE_add1_certs(store, msg->extraCerts, 1/* s-sgnd only */)) {
        valid = CMP_validate_cert_path(ctx, store, scrt, 0);
    }
    if (valid) {
        /*
         * verify that the newly enrolled certificate (which is assumed to have
         * rid == 0) can also be validated with the same trusted store
         */
        CMP_CERTRESPONSE *crep =
            CMP_CERTREPMESSAGE_certResponse_get0(msg->body->value.ip, 0);
        X509 *newcrt = CMP_CERTRESPONSE_get_certificate(ctx, crep); /* maybe
            better use get_cert_status() from cmp_ses.c, which catches errors */
        valid = CMP_validate_cert_path(ctx, store, newcrt, 0);
        X509_free(newcrt);
    }
    X509_STORE_free(store);
    return valid;
}

static X509 *find_srvcert(CMP_CTX *ctx, const CMP_PKIMESSAGE *msg)
{
    X509 *scrt = NULL;
    int valid = 0;
    GENERAL_NAME *sender = msg->header->sender;

    if (sender == NULL || msg->body == NULL)
        return 0; /* other NULL cases already have been checked */
    if (sender->type != GEN_DIRNAME) {
        CMPerr(CMP_F_FIND_SRVCERT,
               CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED);
        return NULL; /* FR#42: support for more than X509_NAME */
    }

    /*
     * valid scrt, matching sender name, found earlier in transaction, will be
     * used for validating any further msgs where extraCerts may be left out
     */
    if (ctx->validatedSrvCert &&
        cert_acceptable(ctx->validatedSrvCert, msg, ctx->trusted_store)) {
        scrt = ctx->validatedSrvCert;
        valid = 1;
    } else {
        STACK_OF(X509) *found_crts = NULL;
        int i;

        /* tentatively set error, which allows accumulating diagnostic info */
        char *sname = X509_NAME_oneline(sender->d.directoryName, NULL, 0);
        (void)ERR_set_mark();
        CMPerr(CMP_F_FIND_SRVCERT, CMP_R_NO_VALID_SERVER_CERT_FOUND);
        ERR_add_error_data(2, "\ntrying to match msg sender name = ", sname);
        OPENSSL_free(sname);

        /* release any cached cert, which is no more acceptable */
        if (ctx->validatedSrvCert)
            X509_free(ctx->validatedSrvCert);
        ctx->validatedSrvCert = NULL;

        /* use and store provided extraCerts in ctx also for future use */
        if (!CMP_sk_X509_add1_certs(ctx->untrusted_certs,
                        msg->extraCerts, 1/* no self-signed */, 1/* no dups */))
            return NULL;

        /* find server cert candidates from any available source */
        found_crts = find_server_cert(ctx->trusted_store, ctx->untrusted_certs,
                                      msg);

        /* select first server cert that can be validated */
        for (i = 0; !valid && i < sk_X509_num(found_crts); i++) {
            scrt = sk_X509_value(found_crts, i);
            valid = CMP_validate_cert_path(ctx, ctx->trusted_store, scrt, 0);
        }

        /* exceptional 3GPP TS 33.310 handling */
        if (!valid && ctx->permitTAInExtraCertsForIR &&
                CMP_PKIMESSAGE_get_bodytype(msg) == V_CMP_PKIBODY_IP) {
            for (i = 0; !valid && i < sk_X509_num(found_crts); i++) {
                scrt = sk_X509_value(found_crts, i);
                valid = srv_cert_valid_3gpp(ctx, scrt, msg);
            }
        }

        if (valid) {
            /* store trusted srv cert for future msgs of same transaction */
            X509_up_ref(scrt);
            ctx->validatedSrvCert = scrt;
            (void)ERR_pop_to_mark();
                        /* discard any diagnostic info on finding server cert */
        } else {
            scrt = NULL;
        }
        sk_X509_pop_free(found_crts, X509_free);
    }

    return scrt;
}

/*
 * Validates the protection of the given PKIMessage using either password-
 * based mac (PBM) or a signature algorithm. In the case of signature algorithm,
 * the certificate can be provided in ctx->srvCert,
 * else it is taken from extraCerts and validated against ctx->trusted_store
 * utilizing ctx->untrusted_certs and extraCerts.
 *
 * If ctx->permitTAInExtraCertsForIR is true, the trust anchor may be taken from
 * the extraCerts field when a self-signed certificate is found there which can
 * be used to validate the enrolled certificate returned in IP.
 *  This is according to the need given in 3GPP TS 33.310.
 *
 * returns 1 on success, 0 on error or validation failed
 */
int CMP_validate_msg(CMP_CTX *ctx, const CMP_PKIMESSAGE *msg)
{
    int nid = 0;
#if OPENSSL_VERSION_NUMBER >= 0x1010001fL
    const
#endif
    ASN1_OBJECT *algorOID = NULL;
    X509 *scrt = NULL;

    if (ctx == NULL || msg == NULL || msg->header == NULL ||
        msg->header->protectionAlg == NULL) /* unprotected message */
        return 0;

    /* determine the nid for the used protection algorithm */
    X509_ALGOR_get0(&algorOID, NULL, NULL, msg->header->protectionAlg);
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
            switch (CMP_PKIMESSAGE_get_bodytype(msg)) {
            case V_CMP_PKIBODY_IP:
            case V_CMP_PKIBODY_CP:
            case V_CMP_PKIBODY_KUP:
            case V_CMP_PKIBODY_CCP:
                if (!CMP_X509_STORE_add1_certs(ctx->trusted_store,
                        msg->body->value.ip->caPubs, /* same for cp, kup, ccp */
                                               0/* allow self-signed or not */))
                    return 0;
            }
            return 1;
        }
        return 0;

        /* TODO: 5.1.3.2.  DH Key Pairs --> feature request #33 */
    case NID_id_DHBasedMac:
        CMPerr(CMP_F_CMP_VALIDATE_MSG,
               CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC);
        break;

        /*
         * 5.1.3.3.  Signature */
        /* TODO: should that better white-list DSA/RSA etc.?
         * -> check all possible options from OpenSSL, should there be macro?
         */
    default:

        /* validate sender name of received msg */
        if (msg->header->sender->type != GEN_DIRNAME) {
            CMPerr(CMP_F_CMP_VALIDATE_MSG,
                   CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED);
            return 0; /* FR#42: support for more than X509_NAME */
        }
        /*
         * Compare actual sender name of response with expected sender name.
         * Mitigates risk to accept misused certificate of an unauthorized
         * entity of a trusted hierarchy.
         */
        if (ctx->expected_sender) {/* set explicitly or not NULL-DN recipient */
            X509_NAME *sender_name = msg->header->sender->d.directoryName;
            if (X509_NAME_cmp(sender_name, ctx->expected_sender) != 0) {
                char *expected = X509_NAME_oneline(ctx->expected_sender,NULL,0);
                char *actual   = X509_NAME_oneline(sender_name, NULL, 0);
                CMPerr(CMP_F_CMP_VALIDATE_MSG, CMP_R_UNEXPECTED_SENDER);
                ERR_add_error_data(4, "\n expected = ", expected,
                                  "\n   actual = ", actual ? actual : "(none)");
                OPENSSL_free(expected);
                OPENSSL_free(actual);
                return 0;
            }
        }/* Note: if recipient was NULL-DN it could be learned here if needed */

        if ((scrt = ctx->srvCert ? ctx->srvCert : find_srvcert(ctx, msg))) {
            if (CMP_verify_signature(ctx, msg, scrt))
                return 1;
            put_cert_verify_err(CMP_F_CMP_VALIDATE_MSG);
        }
    }
    return 0;
}
