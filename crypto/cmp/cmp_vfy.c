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

/* ########################################################################## *
 * internal function
 *
 * validate a message protected by signature according to section 5.1.3.3
 * (sha1+RSA/DSA or any other algorithm supported by OpenSSL)
 * returns 0 on error
 * ########################################################################## */
static int CMP_verify_signature(const CMP_CTX *cmp_ctx,
                                const CMP_PKIMESSAGE *msg, const X509 *cert)
{
    EVP_MD_CTX *ctx = NULL;
    CMP_PROTECTEDPART protPart;
    int ret = 0;
    int digest_NID;
    EVP_MD *digest = NULL;
    EVP_PKEY *pubkey = NULL;

    size_t protPartDerLen = 0;
    unsigned char *protPartDer = NULL;

    if (!msg || !cert)
        goto param_err;

    /* verify that keyUsage, if present, contains digitalSignature */
    if (!cmp_ctx->ignore_keyusage &&
        !(X509_get_key_usage((X509 *)cert) & X509v3_KU_DIGITAL_SIGNATURE)) {
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, CMP_R_WRONG_KEY_USAGE);
            goto cert_err;
    }

    pubkey = X509_get_pubkey((X509 *)cert);
    if (!pubkey) {
    param_err:
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, CMP_R_INVALID_KEY);
        return 0;
    }

    /* create the DER representation of protected part */
    protPart.header = msg->header;
    protPart.body = msg->body;
    protPartDerLen = i2d_CMP_PROTECTEDPART(&protPart, &protPartDer);

    /* verify protection of protected part */
    ctx = EVP_MD_CTX_create();
    if (!OBJ_find_sigid_algs(OBJ_obj2nid(msg->header->protectionAlg->algorithm),
                                         &digest_NID, NULL) ||
        !(digest = (EVP_MD *)EVP_get_digestbynid(digest_NID))) {
        CMPerr(CMP_F_CMP_VERIFY_SIGNATURE, CMP_R_ALGORITHM_NOT_SUPPORTED);
        return 0;
    }
    ret = EVP_VerifyInit_ex(ctx, digest, NULL) &&
          EVP_VerifyUpdate(ctx, protPartDer, protPartDerLen) &&
          EVP_VerifyFinal(ctx, msg->protection->data,
                          msg->protection->length, pubkey) == 1;

    /* cleanup */
    EVP_MD_CTX_destroy(ctx);
    OPENSSL_free(protPartDer);
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

/* ########################################################################## *
 * internal function
 *
 * Validates a message protected with PBMAC
 * ########################################################################## */
static int CMP_verify_MAC(const CMP_PKIMESSAGE *msg,
                          const ASN1_OCTET_STRING *secret)
{
    ASN1_BIT_STRING *protection = NULL;
    int valid = 0;

    /* generate expected protection for the message */
    if (!(protection = CMP_calc_protection_pbmac(msg, secret)))
        goto err;               /* failed to generate protection string! */

    valid = ASN1_STRING_cmp((const ASN1_STRING *)protection,
                            (const ASN1_STRING *)msg->protection) == 0;
    ASN1_BIT_STRING_free(protection);
    return valid;
 err:
    return 0;
}

/* ########################################################################## *
 * Attempt to validate certificate path. returns 1 if the path was
 * validated successfully and 0 if not.
 * ########################################################################## */
int CMP_validate_cert_path(CMP_CTX *ctx, X509_STORE *trusted_store,
                       const STACK_OF (X509) *untrusted_certs, const X509 *cert)
{
    int valid = 0;
    X509_STORE_CTX *csc = NULL;

    if (!cert)
        goto end;

    if (!trusted_store) {
        CMPerr(CMP_F_CMP_VALIDATE_CERT_PATH,
               CMP_R_NO_TRUSTED_CERTIFICATES_SET);
        goto end;
    }

    if (!(csc = X509_STORE_CTX_new()))
        goto end;

    if (!X509_STORE_CTX_init(csc, trusted_store, (X509 *)cert,
                             (STACK_OF (X509) *)untrusted_certs))
        goto end;

    valid = X509_verify_cert(csc);

    X509_STORE_CTX_free(csc);

 end:
    if (valid > 0)
        return 1;

    return 0;
}

#if 0
/* ########################################################################## *
 * NOTE: This is only needed if/when we want to do additional checking on the
 *       certificates!
 *
 *               It is not currently used.
 *
 * This is called for every valid certificate. Here we could add additional
 * checks, for policies for example.
 * ########################################################################## */
int CMP_cert_callback(int ok, X509_STORE_CTX *ctx)
{
    int cert_error = X509_STORE_CTX_get_error(ctx);
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);

    if (!ok) {
        switch (cert_error) {
        case X509_V_ERR_NO_EXPLICIT_POLICY:
            /* policies_print(NULL, ctx); */
        case X509_V_ERR_CERT_HAS_EXPIRED:

            /* since we are just checking the certificates, it is
             * ok if they are self signed. But we should still warn
             * the user.
             */

        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            /* Continue after extension errors too */
        case X509_V_ERR_INVALID_CA:
        case X509_V_ERR_INVALID_NON_CA:
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        case X509_V_ERR_INVALID_PURPOSE:
        case X509_V_ERR_CRL_HAS_EXPIRED:
        case X509_V_ERR_CRL_NOT_YET_VALID:
        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
            ok = 1;

        }

        return ok;
    }
# if 0
    /* TODO: we could check policies here too */
    if (cert_error == X509_V_OK && ok == 2)
        policies_print(NULL, ctx);
# endif

    return (ok);
}
#endif

/* ########################################################################## *
 * internal function
 *
 * Check if the given cert is acceptable as sender cert of the given message.
 * The subject DN must match, the subject key ID as well if present in the msg,
 * and the cert must not be expired (for checking this, the ts must be given).
 * returns 0 on error or not acceptable, else 1
 * ########################################################################## */
static int cert_acceptable(X509 *cert, const CMP_PKIMESSAGE *msg,
                           const X509_STORE *ts) {
    X509_NAME *name = NULL;
    X509_NAME *sender_name = NULL;
    ASN1_OCTET_STRING *kid = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    time_t check_time, *ptime = NULL;

    if (!cert || !msg || !ts)
        return 0; /* maybe better flag and handle this as fatal error */

    vpm = X509_STORE_get0_param((X509_STORE *)ts);
    sender_name = msg->header->sender->d.directoryName;
    kid = msg->header->senderKID;
    if (!sender_name || !vpm) /* keyid is allowed to be NULL */
        return 0; /* maybe better flag and handle this as fatal error */

    if (X509_VERIFY_PARAM_get_flags(vpm) & X509_V_FLAG_USE_CHECK_TIME) {
        check_time = X509_VERIFY_PARAM_get_time(vpm);
        ptime = &check_time;
    }
    if (!(X509_VERIFY_PARAM_get_flags(vpm) & X509_V_FLAG_NO_CHECK_TIME))
        if (X509_cmp_time(X509_get0_notAfter(cert), ptime) < 0)
            return 0; /* expired */

    name = X509_get_subject_name(cert);
    if (!name || X509_NAME_cmp(name, sender_name) != 0)
        return 0; /* missing or wrong subject */
    if (kid) {/* enforce that the right subject key id is there */
        ASN1_OCTET_STRING *ckid = CMP_get_cert_subject_key_id(cert);
        if (!ckid || ASN1_OCTET_STRING_cmp(ckid, kid) != 0)
            return 0; /* missing or wrong kid */
        }
    return 1;
}

/* ########################################################################## *
 * internal function
 *
 * Find in the list of certificates all acceptable certs (see cert_acceptable()).
 * Add them to sk (if not a duplicate to an existing one).
 * returns 0 on error else 1
 * ########################################################################## */
static int find_acceptable_certs(STACK_OF (X509) *certs,
    const CMP_PKIMESSAGE *msg, const X509_STORE *ts, STACK_OF (X509) *sk)
{
    int i;

    if (!sk)
        return 0; /* maybe better flag and handle this as fatal error */

    for (i = 0; i < sk_X509_num(certs); i++) { /* certs may be NULL */
        X509 *cert = sk_X509_value(certs, i);

        if (!cert_acceptable(cert, msg, ts))
            continue;
        if (!CMP_sk_X509_add1_cert(sk, cert, 1/* no duplicates */))
            return 0;
    }

    return 1;
}

/* ########################################################################## *
 * internal function
 *
 * Find one or more server certificates by using find_acceptable_certs()
 * looking for a non-expired cert with subject matching the msg sender name
 * and (if set in msg) a matching sender keyID = subject key ID.
 *
 * Considers given trusted store and any given untrusted certs, which should
 * include any extra certs from the received message msg.
 *
 * Returns exactly one if there is a single clear hit, else several candidates.
 * returns NULL on (out of memory) error
 * ########################################################################## */
static STACK_OF(X509) *find_server_cert(const X509_STORE *ts,
                    STACK_OF (X509) *untrusted, const CMP_PKIMESSAGE *msg)
{
    int ret;
    STACK_OF (X509) *trusted, *found_certs;

    if (!ts || !msg) /* untrusted may be NULL */
        return NULL; /* maybe better flag and handle this as fatal error */

    /* sk_TYPE_find to use compfunc X509_cmp, not ptr comparison */
    if (!(found_certs = sk_X509_new_null()))
        goto oom;

    trusted = CMP_X509_STORE_get1_certs(ts);
    ret = find_acceptable_certs(trusted, msg, ts, found_certs);
    sk_X509_pop_free(trusted, X509_free);
    if (!ret)
        goto oom;

    if (!find_acceptable_certs(untrusted, msg, ts, found_certs))
        goto oom;

    return found_certs;
oom:
    sk_X509_pop_free(found_certs, X509_free);
    return NULL;
}

/* ##########################################################################
 * Validates the protection of the given PKIMessage using either password-
 * based mac or a signature algorithm. In the case of signature algorithm,
 * the certificate can be provided in ctx->srvCert,
 * else it is taken from extraCerts and validated against ctx->trusted_store
 * utilizing ctx->untrusted_certs and extraCerts.
 *
 * If ctx->permitTAInExtraCertsForIR is true, the trust anchor may be taken from
 * the extraCerts field when a self-signed certificate is found there which can
 * be used to validate the enrolled certificate returned in IP.  This is according
 * to the need given in 3GPP TS 33.310.
 *
 * returns 1 on success, 0 on error or validation failed
 * ########################################################################## */
int CMP_validate_msg(CMP_CTX *ctx, const CMP_PKIMESSAGE *msg)
{
    X509 *srvCert = ctx->srvCert;
    int srvCert_valid = 0;
    int nid = 0;
#if OPENSSL_VERSION_NUMBER >= 0x1010001fL
    const
#endif
    ASN1_OBJECT *algorOID = NULL;

    if (!msg->header->protectionAlg)
        /* unprotected message */
        return 0;

    /* determine the nid for the used protection algorithm */
    X509_ALGOR_get0(&algorOID, NULL, NULL, msg->header->protectionAlg);
    nid = OBJ_obj2nid(algorOID);

    switch (nid) {
        /* 5.1.3.1.  Shared Secret Information */
    case NID_id_PasswordBasedMAC:
        return CMP_verify_MAC(msg, ctx->secretValue);

        /* TODO: 5.1.3.2.  DH Key Pairs --> feature request #33 */
    case NID_id_DHBasedMac:
        CMPerr(CMP_F_CMP_VALIDATE_MSG,
               CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC);
        break;

        /* 5.1.3.3.  Signature */
        /* TODO: should that better whitelist DSA/RSA etc.?
         * -> check all possible options from OpenSSL, should there be macro? */
    default:
        if (!srvCert) {
            STACK_OF (X509) *found_certs = NULL;
            /* if we've already found and validated a server cert, and it
             * matches the sender name, we will use that, this is used for
             * PKIconf where the server certificate and others could be missing
             * from the extraCerts */
            if (ctx->validatedSrvCert &&
                cert_acceptable(ctx->validatedSrvCert, msg, ctx->trusted_store)) {
                srvCert = ctx->validatedSrvCert;
                srvCert_valid = 1;
            } else {
                STACK_OF (X509) *untrusted = sk_X509_new_null();
                if (untrusted &&
                    CMP_sk_X509_add1_certs(untrusted,ctx->untrusted_certs,0,1)&&
                /* Load provided extraCerts to help with cert path validation.
                   Note that the extraCerts are not protected and may be bad
                   (and even if they were in the protected part
                    the protection is not yet verified). */
                    CMP_sk_X509_add1_certs(untrusted, msg->extraCerts, 0, 1)) {
                    int i;

                    /* try to find server certificate(s) from
                     * trusted_store, untrusted_certs, or extaCerts */
                    found_certs =
                        find_server_cert(ctx->trusted_store, untrusted, msg);

                    /* select first server certificate that can be validated */
                    for (i = 0;
                         !srvCert_valid && i < sk_X509_num(found_certs); i++) {
                        ERR_clear_error(); /* TODO: still the cert verification
                                 callback function may print extra errors */
                        srvCert = sk_X509_value(found_certs, i);
                        srvCert_valid = CMP_validate_cert_path(ctx,
                                        ctx->trusted_store, untrusted, srvCert);
                    }
                }

                if (!srvCert_valid) {
                    /* do an exceptional handling for 3GPP for IP:
                     * when the ctx option is explicitly set, extract the Trust
                     * Anchor from ExtraCerts, provided that there is a
                     * self-signed certificate which can be used to validate
                     * the enrolled certificate - refer to 3GPP TS 33.310 */
                    if (ctx->permitTAInExtraCertsForIR &&
                            CMP_PKIMESSAGE_get_bodytype(msg) == V_CMP_PKIBODY_IP) {
                        X509_STORE *tempStore = X509_STORE_new();
                        if (tempStore && /* tempStore does not include CRLs */
                            CMP_X509_STORE_add1_certs(tempStore,msg->extraCerts,
                                                 1 /* only self_signed */)) {
                            srvCert_valid = CMP_validate_cert_path(ctx, tempStore,
                                                                   ctx->untrusted_certs,
                                                                   srvCert);
                        }
                        if (srvCert_valid) {
                            /* verify that our received certificate can also be
                             * validated with the same trusted store as srvCert */
                            CMP_CERTRESPONSE *crep = CMP_CERTREPMESSAGE_certResponse_get0(msg->body->value.ip, 0);
                            X509 *newClCert = CMP_CERTRESPONSE_get_certificate(ctx, crep);
                            if (newClCert) {
                                srvCert_valid =
                                    CMP_validate_cert_path(ctx, tempStore, ctx->untrusted_certs, newClCert);
                                X509_free(newClCert);
                            }
                        }

                        X509_STORE_free(tempStore);
                    }
                }
            }

            if (srvCert_valid) {
                X509_up_ref(srvCert);
            }
            sk_X509_pop_free(found_certs, X509_free);

            /* verification failed if no valid server cert was found */
            if (!srvCert_valid) {
                char *sender_name = X509_NAME_oneline(
                                 msg->header->sender->d.directoryName, NULL, 0);
                X509_free(srvCert);
                CMPerr(CMP_F_CMP_VALIDATE_MSG, CMP_R_NO_VALID_SRVCERT_FOUND);
                ERR_add_error_data(2, "sender name = ", sender_name);
                free(sender_name);
                return 0;
            }

            /* store trusted srv cert for future messages in this transaction */
            X509_free(ctx->validatedSrvCert);
            ctx->validatedSrvCert = srvCert;
        }
        return CMP_verify_signature(ctx, msg, srvCert);
    }
    return 0;
}
