/* vim: set cino={1s noet ts=4 sts=4 sw=4: */
/* crypto/crmf/crmf_pbm.c
 * CRMF (RFC 4211) "Password Based Mac" functions for OpenSSL
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
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include "crmf_int.h"

/* ############################################################################ *
 * creates and initializes CRMF_PBMPARAMETER (section 4.4)
 * slen SHOULD be > 8    (16 is common)
 * owfnid e.g. NID_sha256
 * itercnt MUST be > 100 (500 is common)
 * macnid e.g. NID_hmac_sha1
 * returns pointer to CRMF_PBMPARAMETER on success, NULL on error
 * ############################################################################ */
CRMF_PBMPARAMETER *CRMF_pbmp_new(size_t slen, int owfnid,
                                 long itercnt, int macnid)
{
    CRMF_PBMPARAMETER *pbm = NULL;
    unsigned char *salt = NULL;

    if (!(pbm = CRMF_PBMPARAMETER_new()))
        goto err;

    /* salt contains a randomly generated value used in computing the key
     * of the MAC process.  The salt SHOULD be at least 8 octets (64
     * bits) long.
     */
	if ((salt = OPENSSL_malloc(slen)) == NULL) {
		CRMFerr(CRMF_F_CRMF_PBMP_NEW, CRMF_R_MALLOC_FAILURE);
		goto err;
	}
    RAND_bytes(salt, slen);
    if (!(ASN1_OCTET_STRING_set(pbm->salt, salt, slen)))
        goto err;

    /* owf identifies the hash algorithm and associated parameters used to
     * compute the key used in the MAC process.  All implementations MUST
     * support SHA-1.
     */
	if (!X509_ALGOR_set0(pbm->owf, OBJ_nid2obj(owfnid), V_ASN1_UNDEF, NULL)) {
		CRMFerr(CRMF_F_CRMF_PBMP_NEW, CRMF_R_SETTING_OWF_ALRGOR_FAILUR);
		goto err;
	}

    /*
       iterationCount identifies the number of times the hash is applied
       during the key computation process.  The iterationCount MUST be a
       minimum of 100.      Many people suggest using values as high as 1000
       iterations as the minimum value.  The trade off here is between
       protection of the password from attacks and the time spent by the
       server processing all of the different iterations in deriving
       passwords.  Hashing is generally considered a cheap operation but
       this may not be true with all hash functions in the future.
     */
	if (itercnt < 100) {
		CRMFerr(CRMF_F_CRMF_PBMP_NEW, CRMF_R_ITERATIONCOUNT_BELOW_100);
		goto err;
	}

    if (!ASN1_INTEGER_set(pbm->iterationCount, itercnt))
		goto err;

    /* mac identifies the algorithm and associated parameters of the MAC
       function to be used.  All implementations MUST support HMAC-SHA1
       [HMAC].      All implementations SHOULD support DES-MAC and Triple-
       DES-MAC [PKCS11].
     */
    if (!X509_ALGOR_set0(pbm->mac, OBJ_nid2obj(NID_hmac_sha1), V_ASN1_UNDEF, NULL)) {
		CRMFerr(CRMF_F_CRMF_PBMP_NEW, CRMF_R_SETTING_MAC_ALRGOR_FAILUR);
		goto err;
	}

	OPENSSL_free(salt);
    return pbm;
 err:
    if (salt)
        OPENSSL_free(salt);
    if (pbm)
        CRMF_PBMPARAMETER_free(pbm);
    CRMFerr(CRMF_F_CRMF_PBMP_NEW, CRMF_R_CRMFERROR);
    return NULL;
}

/* ############################################################################
 * calculates the PBM based on the settings of the given CRMF_PBMPARAMETER
 * @pbm identifies the algorithms to use
 * @msg message to apply the PBM for
 * @msgLen length of the message
 * @secret key to use
 * @secretLen length of the key
 * @mac pointer to the computed mac, is allocated here, will be freed if not
 *              pointing to NULL
 * @macLen pointer to the length of the mac, will be set
 *
 * returns 1 at success, 0 at error
 * ############################################################################ */
int CRMF_passwordBasedMac_new(const CRMF_PBMPARAMETER *pbm,
                              const unsigned char *msg, size_t msgLen,
                              const unsigned char *secret, size_t secretLen,
                              unsigned char **mac, unsigned int *macLen)
{
    const EVP_MD *m = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char basekey[EVP_MAX_MD_SIZE];
    unsigned int basekeyLen;
    long iterations;

    if (!mac)
        goto err;
    if (*mac)
        OPENSSL_free(*mac);

    if (!pbm)
        goto err;
    if (!msg)
        goto err;
    if (!secret)
        goto err;

    if ((*mac = OPENSSL_malloc(EVP_MAX_MD_SIZE)) == NULL) {
		CRMFerr(CRMF_F_CRMF_PASSWORDBASEDMAC_NEW, CRMF_R_MALLOC_FAILURE);
		goto err;
	}
    if (!*mac)
        goto err;

    OpenSSL_add_all_digests();

    /*
     * owf identifies the hash algorithm and associated parameters used to
     * compute the key used in the MAC process.  All implementations MUST
     * support SHA-1.
     */
    if (!(m = EVP_get_digestbyobj(pbm->owf->algorithm)))
        goto err;

    ctx = EVP_MD_CTX_create();

    /* compute the basekey of the salted secret */
    if (!(EVP_DigestInit_ex(ctx, m, NULL)))
        goto err;
    /* first the secret */
    EVP_DigestUpdate(ctx, secret, secretLen);
    /* then the salt */
    EVP_DigestUpdate(ctx, pbm->salt->data, pbm->salt->length);
    if (!(EVP_DigestFinal_ex(ctx, basekey, &basekeyLen)))
        goto err;

    /* the first iteration is already done above -> -1 */
    iterations = ASN1_INTEGER_get(pbm->iterationCount) - 1;
    while (iterations-- > 0) {
        if (!(EVP_DigestInit_ex(ctx, m, NULL)))
            goto err;
        EVP_DigestUpdate(ctx, basekey, basekeyLen);
        if (!(EVP_DigestFinal_ex(ctx, basekey, &basekeyLen)))
            goto err;
    }

    /*
     * mac identifies the algorithm and associated parameters of the MAC
     * function to be used.  All implementations MUST support HMAC-SHA1
     * [HMAC].      All implementations SHOULD support DES-MAC and Triple-
     * DES-MAC [PKCS11].
     */
    switch (OBJ_obj2nid(pbm->mac->algorithm)) {
    case NID_hmac_sha1: /* explicitly mentioned in RFC 4210, D2 - and RFC 3370 */
    case NID_hmacWithSHA1: /* shouldn't be actively used; above OID is in 4210*/
        HMAC(EVP_sha1(), basekey, basekeyLen, msg, msgLen, *mac, macLen);
		break;
    case NID_hmacWithSHA224: /* RFC 4231 */
        HMAC(EVP_sha224(), basekey, basekeyLen, msg, msgLen, *mac, macLen);
		break;
    case NID_hmacWithSHA256:/* RFC 4231 */
        HMAC(EVP_sha256(), basekey, basekeyLen, msg, msgLen, *mac, macLen);
		break;
    case NID_hmacWithSHA384:/* RFC 4231 */
        HMAC(EVP_sha384(), basekey, basekeyLen, msg, msgLen, *mac, macLen);
		break;
    case NID_hmacWithSHA512:/* RFC 4231 */
        HMAC(EVP_sha512(), basekey, basekeyLen, msg, msgLen, *mac, macLen);
		break;
#ifndef OPENSSL_NO_MD5
    case NID_hmac_md5:
    case NID_hmacWithMD5:
        HMAC(EVP_md5(), basekey, basekeyLen, msg, msgLen, *mac, macLen);
        break;
#endif
    default:
        CRMFerr(CRMF_F_CRMF_PASSWORDBASEDMAC_NEW,
                CRMF_R_UNSUPPORTED_ALGORITHM);
        goto err;
    }

    /* cleanup */
    EVP_MD_CTX_destroy(ctx);

    return 1;
 err:
    if (mac && *mac) {
        OPENSSL_free(*mac);
    }
    CRMFerr(CRMF_F_CRMF_PASSWORDBASEDMAC_NEW, CRMF_R_CRMFERROR);
    return 0;
}
