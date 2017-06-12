/* vim: set cino={1s noet ts=4 sts=4 sw=4: */
/* crypto/crmf/crmf_lib.c
 * CRMF (RFC 4211) library functions for OpenSSL
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
/* NAMING
 * The 0 version uses the supplied structure pointer directly in the parent and 
 * it will be freed up when the parent is freed. In the above example crl would 
 * be freed but rev would not.
 *
 * The 1 function uses a copy of the supplied structure pointer (or in some 
 * cases increases its link count) in the parent and so both (x and obj above) 
 * should be freed up. 
 */
/* ############################################################################ *
 * In this file are the functions which set the individual items inside                 *
 * the CRMF structures                                                                                                                  *
 * ############################################################################ */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crmf_int.h"

/* ############################################################################ *
 * Pushes the given control attribute into the controls stack of a CertRequest
 * (section 6)
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_push0_control(CRMF_CERTREQMSG *certReqMsg,
                                  CRMF_ATTRIBUTETYPEANDVALUE *control)
{
    int newControls = 0;

    if (!certReqMsg)
        goto err;
    if (!control)
        goto err;

    if (!(certReqMsg->certReq->controls)) {
        /* as it is OPTIONAL it might not yet be initialized */
        if (!
            (certReqMsg->certReq->controls =
             sk_CRMF_ATTRIBUTETYPEANDVALUE_new_null()))
            goto err;
        newControls = 1;        /* for potential cleanup in error case */
    }
    if (!sk_CRMF_ATTRIBUTETYPEANDVALUE_push
        (certReqMsg->certReq->controls, control))
        goto err;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_PUSH0_CONTROL, CRMF_R_CRMFERROR);

    if (newControls) {
        sk_CRMF_ATTRIBUTETYPEANDVALUE_pop_free(certReqMsg->certReq->controls,
                                               CRMF_ATTRIBUTETYPEANDVALUE_free);
        certReqMsg->certReq->controls = NULL;
    }
    return 0;
}

/* ############################################################################ *
 * sets the id-regCtrl-regToken Control (section 6.1)
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_control_regToken(CRMF_CERTREQMSG *msg,
                                          ASN1_UTF8STRING *tok)
{
    CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;

    if (!msg)
        goto err;
    if (!tok)
        goto err;

    if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new()))
        goto err;

    atav->type = OBJ_nid2obj(NID_id_regCtrl_regToken);
    if (!(atav->value.regToken = ASN1_STRING_dup(tok)))
        goto err;

    if (!CRMF_CERTREQMSG_push0_control(msg, atav))
        goto err;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_REGTOKEN,
            CRMF_R_ERROR_SETTING_REGTOKEN_ATAV);
    if (atav)
        CRMF_ATTRIBUTETYPEANDVALUE_free(atav);
    return 0;
}

/* ############################################################################ *
 * sets the id-regCtrl-authenticator Control (section 6.2)
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_control_authenticator(CRMF_CERTREQMSG *msg,
                                               ASN1_UTF8STRING *auth)
{
    CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;

    if (!msg)
        goto err;
    if (!auth)
        goto err;

    if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new()))
        goto err;

    atav->type = OBJ_nid2obj(NID_id_regCtrl_authenticator);
    if (!(atav->value.regToken = ASN1_STRING_dup(auth)))
        goto err;
    if (!CRMF_CERTREQMSG_push0_control(msg, atav))
        goto err;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_AUTHENTICATOR,
            CRMF_R_ERROR_SETTING_CONTROL_AUTHENTICATOR_ATAV);
    if (atav)
        CRMF_ATTRIBUTETYPEANDVALUE_free(atav);
    return 0;
}

/* ############################################################################ *
 * sets the id-regCtrl-pkiPublicationInfo Control (section 6.3)
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_control_pkiPublicationInfo(CRMF_CERTREQMSG *msg,
                                                    CRMF_PKIPUBLICATIONINFO
                                                    *pubinfo)
{
    CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;

    if (!msg)
        goto err;
    if (!pubinfo)
        goto err;

    if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new()))
        goto err;

    atav->type = OBJ_nid2obj(NID_id_regCtrl_pkiPublicationInfo);
    if (!
        (atav->value.pkiPublicationInfo =
         CRMF_PKIPUBLICATIONINFO_dup(pubinfo)))
        goto err;
    if (!CRMF_CERTREQMSG_push0_control(msg, atav))
        goto err;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_PKIPUBLICATIONINFO,
            CRMF_R_ERROR_SETTING_CONTROL_PKIPUBLICATIONINFO_ATAV);
    if (atav)
        CRMF_ATTRIBUTETYPEANDVALUE_free(atav);
    return 0;
}

/* ############################################################################
 * sets the id-regCtrl-pkiArchiveOptions Control (section 6.4)
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_control_pkiArchiveOptions(CRMF_CERTREQMSG *msg,
                                                   CRMF_PKIARCHIVEOPTIONS
                                                   *archopts)
{
    CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;

    if (!msg)
        goto err;
    if (!archopts)
        goto err;

    if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new()))
        goto err;

    atav->type = OBJ_nid2obj(NID_id_regCtrl_pkiArchiveOptions);
    if (!(atav->value.pkiArchiveOptions =
          CRMF_PKIARCHIVEOPTIONS_dup(archopts)))
        goto err;
    if (!CRMF_CERTREQMSG_push0_control(msg, atav))
        goto err;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_PKIARCHIVEOPTIONS,
            CRMF_R_ERROR_SETTING_CONTROL_PKIARCHIVEOPTIONS_ATAV);
    if (atav)
        CRMF_ATTRIBUTETYPEANDVALUE_free(atav);
    return 0;
}

/* ############################################################################ *
 * sets the id-regCtrl-oldCertID Control (section 6.5) from the given
 * certificate
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_control_oldCertId(CRMF_CERTREQMSG *certReqMsg,
                                           X509 *oldCert)
{
    CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;
    CRMF_CERTID *certId = NULL;

    if (!certReqMsg)
        goto err;
    if (!oldCert)
        goto err;

    if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())
        || !(certId = CRMF_CERTID_new()))
        goto err;

    X509_NAME_set(&certId->issuer->d.directoryName, X509_get_issuer_name(oldCert));
    certId->issuer->type = GEN_DIRNAME;

    if (!ASN1_INTEGER_set(certId->serialNumber,
          ASN1_INTEGER_get(X509_get_serialNumber(oldCert))))
        goto err;

    atav->type = OBJ_nid2obj(NID_id_regCtrl_oldCertID);
    atav->value.oldCertId = certId;

    if (!CRMF_CERTREQMSG_push0_control(certReqMsg, atav))
        goto err;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_OLDCERTID,
            CRMF_R_ERROR_SETTING_CONTROL_OLDCERTID_ATAV);
    if (certId) {
        certId->issuer = NULL;
        CRMF_CERTID_free(certId);
    }
    if (atav)
        CRMF_ATTRIBUTETYPEANDVALUE_free(atav);
    return 0;
}

/* ############################################################################ *
 * For some reason X509_PUBKEY_dup() does not appear to be implemented by 
 * OpenSSL's X509 code, so we implement it here. It's only needed in the following
 * function so it can be declared static. *
 * TODO: check whether that should go elsewhere *
 * ############################################################################ */
static IMPLEMENT_ASN1_DUP_FUNCTION(X509_PUBKEY)

/* ############################################################################ *
 * sets the id-regCtrl-protocolEncrKey Control (section 6.6) from the given
 * public key
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_control_protocolEncrKey(CRMF_CERTREQMSG *msg,
                                                 X509_PUBKEY *pubkey)
{
    CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;

    if (!msg)
        goto err;
    if (!pubkey)
        goto err;

    if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new()))
        goto err;

    atav->type = OBJ_nid2obj(NID_id_regCtrl_protocolEncrKey);
    if (!(atav->value.protocolEncrKey = X509_PUBKEY_dup(pubkey)))
        goto err;
    if (!CRMF_CERTREQMSG_push0_control(msg, atav))
        goto err;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_CONTROL_PROTOCOLENCRKEY,
            CRMF_R_ERROR_SETTING_CONTROL_PROTOCOLENCRKEY_ATAV);
    if (atav)
        CRMF_ATTRIBUTETYPEANDVALUE_free(atav);
    return 0;
}

/* ############################################################################ *
 * Pushes the attribute given in regInfo in to the CertReqMsg->regInfo stack.
 * (section 7)
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_push0_regInfo(CRMF_CERTREQMSG *certReqMsg,
                                  CRMF_ATTRIBUTETYPEANDVALUE *regInfo)
{
    int newRegInfo = 0;

    if (!certReqMsg)
        goto err;
    if (!regInfo)
        goto err;

    if (!(certReqMsg->regInfo)) {
        /* as it is OPTIONAL it might not yet be initialized */
        if (!(certReqMsg->regInfo = sk_CRMF_ATTRIBUTETYPEANDVALUE_new_null()))
            goto err;
        newRegInfo = 1;
    }
    if (!sk_CRMF_ATTRIBUTETYPEANDVALUE_push(certReqMsg->regInfo, regInfo))
        goto err;
    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_PUSH0_REGINFO, CRMF_R_CRMFERROR);

    if (newRegInfo) {
        sk_CRMF_ATTRIBUTETYPEANDVALUE_pop_free(certReqMsg->regInfo,
                                               CRMF_ATTRIBUTETYPEANDVALUE_free);
        certReqMsg->regInfo = NULL;
    }
    return 0;
}

/* ############################################################################ *
 * sets the id-regInfo-utf8Pairs to regInfo (section 7.1) from a given
 * UTF8string
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_regInfo_utf8Pairs(CRMF_CERTREQMSG *msg,
                                           ASN1_UTF8STRING *utf8pairs)
{
    CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;

    if (!msg)
        goto err;
    if (!utf8pairs)
        goto err;

    if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new()))
        goto err;

    atav->type = OBJ_nid2obj(NID_id_regInfo_utf8Pairs);
    if (!(atav->value.utf8pairs = ASN1_STRING_dup(utf8pairs)))
        goto err;

    if (!CRMF_CERTREQMSG_push0_regInfo(msg, atav))
        goto err;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_REGINFO_UTF8PAIRS,
            CRMF_R_ERROR_SETTING_REGINFO_UTF8PAIRS_ATAV);
    if (atav)
        CRMF_ATTRIBUTETYPEANDVALUE_free(atav);
    return 0;
}

/* ############################################################################ *
 * sets the id-regInfo-certReq to regInfo (section 7.2) from a given certificate
 * request
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_regInfo_certReq(CRMF_CERTREQMSG *msg,
                                         CRMF_CERTREQUEST *certReq)
{
    CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;

    if (!msg)
        goto err;
    if (!certReq)
        goto err;

    if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new()))
        goto err;

    atav->type = OBJ_nid2obj(NID_id_regInfo_certReq);
    if (!(atav->value.certReq = CRMF_CERTREQUEST_dup(certReq)))
        goto err;

    if (!CRMF_CERTREQMSG_push0_regInfo(msg, atav))
        goto err;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_REGINFO_CERTREQ,
            CRMF_R_ERROR_SETTING_REGINFO_CERTREQ_ATAV);
    if (atav)
        CRMF_ATTRIBUTETYPEANDVALUE_free(atav);
    return 0;
}

/* ############################################################################ *
 * sets the id-regCtrl-regToken to regInfo (not described in RFC)
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_regInfo_regToken(CRMF_CERTREQMSG *msg,
                                          ASN1_UTF8STRING *tok)
{
    CRMF_ATTRIBUTETYPEANDVALUE *atav = NULL;

    if (!msg)
        goto err;
    if (!tok)
        goto err;

    if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new()))
        goto err;

    atav->type = OBJ_nid2obj(NID_id_regCtrl_regToken);
    if (!(atav->value.regToken = ASN1_STRING_dup(tok)))
        goto err;

    if (!CRMF_CERTREQMSG_push0_regInfo(msg, atav))
        goto err;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_REGINFO_REGTOKEN,
            CRMF_R_ERROR_SETTING_REGTOKEN_CERTREQ_ATAV);
    if (atav)
        CRMF_ATTRIBUTETYPEANDVALUE_free(atav);
    return 0;
}

/* ############################################################################ *
 * sets version to 2 in cert Template (section 5)
 *       version MUST be 2 if supplied.  It SHOULD be omitted.
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set_version2(CRMF_CERTREQMSG *certReqMsg)
{
    if (!certReqMsg)
        goto err;

    if (!certReqMsg->certReq->certTemplate->version)
        /* as it is OPTIONAL it might not yet be initialized */
        certReqMsg->certReq->certTemplate->version = ASN1_INTEGER_new();
    ASN1_INTEGER_set(certReqMsg->certReq->certTemplate->version, 2L);
    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET_VERSION2,
            CRMF_R_ERROR_SETTING_VERSION_2);
    return 0;
}

/* ############################################################################ *
 * sets notBefore and/or notAfter in certTemplate of the given certreqmsg
 * (section 5) - if they are not given as 0
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set_validity(CRMF_CERTREQMSG *certReqMsg,
                                 time_t notBefore, time_t notAfter)
{
    CRMF_OPTIONALVALIDITY *validity = NULL;
    ASN1_TIME *notBeforeAsn = NULL;
    ASN1_TIME *notAfterAsn = NULL;

    if (!certReqMsg)
        goto err;

    if (notBefore) {
        if (!(notBeforeAsn = ASN1_TIME_set(NULL, notBefore)))
            goto err;
    }
    if (notAfter) {
        if (!(notAfterAsn = ASN1_TIME_set(NULL, notAfter)))
            goto err;
    }
    if (!(validity = CRMF_OPTIONALVALIDITY_new()))
        goto err;

    validity->notBefore = notBeforeAsn;
    validity->notAfter = notAfterAsn;

    certReqMsg->certReq->certTemplate->validity = validity;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET_VALIDITY, CRMF_R_CRMFERROR);
    if (notBeforeAsn)
        ASN1_TIME_free(notBeforeAsn);
    if (notAfterAsn)
        ASN1_TIME_free(notAfterAsn);
    return 0;
}

/* ############################################################################ *
 * set the certReqId (section 5)
 *        certReqId contains an integer value that is used by the
 *        certificate requestor to associate a specific certificate request
 *        with a certificate response.
 * returns 0 on error, 1 on success
 * ############################################################################ */
int CRMF_CERTREQMSG_set_certReqId(CRMF_CERTREQMSG *certReqMsg,
                                  const long certReqId)
{
    if (!certReqMsg)
        goto err;
    if (!certReqMsg->certReq)
        goto err;

    return ASN1_INTEGER_set(certReqMsg->certReq->certReqId, certReqId);
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET_CERTREQID, CRMF_R_CRMFERROR);
    return 0;
}

/* ############################################################################ *
 * set the public Key to the certTemplate (chapgter 5)
 *        publicKey contains the public key for which the certificate is
 *        being created.  This field MUST be filled in if the requestor
 *        generates its own key.  The field is omitted if the key is
 *        generated by the RA/CA.
 * returns 0 on error, 1 on success
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_publicKey(CRMF_CERTREQMSG *certReqMsg,
                                   const EVP_PKEY *pkey)
{
    if (!certReqMsg)
        goto err;
    if (!pkey)
        goto err;

    /* this function is not consuming the pointer */
    return X509_PUBKEY_set(&(certReqMsg->certReq->certTemplate->publicKey),
                           (EVP_PKEY *)pkey);
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_PUBLICKEY, CRMF_R_CRMFERROR);
    return 0;
}

/* ############################################################################ *
 * Set the subject name in the given certificate template (section 5)
 *        subject is filled in with the suggested name for the requestor.
 *        This would normally be filled in by a name that has been
 *        previously issued to the requestor by the CA.
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_subject(CRMF_CERTREQMSG *certReqMsg,
                                 const X509_NAME *subject)
{
    if (!certReqMsg)
        goto err;
    if (!subject)
        goto err;

    /* this function is *not* consuming the pointer */
    return X509_NAME_set(&(certReqMsg->certReq->certTemplate->subject),
                         (X509_NAME *)subject);
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_SUBJECT, CRMF_R_CRMFERROR);
    return 0;
}

/* ############################################################################ *
 * Set the suggested issuer name in the given certificate template (section 5)
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_issuer( CRMF_CERTREQMSG *certReqMsg, const X509_NAME *issuer)
{
    if (!certReqMsg || !issuer) goto err;

    /* this function is *not* consuming the pointer */
    return X509_NAME_set(&(certReqMsg->certReq->certTemplate->issuer), (X509_NAME*) issuer);
err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_ISSUER, CRMF_R_CRMFERROR);
    return 0;
}

/* ############################################################################ *
 * push an extension to the extension stack (section 5)
 *        extensions contains extensions that the requestor wants to have
 *        placed in the certificate.  These extensions would generally deal
 *        with things such as setting the key usage to keyEncipherment.
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_push0_extension(CRMF_CERTREQMSG *certReqMsg,
                                    const X509_EXTENSION *ext)
{
    int createdStack = 0;

    if (!certReqMsg)
        goto err;
    if (!ext)
        goto err;

    if (!certReqMsg->certReq->certTemplate->extensions) {
        if (!(certReqMsg->certReq->certTemplate->extensions =
             sk_X509_EXTENSION_new_null()))
            goto err;
        createdStack = 1;
    }

    if (!sk_X509_EXTENSION_push(certReqMsg->certReq->certTemplate->extensions,
                                (X509_EXTENSION *)ext))
        goto err;
    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_PUSH0_EXTENSION, CRMF_R_CRMFERROR);

    if (createdStack) {
        sk_X509_EXTENSION_pop_free(certReqMsg->certReq->
                                   certTemplate->extensions,
                                   X509_EXTENSION_free);
        certReqMsg->certReq->certTemplate->extensions = NULL;
    }
    return 0;
}

/* ############################################################################ *
 * Create proof-of-posession information by signing the certrequest with our 
 * private key (section 4.1 of RFC 4211). Algorithm according to key type.
 *
 * TODO:
 * This function does not yet work for cases other than the one listed in case 3
 * of section 4.1.      For this it needs to put subject name and public key into
 * the POPOSigningKey:
 *
   3.  The certificate subject places its name in the Certificate
           Template structure along with the public key.  In this case the
           poposkInput field is omitted from the POPOSigningKey structure.
           The signature field is computed over the DER-encoded certificate
           template structure.
 *
 * returns a pointer to the created CRMF_POPOSIGNINGKEY on success, NULL on
 * error
 * ############################################################################ */
CRMF_POPOSIGNINGKEY *CRMF_poposigningkey_new(CRMF_CERTREQUEST *certReq,
                                             const EVP_PKEY *pkey,
                                             int digest)
{
    CRMF_POPOSIGNINGKEY *poposig = NULL;
    size_t certReqSize, maxSignatureSize;
    unsigned int sigLen;
    unsigned char *certReqDer = NULL;
    unsigned char *signature = NULL;
    int algNID=0;
    int md_NID=0;
    const EVP_MD *alg = NULL;

    EVP_MD_CTX *ctx = NULL;

    /* NOTE: PoposkInput is not handled here. */
    if (!(poposig = CRMF_POPOSIGNINGKEY_new()))
        goto err;

    /* OpenSSL defaults all bitstrings to be encoded as ASN.1 NamedBitList */
    poposig->signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    poposig->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    /* get DER representation */
    certReqSize = i2d_CRMF_CERTREQUEST(certReq, &certReqDer);

    maxSignatureSize = EVP_PKEY_size((EVP_PKEY *)pkey);
    signature = OPENSSL_malloc(maxSignatureSize);
    if (!signature)
        goto err;

    /* set the type of the algorithm */
    if (!OBJ_find_sigid_by_algs(&algNID, digest, EVP_PKEY_id(pkey))) {
        CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_NEW, CRMF_R_UNSUPPORTED_ALG_FOR_POPSIGNINGKEY);
        goto err;
    }
    if (!(OBJ_find_sigid_algs(algNID, &md_NID, NULL) && (alg = EVP_get_digestbynid(md_NID)))) {
        CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_NEW, CRMF_R_UNSUPPORTED_ALG_FOR_POPSIGNINGKEY);
        goto err;
    }
    X509_ALGOR_set0(poposig->algorithmIdentifier, OBJ_nid2obj(algNID), V_ASN1_NULL, NULL);

    ctx = EVP_MD_CTX_create();
    if (!(EVP_SignInit_ex(ctx, alg, NULL)))
        goto err;
    if (!(EVP_SignUpdate(ctx, certReqDer, certReqSize)))
        goto err;
    if (!(EVP_SignFinal(ctx, signature, &sigLen, (EVP_PKEY *)pkey)))
        goto err;

    /* set the signature value */
    if (!(ASN1_BIT_STRING_set(poposig->signature, signature, sigLen)))
        goto err;

    /* cleanup */
    OPENSSL_free(certReqDer);
    EVP_MD_CTX_destroy(ctx);
    OPENSSL_free(signature);
    return poposig;
 err:
    CRMFerr(CRMF_F_CRMF_POPOSIGNINGKEY_NEW,
            CRMF_R_ERROR_SETTING_POPSIGNINGKEY);
    if (poposig)
        CRMF_POPOSIGNINGKEY_free(poposig);
    if (certReqDer)
        OPENSSL_free(certReqDer);
    if (ctx)
        EVP_MD_CTX_destroy(ctx);
    if (signature)
        OPENSSL_free(signature);
    return NULL;
}

/* ############################################################################ *
 * calculate and set the proof of possession based on the popoMethod (define in cmp.h)
 * the following types are supported so far (#defines in crfm.h):
 *       CRMF_POPO_NONE: ProofOfPossession field omitted, CA/RA uses out-of-band method to verify POP (compare RFC 4211, section 4).
 *       CRMF_POPO_SIGNATURE: according to section 4.1 (only case 3 supported so far)
 *       CRMF_POPO_ENCRCERT:  according to section 4.2 with the indirect method
 *       (subsequentMessage/enccert)
 *
          subsequentMessage is used to indicate that the POP will be
          completed by decrypting a message from the CA/RA and returning a
          response.  The type of message to be decrypted is indicated by the
          value used.

                 encrCert indicates that the certificate issued is to be
                 returned in an encrypted form.  The requestor is required to
                 decrypt the certificate and prove success to the CA/RA.  The
                 details of this are provided by the CRP.
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_calc_and_set_popo(CRMF_CERTREQMSG *certReqMsg,
                                      const EVP_PKEY *pkey, int digest, int popoMethod)
{
    CRMF_PROOFOFPOSSESION *newPopo = NULL;

    if (popoMethod == CRMF_POPO_NONE)
        return 1;               /* nothing to be done */

    if (!certReqMsg)
        goto err;
    if (popoMethod == CRMF_POPO_SIGNATURE && !pkey)
        goto err;

    if (!(newPopo = CRMF_PROOFOFPOSSESION_new()))
        goto err;

    switch (popoMethod) {
    case CRMF_POPO_RAVERIFIED:
        newPopo->type = CRMF_PROOFOFPOSESSION_RAVERIFIED;
        newPopo->value.raVerified = ASN1_NULL_new();
        break;

    case CRMF_POPO_SIGNATURE:
        if (!
            (newPopo->value.signature =
             CRMF_poposigningkey_new(certReqMsg->certReq, pkey, digest)))
            goto err;
        newPopo->type = CRMF_PROOFOFPOSESSION_SIGNATURE;
        break;

    case CRMF_POPO_ENCRCERT:
        newPopo->type = CRMF_PROOFOFPOSESSION_KEYENCIPHERMENT;
        newPopo->value.keyEncipherment = CRMF_POPOPRIVKEY_new();

        newPopo->value.keyEncipherment->type =
            CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE;

        newPopo->value.keyEncipherment->value.subsequentMessage =
            ASN1_INTEGER_new();
        ASN1_INTEGER_set(newPopo->value.keyEncipherment->value.subsequentMessage,
                         CRMF_SUBSEQUENTMESSAGE_ENCRCERT);
        break;

    default:
        CRMFerr(CRMF_F_CRMF_CERTREQMSG_CALC_AND_SET_POPO,
                CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO);
        goto err;
    }

    if (certReqMsg->popo)
        /* OPTIONAL but initialized before */
        CRMF_PROOFOFPOSSESION_free(certReqMsg->popo);
    certReqMsg->popo = newPopo;

    return 1;
 err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_CALC_AND_SET_POPO,
            CRMF_R_ERROR_CALCULATING_AND_SETTING_POPO);
    if (newPopo)
        CRMF_PROOFOFPOSSESION_free(newPopo);
    return 0;
}
