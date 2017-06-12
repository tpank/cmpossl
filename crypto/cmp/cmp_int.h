
#ifndef HEADER_CMP_INT_H
# define HEADER_CMP_INT_H

# include <openssl/ossl_typ.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
# include <openssl/safestack.h>

# include <openssl/crmf.h>

# define CMP_VERSION 2L

# ifdef  __cplusplus
extern "C" {
# endif

/* ########################################################################## *
 * Helper functions
 * ########################################################################## */

/* from cmp_ses.c */
void add_error_data(const char *txt);

/* ########################################################################## *
 * ASN.1 DECLARATIONS
 * ########################################################################## */

/* this structure is used to store the context for CMP sessions 
 * partly using OpenSSL ASN.1 types in order to ease handling it */
struct cmp_ctx_st {
    /* "reference and secret" for MSG_MAC_ALG */
    ASN1_OCTET_STRING *referenceValue;
    ASN1_OCTET_STRING *secretValue;
    /* PBMParameters */
    size_t pbm_slen;
    int pbm_owf;
    long pbm_itercnt;
    int pbm_mac;

    /* for setting itav for EJBCA in CA mode */
    ASN1_UTF8STRING *regToken;
    /* certificate used to identify the server */
    X509 *srvCert;
    /* current client certificate used to identify and sign for MSG_SIG_ALG */
    X509 *clCert;
    /* for KUR: certificate to be updated; for RR: certificate to be revoked */
    X509 *oldClCert;
    /* subject name to be used in the cert template. NB: could also be taken
     * from clcert */
    X509_NAME *subjectName;
    /* to set in recipient in pkiheader */
    X509_NAME *recipient;
    /* to set in issuer in pkiheader */
    X509_NAME *issuer;
    /* NID of digest algorithm used in MSG_SIG_ALG, defaults to SHA256 */
    int digest;
    /* X.509 extensions to be added to certificate request */
    X509_EXTENSIONS *reqExtensions;
    /* names to be added to the cert template as the subjectAltName extension */
    STACK_OF (GENERAL_NAME) * subjectAltNames;
    /* whether or not the subjectAltName extension should be set critical */
    int setSubjectAltNameCritical;
    /* Stack of CA certificates sent by the CA in a IP message */
    STACK_OF (X509) * caPubs;
    /* stack of extraCerts to be included when sending a PKI message */
    STACK_OF (X509) * extraCertsOut;
    /* stack of extraCerts received from remote */
    STACK_OF (X509) * extraCertsIn;
    /* EVP_PKEY holding the *current* key pair
     * Note: this is not an ASN.1 type */
    EVP_PKEY *pkey;
    /* *new* CLIENT certificate received from the CA
     * TODO: this should be a stack since there could be more than one */
    X509 *newClCert;
    /* EVP_PKEY holding the *new* key pair
     * Note: this is not an ASN.1 type */
    EVP_PKEY *newPkey;
    /* the current transaction ID */
    ASN1_OCTET_STRING *transactionID;
    /* last nonce received */
    ASN1_OCTET_STRING *recipNonce;
    /* to set implicitConfirm in IR/KUR/CR messages */
    int implicitConfirm;
    /* disable confirmation messages in IR/KUR/CR message exchanges to cope with broken server */
    int disableConfirm;
    /* accept unprotected error responses */
    int unprotectedErrors;
    /* Proof-of-posession mechanism used. Defaults to signature (POPOsignkingKey) */
    int popoMethod;
    /* Revocation reason code to be included in RR */
    int revocationReason;
    /* maximum time in secods to wait for an http transfer to complete
     * Note: only usable with libcurl! */
    int HttpTimeOut;
    /* maximum time to poll the server for a response if a 'waiting' PKIStatus is received */
    int maxPollTime;
    /* PKIStatus of last received IP/CP/KUP */
    /* TODO: this should be a stack since there could be more than one */
    long lastPKIStatus;
    /* failInfoCode of last received IP/CP/KUP */
    /* TODO: this should be a stack since there could be more than one */
    unsigned long failInfoCode;
    STACK_OF (ASN1_UTF8STRING) * lastStatusString;

    /* log callback functions for error and debug messages */
    cmp_logfn_t error_cb, debug_cb;

    /* callback for letting the user check the received certificate and 
     * reject if necessary */
    cmp_certConfFn_t certConf_cb;
    /* callback to be used during verification of server certificate */
    cert_verify_cb_t cert_verify_cb;

    /* stores for trusted and untrusted (intermediate) certificates */
    X509_STORE *trusted_store;
    X509_STORE *untrusted_store;
    /* CRLs to be used as primary source during CMP certificate verification */
    STACK_OF(X509_CRL) *crls;

    /* include root certs from extracerts when validating? Used for 3GPP-style E.7 */
    int permitTAInExtraCertsForIR;
    /* stores the server Cert as soon as it's trust chain has been validated */
    X509 *validatedSrvCert;

    /* HTTP transfer related settings */
    char *serverName;
    int serverPort;
    char *serverPath;
    char *proxyName;
    int proxyPort;
    int lastHTTPCode;
    BIO *tlsBIO;
    char *sourceAddress;

    CERTIFICATEPOLICIES *policies;

} /* CMP_CTX */;
DECLARE_ASN1_FUNCTIONS(CMP_CTX)

/*
     RevAnnContent ::= SEQUENCE {
             status                          PKIStatus,
             certId                          CertId,
             willBeRevokedAt         GeneralizedTime,
             badSinceDate            GeneralizedTime,
             crlDetails                      Extensions  OPTIONAL
             -- extra CRL details (e.g., crl number, reason, location, etc.)
     }
 */
typedef struct cmp_revanncontent_st {
    ASN1_INTEGER *status;
    CRMF_CERTID *certId;
    ASN1_GENERALIZEDTIME *willBeRevokedAt;
    ASN1_GENERALIZEDTIME *badSinceDate;
    X509_EXTENSIONS *crlDetails;
} CMP_REVANNCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_REVANNCONTENT)

/*
     Challenge ::= SEQUENCE {
             owf                             AlgorithmIdentifier  OPTIONAL,

             -- MUST be present in the first Challenge; MAY be omitted in
             -- any subsequent Challenge in POPODecKeyChallContent (if
             -- omitted, then the owf used in the immediately preceding
             -- Challenge is to be used).

             witness                         OCTET STRING,
             -- the result of applying the one-way function (owf) to a
             -- randomly-generated INTEGER, A.      [Note that a different
             -- INTEGER MUST be used for each Challenge.]
             challenge                       OCTET STRING
             -- the encryption (under the public key for which the cert.
             -- request is being made) of Rand, where Rand is specified as
             --   Rand ::= SEQUENCE {
             --              int      INTEGER,
             --               - the randomly-generated INTEGER A (above)
             --              sender   GeneralName
             --               - the sender's name (as included in PKIHeader)
             --   }
     }
 */
typedef struct cmp_challenge_st {
    X509_ALGOR *owf;
    ASN1_OCTET_STRING *whitness;
    ASN1_OCTET_STRING *challenge;
} CMP_CHALLENGE;
DECLARE_ASN1_FUNCTIONS(CMP_CHALLENGE)

/*
     CAKeyUpdAnnContent ::= SEQUENCE {
             oldWithNew   CMPCertificate, -- old pub signed with new priv
             newWithOld   CMPCertificate, -- new pub signed with old priv
             newWithNew   CMPCertificate  -- new pub signed with new priv
     }
 */
typedef struct cmp_cakeyupdanncontent_st {
    X509 *oldWithNew;
    X509 *newWithOld;
    X509 *newWithNew;
} CMP_CAKEYUPDANNCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_CAKEYUPDANNCONTENT)

/* declared already here as it will be used in CMP_PKIMESSAGE (nested) and infotype and * value*/
typedef STACK_OF(CMP_PKIMESSAGE) CMP_PKIMESSAGES;
DECLARE_ASN1_FUNCTIONS(CMP_PKIMESSAGES)

/*
     InfoTypeAndValue ::= SEQUENCE {
             infoType                               OBJECT IDENTIFIER,
             infoValue                              ANY DEFINED BY infoType  OPTIONAL
     }
 */
struct cmp_infotypeandvalue_st {
    ASN1_OBJECT *infoType;
    union {
        char *ptr;
        /* NID_id_it_caProtEncCert - CA Protocol Encryption Certificate  */
        X509 *caProtEncCert;
        /* NID_id_it_signKeyPairTypes - Signing Key Pair Types  */
        STACK_OF (X509_ALGOR) * signKeyPairTypes;
        /* NID_id_it_encKeyPairTypes - Encryption/Key Agreement Key Pair Types  */
        STACK_OF (X509_ALGOR) * encKeyPairTypes;
        /* NID_id_it_preferredSymmAlg - Preferred Symmetric Algorithm  */
        X509_ALGOR *preferredSymmAlg;
        /* NID_id_it_caKeyUpdateInfo - Updated CA Key Pair      */
        CMP_CAKEYUPDANNCONTENT *caKeyUpdateInfo;
        /* NID_id_it_currentCRL - CRL  */
        X509_CRL *currentCRL;
        /* NID_id_it_unsupportedOIDs - Unsupported Object Identifiers  */
        STACK_OF (ASN1_OBJECT) * unsupportedOIDs;
        /* NID_id_it_keyPairParamReq - Key Pair Parameters Request      */
        ASN1_OBJECT *keyPairParamReq;
        /* NID_id_it_keyPairParamRep - Key Pair Parameters Response  */
        X509_ALGOR *keyPairParamRep;
        /* NID_id_it_revPassphrase - Revocation Passphrase      */
        CRMF_ENCRYPTEDVALUE *revPassphrase;
        /* NID_id_it_implicitConfirm - ImplicitConfirm  */
        ASN1_NULL *implicitConfirm;
        /* NID_id_it_confirmWaitTime - ConfirmWaitTime  */
        ASN1_GENERALIZEDTIME *confirmWaitTime;
        /* NID_id_it_origPKIMessage - origPKIMessage  */
        CMP_PKIMESSAGES *origPKIMessage;
        /* NID_id_it_suppLangTags - Supported Language Tags */
        STACK_OF (ASN1_UTF8STRING) * suppLangTagsValue;
        /* this is to be used for so far undeclared objects */
        ASN1_TYPE *other;
    } infoValue;
} /* CMP_INFOTYPEANDVALUE */;
DECLARE_ASN1_FUNCTIONS(CMP_INFOTYPEANDVALUE)

typedef STACK_OF(ASN1_UTF8STRING) CMP_PKIFREETEXT;


typedef struct cmp_certorenccert_st {
    int type;
    union {
        X509 *certificate;
        CRMF_ENCRYPTEDVALUE *encryptedCert;
    } value;
} CMP_CERTORENCCERT;
DECLARE_ASN1_FUNCTIONS(CMP_CERTORENCCERT)

/*
     CertifiedKeyPair ::= SEQUENCE {
             certOrEncCert           CertOrEncCert,
             privateKey              [0] EncryptedValue              OPTIONAL,
             -- see [CRMF] for comment on encoding
             publicationInfo [1] PKIPublicationInfo  OPTIONAL
     }
 */
typedef struct cmp_certifiedkeypair_st {
    CMP_CERTORENCCERT *certOrEncCert;
    CRMF_ENCRYPTEDVALUE *privateKey;
    CRMF_PKIPUBLICATIONINFO *failInfo;
} CMP_CERTIFIEDKEYPAIR;
DECLARE_ASN1_FUNCTIONS(CMP_CERTIFIEDKEYPAIR)

/*
     PKIStatusInfo ::= SEQUENCE {
             status            PKIStatus,
             statusString  PKIFreeText         OPTIONAL,
             failInfo          PKIFailureInfo  OPTIONAL
     }
 */
struct cmp_pkistatusinfo_st {
    CMP_PKISTATUS *status;
    CMP_PKIFREETEXT *statusString;
    CMP_PKIFAILUREINFO *failInfo;
} /* CMP_PKISTATUSINFO */;
DECLARE_ASN1_FUNCTIONS(CMP_PKISTATUSINFO)

/*
     RevReqContent ::= SEQUENCE OF RevDetails

     RevDetails ::= SEQUENCE {
             certDetails             CertTemplate,
             -- allows requester to specify as much as they can about
             -- the cert. for which revocation is requested
             -- (e.g., for cases in which serialNumber is not available)
             crlEntryDetails         Extensions               OPTIONAL
             -- requested crlEntryExtensions
     }
*/
typedef struct cmp_revdetails_st {
    CRMF_CERTTEMPLATE *certDetails;
    X509_EXTENSIONS *crlEntryDetails;
} CMP_REVDETAILS;
DECLARE_ASN1_FUNCTIONS(CMP_REVDETAILS)
DEFINE_STACK_OF(CMP_REVDETAILS)

/*
     RevRepContent ::= SEQUENCE {
             status           SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
             -- in same order as was sent in RevReqContent
             revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId
                                                                                     OPTIONAL,
             -- IDs for which revocation was requested
             -- (same order as status)
             crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList
                                                                                     OPTIONAL
             -- the resulting CRLs (there may be more than one)
     }
 */
struct cmp_revrepcontent_st {
    STACK_OF (CMP_PKISTATUSINFO) * status;
    STACK_OF (CRMF_CERTID) * certId;
    STACK_OF (X509) * crls;
} /* CMP_REVREPCONTENT */;
DECLARE_ASN1_FUNCTIONS(CMP_REVREPCONTENT)

/*
     KeyRecRepContent ::= SEQUENCE {
             status                                  PKIStatusInfo,
             newSigCert                      [0] CMPCertificate OPTIONAL,
             caCerts                         [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL,
             keyPairHist             [2] SEQUENCE SIZE (1..MAX) OF CertifiedKeyPair OPTIONAL
     }
*/
typedef struct cmp_keyrecrepcontent_st {
    CMP_PKISTATUSINFO *status;
    X509 *newSigCert;
    STACK_OF (X509) * caCerts;
    STACK_OF (CMP_CERTIFIEDKEYPAIR) * keyPairHist;
} CMP_KEYRECREPCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_KEYRECREPCONTENT)
/*
     ErrorMsgContent ::= SEQUENCE {
             pKIStatusInfo                  PKIStatusInfo,
             errorCode                              INTEGER                   OPTIONAL,
             -- implementation-specific error codes
             errorDetails                   PKIFreeText               OPTIONAL
             -- implementation-specific error details
     }
 */
typedef struct cmp_errormsgcontent_st {
    CMP_PKISTATUSINFO *pKIStatusInfo;
    ASN1_INTEGER *errorCode;
    STACK_OF (ASN1_UTF8STRING) * errorDetails;
} CMP_ERRORMSGCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_ERRORMSGCONTENT)

/*
     CertConfirmContent ::= SEQUENCE OF CertStatus

     CertStatus ::= SEQUENCE {
            certHash        OCTET STRING,
            -- the hash of the certificate, using the same hash algorithm
            -- as is used to create and verify the certificate signature
            certReqId       INTEGER,
            -- to match this confirmation with the corresponding req/rep
            statusInfo      PKIStatusInfo OPTIONAL
     }
 */
struct cmp_certstatus_st {
    ASN1_OCTET_STRING *certHash;
    ASN1_INTEGER *certReqId;
    CMP_PKISTATUSINFO *statusInfo;
} /* CMP_CERTSTATUS */;
DECLARE_ASN1_FUNCTIONS(CMP_CERTSTATUS)

typedef STACK_OF(CMP_CERTSTATUS) CMP_CERTCONFIRMCONTENT;

/*
     CertResponse ::= SEQUENCE {
             certReqId                       INTEGER,
             -- to match this response with corresponding request (a value
             -- of -1 is to be used if certReqId is not specified in the
             -- corresponding request)
             status                          PKIStatusInfo,
             certifiedKeyPair        CertifiedKeyPair        OPTIONAL,
             rspInfo                         OCTET STRING            OPTIONAL
             -- analogous to the id-regInfo-utf8Pairs string defined
             -- for regInfo in CertReqMsg [CRMF]
     }
 */
struct cmp_certresponse_st {
    ASN1_INTEGER *certReqId;
    CMP_PKISTATUSINFO *status;
    CMP_CERTIFIEDKEYPAIR *certifiedKeyPair;
    ASN1_OCTET_STRING *rspInfo;
} /* CMP_CERTRESPONSE */;
DECLARE_ASN1_FUNCTIONS(CMP_CERTRESPONSE)

/*
     CertRepMessage ::= SEQUENCE {
             caPubs           [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                                              OPTIONAL,
             response                 SEQUENCE OF CertResponse
     }
 */
struct cmp_certrepmessage_st {
    STACK_OF (X509) * caPubs;
    STACK_OF (CMP_CERTRESPONSE) * response;
} /* CMP_CERTREPMESSAGE */;
DECLARE_ASN1_FUNCTIONS(CMP_CERTREPMESSAGE)

/* the following is from RFC 2986 - PKCS #10

Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
    type    ATTRIBUTE.&id({IOSet}),
    values  SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
}

CertificationRequestInfo ::= SEQUENCE {
    version           INTEGER { v1(0) } (v1,...),
    subject           Name,
    subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
    attributes        [0] Attributes{{ CRIAttributes }}
}

CertificationRequest ::= SEQUENCE {
    certificationRequestInfo CertificationRequestInfo,
    signatureAlgorithm               AlgorithmIdentifier{{ SignatureAlgorithms }},
    signature                                BIT STRING
}
*/
typedef struct pkcs10_attribute_st {
    ASN1_OBJECT *id;
    STACK_OF (ASN1_TYPE) * values;
} PKCS10_ATTRIBUTE;
DECLARE_ASN1_FUNCTIONS(PKCS10_ATTRIBUTE)

typedef struct pkcs10_certificationrequestinfo_st {
    ASN1_INTEGER *version;
    X509_NAME *subject;
    X509_PUBKEY *subjectPKInfo;
    STACK_OF (PKCS10_ATTRIBUTE) * attributes;
} PKCS10_CERTIFICATIONREQUESTINFO;
DECLARE_ASN1_FUNCTIONS(PKCS10_CERTIFICATIONREQUESTINFO)

typedef struct pkcs10_certificationrequest_st {
    PKCS10_CERTIFICATIONREQUESTINFO *certificationRequestInfo;
    X509_ALGOR *signatureAlgorithm;
    ASN1_BIT_STRING *signature;
} PKCS10_CERTIFICATIONREQUEST;
DECLARE_ASN1_FUNCTIONS(PKCS10_CERTIFICATIONREQUEST)

/*
     PollReqContent ::= SEQUENCE OF SEQUENCE {
             certReqId                              INTEGER
     }
 */
typedef struct cmp_pollreq_st {
    ASN1_INTEGER *certReqId;
} CMP_POLLREQ;
DECLARE_ASN1_FUNCTIONS(CMP_POLLREQ)
DEFINE_STACK_OF(CMP_POLLREQ)
typedef STACK_OF(CMP_POLLREQ) CMP_POLLREQCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_POLLREQCONTENT)

/*
     PollRepContent ::= SEQUENCE OF SEQUENCE {
             certReqId                              INTEGER,
             checkAfter                             INTEGER,  -- time in seconds
             reason                                 PKIFreeText OPTIONAL
     }
 */
typedef struct cmp_pollrep_st {
    ASN1_INTEGER *certReqId;
    ASN1_INTEGER *checkAfter;
    STACK_OF (ASN1_UTF8STRING) * reason;
} CMP_POLLREP;
DECLARE_ASN1_FUNCTIONS(CMP_POLLREP)
DEFINE_STACK_OF(CMP_POLLREP)
typedef STACK_OF(CMP_POLLREP) CMP_POLLREPCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_POLLREPCONTENT)

/*
     PKIHeader ::= SEQUENCE {
             pvno                            INTEGER         { cmp1999(1), cmp2000(2) },
             sender                          GeneralName,
             -- identifies the sender
             recipient                       GeneralName,
             -- identifies the intended recipient
             messageTime     [0] GeneralizedTime             OPTIONAL,
             -- time of production of this message (used when sender
             -- believes that the transport will be "suitable"; i.e.,
             -- that the time will still be meaningful upon receipt)
             protectionAlg   [1] AlgorithmIdentifier         OPTIONAL,
             -- algorithm used for calculation of protection bits
             senderKID               [2] KeyIdentifier                       OPTIONAL,
             recipKID                [3] KeyIdentifier                       OPTIONAL,
             -- to identify specific keys used for protection
             transactionID   [4] OCTET STRING                        OPTIONAL,
             -- identifies the transaction; i.e., this will be the same in
             -- corresponding request, response, certConf, and PKIConf
             -- messages
             senderNonce     [5] OCTET STRING                        OPTIONAL,
             recipNonce              [6] OCTET STRING                        OPTIONAL,
             -- nonces used to provide replay protection, senderNonce
             -- is inserted by the creator of this message; recipNonce
             -- is a nonce previously inserted in a related message by
             -- the intended recipient of this message
             freeText                [7] PKIFreeText                         OPTIONAL,
             -- this may be used to indicate context-specific instructions
             -- (this field is intended for human consumption)
             generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
                                                            InfoTypeAndValue         OPTIONAL
             -- this may be used to convey context-specific information
             -- (this field not primarily intended for human consumption)
     }
*/
struct cmp_pkiheader_st {
    ASN1_INTEGER *pvno;
    GENERAL_NAME *sender;
    GENERAL_NAME *recipient;
    ASN1_GENERALIZEDTIME *messageTime; /* 0 */
    X509_ALGOR *protectionAlg; /* 1 */
    ASN1_OCTET_STRING *senderKID; /* 2 */
    ASN1_OCTET_STRING *recipKID; /* 3 */
    ASN1_OCTET_STRING *transactionID; /* 4 */
    ASN1_OCTET_STRING *senderNonce; /* 5 */
    ASN1_OCTET_STRING *recipNonce; /* 6 */
    STACK_OF (ASN1_UTF8STRING) * freeText; /* 7 */
    STACK_OF (CMP_INFOTYPEANDVALUE) * generalInfo; /* 8 */
} /* CMP_PKIHEADER */;
DECLARE_ASN1_FUNCTIONS(CMP_PKIHEADER)

# define V_CMP_PKIBODY_IR        0
# define V_CMP_PKIBODY_IP        1
# define V_CMP_PKIBODY_CR        2
# define V_CMP_PKIBODY_CP        3
# define V_CMP_PKIBODY_P10CR     4
# define V_CMP_PKIBODY_POPDECC   5
# define V_CMP_PKIBODY_POPDECR   6
# define V_CMP_PKIBODY_KUR       7
# define V_CMP_PKIBODY_KUP       8
# define V_CMP_PKIBODY_KRR       9
# define V_CMP_PKIBODY_KRP       10
# define V_CMP_PKIBODY_RR        11
# define V_CMP_PKIBODY_RP        12
# define V_CMP_PKIBODY_CCR       13
# define V_CMP_PKIBODY_CCP       14
# define V_CMP_PKIBODY_CKUANN    15
# define V_CMP_PKIBODY_CANN      16
# define V_CMP_PKIBODY_RANN      17
# define V_CMP_PKIBODY_CRLANN    18
# define V_CMP_PKIBODY_PKICONF   19
# define V_CMP_PKIBODY_NESTED    20
# define V_CMP_PKIBODY_GENM      21
# define V_CMP_PKIBODY_GENP      22
# define V_CMP_PKIBODY_ERROR     23
# define V_CMP_PKIBODY_CERTCONF  24
# define V_CMP_PKIBODY_POLLREQ   25
# define V_CMP_PKIBODY_POLLREP   26

typedef STACK_OF(CMP_CHALLENGE) CMP_POPODECKEYCHALLCONTENT;
typedef STACK_OF(ASN1_INTEGER) CMP_POPODECKEYRESPCONTENT;
typedef STACK_OF(CMP_REVDETAILS) CMP_REVREQCONTENT;
typedef STACK_OF(X509_CRL) CMP_CRLANNCONTENT;
typedef STACK_OF(CMP_INFOTYPEANDVALUE) CMP_GENMSGCONTENT;
typedef STACK_OF(CMP_INFOTYPEANDVALUE) CMP_GENREPCONTENT;

/*
     PKIBody ::= CHOICE {           -- message-specific body elements
             ir               [0]  CertReqMessages,            --Initialization Request
             ip               [1]  CertRepMessage,             --Initialization Response
             cr               [2]  CertReqMessages,            --Certification Request
             cp               [3]  CertRepMessage,             --Certification Response
             p10cr    [4]  CertificationRequest,   --imported from [PKCS10]
             popdecc  [5]  POPODecKeyChallContent, --pop Challenge
             popdecr  [6]  POPODecKeyRespContent,  --pop Response
             kur      [7]  CertReqMessages,            --Key Update Request
             kup      [8]  CertRepMessage,             --Key Update Response
             krr      [9]  CertReqMessages,            --Key Recovery Request
             krp      [10] KeyRecRepContent,           --Key Recovery Response
             rr               [11] RevReqContent,              --Revocation Request
             rp               [12] RevRepContent,              --Revocation Response
             ccr      [13] CertReqMessages,            --Cross-Cert. Request
             ccp      [14] CertRepMessage,             --Cross-Cert. Response
             ckuann   [15] CAKeyUpdAnnContent,         --CA Key Update Ann.
             cann     [16] CertAnnContent,             --Certificate Ann.
             rann     [17] RevAnnContent,              --Revocation Ann.
             crlann   [18] CRLAnnContent,              --CRL Announcement
             pkiconf  [19] PKIConfirmContent,          --Confirmation
             nested   [20] NestedMessageContent,   --Nested Message
             genm     [21] GenMsgContent,              --General Message
             genp     [22] GenRepContent,              --General Response
             error    [23] ErrorMsgContent,            --Error Message
             certConf [24] CertConfirmContent,         --Certificate confirm
             pollReq  [25] PollReqContent,             --Polling request
             pollRep  [26] PollRepContent              --Polling response
*/
typedef struct cmp_pkibody_st {
    int type;
    union {
        CRMF_CERTREQMESSAGES *ir; /* 0 */
        CMP_CERTREPMESSAGE *ip; /* 1 */
        CRMF_CERTREQMESSAGES *cr; /* 2 */
        CMP_CERTREPMESSAGE *cp; /* 3 */
        /* p10cr        [4]  CertificationRequest,       --imported from [PKCS10] */
        PKCS10_CERTIFICATIONREQUEST *p10cr; /* 4 */
        /* popdecc      [5]  POPODecKeyChallContent, --pop Challenge */
        /* POPODecKeyChallContent ::= SEQUENCE OF Challenge */
        CMP_POPODECKEYCHALLCONTENT *popdecc; /* 5 */
        /* popdecr      [6]  POPODecKeyRespContent,  --pop Response */
        /* POPODecKeyRespContent ::= SEQUENCE OF INTEGER */
        CMP_POPODECKEYRESPCONTENT *popdecr; /* 6 */
        CRMF_CERTREQMESSAGES *kur; /* 7 */
        CMP_CERTREPMESSAGE *kup; /* 8 */
        CRMF_CERTREQMESSAGES *krr; /* 9 */

        /* krp          [10] KeyRecRepContent,           --Key Recovery Response */
        CMP_KEYRECREPCONTENT *krp; /* 10 */
        /* rr           [11] RevReqContent,                      --Revocation Request */
        CMP_REVREQCONTENT *rr; /* 11 */
        /* rp           [12] RevRepContent,                      --Revocation Response */
        CMP_REVREPCONTENT *rp; /* 12 */
        /* ccr          [13] CertReqMessages,            --Cross-Cert. Request */
        CRMF_CERTREQMESSAGES *ccr; /* 13 */
        /* ccp          [14] CertRepMessage,             --Cross-Cert. Response */
        CMP_CERTREPMESSAGE *ccp; /* 14 */
        /* ckuann       [15] CAKeyUpdAnnContent,         --CA Key Update Ann. */
        CMP_CAKEYUPDANNCONTENT *ckuann; /* 15 */
        /* cann         [16] CertAnnContent,             --Certificate Ann. */
        /* CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
        X509 *cann;         /* 16 */
        /* rann         [17] RevAnnContent,                      --Revocation Ann. */
        CMP_REVANNCONTENT *rann; /* 17 */
        /* crlann       [18] CRLAnnContent,                      --CRL Announcement */
        /* CRLAnnContent ::= SEQUENCE OF CertificateList */
        CMP_CRLANNCONTENT *crlann;
        /* PKIConfirmContent ::= NULL */
        /* pkiconf      [19] PKIConfirmContent,          --Confirmation */
        /* CMP_PKICONFIRMCONTENT would be only a typedef of ASN1_NULL */
        /* CMP_CONFIRMCONTENT *pkiconf; */
        /* NOTE: this should ASN1_NULL according to the RFC but there might be a struct in it when sent from faulty servers... */
        ASN1_TYPE *pkiconf; /* 19 */
        /* nested       [20] NestedMessageContent,       --Nested Message */
        /* NestedMessageContent ::= PKIMessages */
        CMP_PKIMESSAGES *nested; /* 20 */
        /* genm         [21] GenMsgContent,                      --General Message */
        /* GenMsgContent ::= SEQUENCE OF InfoTypeAndValue */
        CMP_GENMSGCONTENT *genm; /* 21 */
        /* genp         [22] GenRepContent,                      --General Response */
        /* GenRepContent ::= SEQUENCE OF InfoTypeAndValue */
        CMP_GENREPCONTENT *genp; /* 22 */
        /* error        [23] ErrorMsgContent,            --Error Message */
        CMP_ERRORMSGCONTENT *error; /* 23 */
        /* certConf [24] CertConfirmContent,     --Certificate confirm */
        CMP_CERTCONFIRMCONTENT *certConf; /* 24 */
        /* pollReq      [25] PollReqContent,             --Polling request */
        CMP_POLLREQCONTENT *pollReq;
        /* pollRep      [26] PollRepContent                      --Polling response */
        CMP_POLLREPCONTENT *pollRep;
    } value;
} CMP_PKIBODY;
DECLARE_ASN1_FUNCTIONS(CMP_PKIBODY)

/*
     PKIProtection ::= BIT STRING

     PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage

      PKIMessage ::= SEQUENCE {
             header                   PKIHeader,
             body                     PKIBody,
             protection   [0] PKIProtection OPTIONAL,
             extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                                              OPTIONAL
     }
 */
struct cmp_pkimessage_st {
    CMP_PKIHEADER *header;
    CMP_PKIBODY *body;
    ASN1_BIT_STRING *protection; /* 0 */
    /* CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
    STACK_OF (X509) * extraCerts; /* 1 */
} /* CMP_PKIMESSAGE */;
DECLARE_ASN1_FUNCTIONS(CMP_PKIMESSAGE)

    /*
       ProtectedPart ::= SEQUENCE {
       header    PKIHeader,
       body      PKIBody
       }
     */
typedef struct cmp_protectedpart_st {
    CMP_PKIHEADER *header;
    CMP_PKIBODY *body;
} CMP_PROTECTEDPART;
DECLARE_ASN1_FUNCTIONS(CMP_PROTECTEDPART)

/* this is not defined here as it is already in CRMF:
     id-PasswordBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 13}
     PBMParameter ::= SEQUENCE {
             salt                            OCTET STRING,
             -- note:  implementations MAY wish to limit acceptable sizes
             -- of this string to values appropriate for their environment
             -- in order to reduce the risk of denial-of-service attacks
             owf                             AlgorithmIdentifier,
             -- AlgId for a One-Way Function (SHA-1 recommended)
             iterationCount          INTEGER,
             -- number of times the OWF is applied
             -- note:  implementations MAY wish to limit acceptable sizes
             -- of this integer to values appropriate for their environment
             -- in order to reduce the risk of denial-of-service attacks
             mac                             AlgorithmIdentifier
             -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
     }       -- or HMAC [RFC2104, RFC2202])
 */
/*
    TODO: this is not yet defined here - but DH is anyway not used yet

     id-DHBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 30}
     DHBMParameter ::= SEQUENCE {
             owf                             AlgorithmIdentifier,
             -- AlgId for a One-Way Function (SHA-1 recommended)
             mac                             AlgorithmIdentifier
             -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
     }       -- or HMAC [RFC2104, RFC2202])

 */
/* The following is not cared for, because it is described in section 5.2.5
 * that this is beyond the scope of CMP
     OOBCert ::= CMPCertificate

     OOBCertHash ::= SEQUENCE {
             hashAlg         [0] AlgorithmIdentifier         OPTIONAL,
             certId          [1] CertId                                      OPTIONAL,
             hashVal                 BIT STRING
             -- hashVal is calculated over the DER encoding of the
             -- self-signed certificate with the identifier certID.
     }
 */




    

# ifdef  __cplusplus
}
# endif
#endif
