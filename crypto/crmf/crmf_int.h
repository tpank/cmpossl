
#ifndef HEADER_CRMF_INT_H
# define HEADER_CRMF_INT_H

# include <openssl/ossl_typ.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
# include <openssl/safestack.h>
# include <openssl/crmf.h>

# ifdef  __cplusplus
extern "C" {
# endif


/*-
 *  Attributes ::= SET OF Attribute
 *  => X509_ATTRIBUTE
 *
 *  PrivateKeyInfo ::= SEQUENCE {
 *     version                       INTEGER,
 *     privateKeyAlgorithm           AlgorithmIdentifier,
 *     privateKey                    OCTET STRING,
 *     attributes                    [0] IMPLICIT Attributes OPTIONAL
 *  }
 */
typedef struct crmf_privatekeyinfo_st {
    ASN1_INTEGER *version;
    X509_ALGOR *AlgorithmIdentifier;
    ASN1_OCTET_STRING *privateKey;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
} CRMF_PRIVATEKEYINFO;
DECLARE_ASN1_FUNCTIONS(CRMF_PRIVATEKEYINFO)

/*-
 * section 4.2.1 Private Key Info Content Type
 * id-ct-encKeyWithID OBJECT IDENTIFIER ::= {id-ct 21}
 *
 * EncKeyWithID ::= SEQUENCE {
 * privateKey               PrivateKeyInfo,
 * identifier CHOICE {
 *      string                     UTF8String,
 *      generalName                GeneralName
 *      } OPTIONAL
 * }
 */
typedef struct crmf_enckeywithid_identifier_st {
    int type;
    union {
        ASN1_UTF8STRING *string;
        GENERAL_NAME *generalName;
    } value;
} CRMF_ENCKEYWITHID_IDENTIFIER;
DECLARE_ASN1_FUNCTIONS(CRMF_ENCKEYWITHID_IDENTIFIER)

typedef struct crmf_enckeywithid_st {
    CRMF_PRIVATEKEYINFO *privateKey;
    /* [0] */
    CRMF_ENCKEYWITHID_IDENTIFIER *identifier;
} CRMF_ENCKEYWITHID;
DECLARE_ASN1_FUNCTIONS(CRMF_ENCKEYWITHID)

/*-
 * CertId ::= SEQUENCE {
 *      issuer           GeneralName,
 *      serialNumber     INTEGER
 * }
 */
struct crmf_certid_st {
    GENERAL_NAME *issuer;
    ASN1_INTEGER *serialNumber;
} /* CRMF_CERTID */;
DEFINE_STACK_OF(CRMF_CERTID)
CRMF_CERTID *CRMF_CERTID_dup(CRMF_CERTID *cid);

/*-
 * EncryptedKey ::= CHOICE {
 * encryptedValue    EncryptedValue,       -- Deprecated
 * envelopedData     [0] EnvelopedData
 * }
 */
typedef struct crmf_encryptedkey_st {
    int type;
    union {
        CRMF_ENCRYPTEDVALUE *encryptedValue; /* Deprecated */
        /*-
         * TODO: This is not ASN1_NULL but CMS_ENVELOPEDDATA which should be
         * somehow  taken from crypto/cms which exists now
         * - this is not used anywhere so far */
        ASN1_NULL *envelopedData;
    } value;
} CRMF_ENCRYPTEDKEY;
DECLARE_ASN1_FUNCTIONS(CRMF_ENCRYPTEDKEY)

/*
 * PKIArchiveOptions ::= CHOICE {
 * encryptedPrivKey         [0] EncryptedKey,
 * -- the actual value of the private key
 * keyGenParameters         [1] KeyGenParameters,
 * -- parameters that allow the private key to be re-generated
 * archiveRemGenPrivKey [2] BOOLEAN
 * }
 * -- set to TRUE if sender wishes receiver to archive the private
 * -- key of a key pair that the receiver generates in response to
 * -- this request; set to FALSE if no archival is desired.
 */
struct crmf_pkiarchiveoptions_st {
    int type;
    union {
        /* 0 */
        CRMF_ENCRYPTEDKEY *encryptedPrivKey;
        /* KeyGenParameters ::= OCTET STRING *//* 1 */
        ASN1_OCTET_STRING *keyGenParameters;
        /* 2 */
        ASN1_BOOLEAN *archiveRemGenPrivKey;
    } value;
} /* CRMF_PKIARCHIVEOPTIONS */;
DECLARE_ASN1_FUNCTIONS(CRMF_PKIARCHIVEOPTIONS)
CRMF_PKIARCHIVEOPTIONS *CRMF_PKIARCHIVEOPTIONS_dup(CRMF_PKIARCHIVEOPTIONS
                                                   *pkiPubInfo);

/*
 * SinglePubInfo ::= SEQUENCE {
 *  pubMethod        INTEGER {
 *  dontCare        (0),
 *  x500            (1),
 *  web             (2),
 *  ldap            (3) },
 *  pubLocation  GeneralName OPTIONAL
 * }
 */
typedef struct crmf_singlepubinfo_st {
    ASN1_INTEGER *pubMethod;
    GENERAL_NAME *pubLocation;
} CRMF_SINGLEPUBINFO;
DECLARE_ASN1_FUNCTIONS(CRMF_SINGLEPUBINFO)

/*
 * PKIPublicationInfo ::= SEQUENCE {
 *      action     INTEGER {
 *                   dontPublish (0),
 *                   pleasePublish (1) },
 *      pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
 *      -- pubInfos MUST NOT be present if action is "dontPublish"
 *      -- (if action is "pleasePublish" and pubInfos is omitted,
 *      -- "dontCare" is assumed)
 */
struct crmf_pkipublicationinfo_st {
    ASN1_INTEGER *action;
    CRMF_SINGLEPUBINFO *pubinfos;
} /* CRMF_PKIPUBLICATIONINFO */;
DECLARE_ASN1_FUNCTIONS(CRMF_PKIPUBLICATIONINFO)
CRMF_PKIPUBLICATIONINFO *CRMF_PKIPUBLICATIONINFO_dup(
                                           CRMF_PKIPUBLICATIONINFO *pkiPubInfo);

/*
 * PKMACValue ::= SEQUENCE {
 * algId  AlgorithmIdentifier,
 * -- algorithm value shall be PasswordBasedMac {1 2 840 113533 7 66 13}
 * -- parameter value is PBMParameter
 * value  BIT STRING }
 */
typedef struct crmf_pkmacvalue_st {
    X509_ALGOR *algId;
    ASN1_BIT_STRING *value;
} CRMF_PKMACVALUE;
DECLARE_ASN1_FUNCTIONS(CRMF_PKMACVALUE)

/*
 * SubsequentMessage ::= INTEGER {
 * encrCert (0),
 * -- requests that resulting certificate be encrypted for the
 * -- end entity (following which, POP will be proven in a
 * -- confirmation message)
 * challengeResp (1) }
 * -- requests that CA engage in challenge-response exchange with
 * -- end entity in order to prove private key possession
 *
 * POPOPrivKey ::= CHOICE {
 * thisMessage       [0] BIT STRING,                 -- Deprecated
 * -- possession is proven in this message (which contains the private
 * -- key itself (encrypted for the CA))
 * subsequentMessage [1] SubsequentMessage,
 * -- possession will be proven in a subsequent message
 * dhMAC                     [2] BIT STRING,                 -- Deprecated
 * agreeMAC                  [3] PKMACValue,
 * encryptedKey      [4] EnvelopedData }
 */

typedef struct crmf_popoprivkey_st {
    int type;
    union {
        ASN1_BIT_STRING *thisMessage; /* Deprecated *//* 0 */
        ASN1_INTEGER *subsequentMessage; /* 1 */
        ASN1_BIT_STRING *dhMAC; /* 2 */
        CRMF_PKMACVALUE *agreeMAC; /* 3 */
        /*
         * TODO: This is not ASN1_NULL but CMS_ENVELOPEDDATA which should be
         * somehow taken from crypto/cms which exists now
         * - this is not used anywhere so far
         */
        /* 4 */
        ASN1_NULL *encryptedKey;
    } value;
} CRMF_POPOPRIVKEY;
DECLARE_ASN1_FUNCTIONS(CRMF_POPOPRIVKEY)

/*
 * PBMParameter ::= SEQUENCE {
 *    salt                            OCTET STRING,
 *    owf                             AlgorithmIdentifier,
 *    -- AlgId for a One-Way Function (SHA-1 recommended)
 *    iterationCount          INTEGER,
 *    -- number of times the OWF is applied
 *    mac                             AlgorithmIdentifier
 *    -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
 *    -- or HMAC [HMAC, RFC2202])
 * }
 */
struct crmf_pbmparameter_st {
    ASN1_OCTET_STRING *salt;
    X509_ALGOR *owf;
    ASN1_INTEGER *iterationCount;
    X509_ALGOR *mac;
} /* CRMF_PBMPARAMETER */;
DECLARE_ASN1_FUNCTIONS(CRMF_PBMPARAMETER)
#define CRMF_PBM_MAX_ITERATION_COUNT 100000 /* manipulated cnt leads to DoS */

/*
 * POPOSigningKeyInput ::= SEQUENCE {
 * authInfo                        CHOICE {
 *     sender                          [0] GeneralName,
 *   -- used only if an authenticated identity has been
 *   -- established for the sender (e.g., a DN from a
 *   -- previously-issued and currently-valid certificate)
 *   publicKeyMAC            PKMACValue },
 *   -- used if no authenticated GeneralName currently exists for
 *   -- the sender; publicKeyMAC contains a password-based MAC
 *   -- on the DER-encoded value of publicKey
 * publicKey                       SubjectPublicKeyInfo }  -- from CertTemplate
*/
typedef struct crmf_poposigningkeyinput_authinfo_st {
    int type;
    union {
        /* 0 */
        GENERAL_NAME *sender;
        /* 1 */
        CRMF_PKMACVALUE *publicKeyMAC;
    } value;
} CRMF_POPOSIGNINGKEYINPUT_AUTHINFO;
DECLARE_ASN1_FUNCTIONS(CRMF_POPOSIGNINGKEYINPUT_AUTHINFO)

typedef struct crmf_poposigningkeyinput_st {
    CRMF_POPOSIGNINGKEYINPUT_AUTHINFO *authinfo;
    X509_PUBKEY *publicKey;
} CRMF_POPOSIGNINGKEYINPUT;
DECLARE_ASN1_FUNCTIONS(CRMF_POPOSIGNINGKEYINPUT)

/*
 * POPOSigningKey ::= SEQUENCE {
 *  poposkInput               [0] POPOSigningKeyInput OPTIONAL,
 *  algorithmIdentifier   AlgorithmIdentifier,
 *  signature                         BIT STRING }
 */
struct crmf_poposigningkey_st {
    CRMF_POPOSIGNINGKEYINPUT *poposkInput;
    X509_ALGOR *algorithmIdentifier;
    ASN1_BIT_STRING *signature;
} /* CRMF_POPOSIGNINGKEY */;
DECLARE_ASN1_FUNCTIONS(CRMF_POPOSIGNINGKEY)

/*
 * ProofOfPossession ::= CHOICE {
 *  raVerified                [0] NULL,
 *  -- used if the RA has already verified that the requester is in
 *  -- possession of the private key
 *  signature                 [1] POPOSigningKey,
 *  keyEncipherment   [2] POPOPrivKey,
 *  keyAgreement      [3] POPOPrivKey }
 */
# define CRMF_PROOFOFPOSESSION_RAVERIFIED          0
# define CRMF_PROOFOFPOSESSION_SIGNATURE           1
# define CRMF_PROOFOFPOSESSION_KEYENCIPHERMENT 2
# define CRMF_PROOFOFPOSESSION_KEYAGREEMENT        3
typedef struct crmf_proofofpossesion_st {
    int type;
    union {
        ASN1_NULL *raVerified; /* 0 */
        CRMF_POPOSIGNINGKEY *signature; /* 1 */
        CRMF_POPOPRIVKEY *keyEncipherment; /* 2 */
        CRMF_POPOPRIVKEY *keyAgreement; /* 3 */
    } value;
} CRMF_PROOFOFPOSSESION;
DECLARE_ASN1_FUNCTIONS(CRMF_PROOFOFPOSSESION)

/*
 * OptionalValidity ::= SEQUENCE {
 * notBefore      [0] Time OPTIONAL,
 * notAfter       [1] Time OPTIONAL } -- at least one MUST be present
 */
struct crmf_optionalvalidity_st {
    /* 0 */
    ASN1_TIME *notBefore;
    /* 1 */
    ASN1_TIME *notAfter;
} /* CRMF_OPTIONALVALIDITY */;
DECLARE_ASN1_FUNCTIONS(CRMF_OPTIONALVALIDITY)

/*-
 * CertRequest ::= SEQUENCE {
 * certReqId         INTEGER,   -- ID for matching request and reply
 * certTemplate  CertTemplate,  -- Selected fields of cert to be issued
 * controls          Controls OPTIONAL }   -- Attributes affecting issuance
 */
struct crmf_certrequest_st {
    ASN1_INTEGER *certReqId;
    CRMF_CERTTEMPLATE *certTemplate;
    /* TODO: make CRMF_CONTROLS out of that - but only cosmetical */
    STACK_OF(CRMF_ATTRIBUTETYPEANDVALUE) *controls;
} /* CRMF_CERTREQUEST */;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTREQUEST)
CRMF_CERTREQUEST *CRMF_CERTREQUEST_dup(CRMF_CERTREQUEST *atav);

/* TODO: isn't there a better way to have this for ANY type? */
struct crmf_attributetypeandvalue_st {
    ASN1_OBJECT *type;
    union {
        /* NID_id_regCtrl_regToken */
        ASN1_UTF8STRING *regToken;

        /* NID_id_regCtrl_authenticator */
        ASN1_UTF8STRING *authenticator;

        /* NID_id_regCtrl_pkiPublicationInfo */
        CRMF_PKIPUBLICATIONINFO *pkiPublicationInfo;

        /* NID_id_regCtrl_pkiArchiveOptions */
        CRMF_PKIARCHIVEOPTIONS *pkiArchiveOptions;

        /* NID_id_regCtrl_oldCertID */
        CRMF_CERTID *oldCertID;

        /* NID_id_regCtrl_protocolEncrKey */
        X509_PUBKEY *protocolEncrKey;

        /* NID_id_regInfo_utf8Pairs */
        ASN1_UTF8STRING *utf8Pairs;

        /* NID_id_regInfo_certReq */
        CRMF_CERTREQUEST *certReq;

        ASN1_TYPE *other;
    } value;
} /* CRMF_ATTRIBUTETYPEANDVALUE */;
DECLARE_ASN1_FUNCTIONS(CRMF_ATTRIBUTETYPEANDVALUE)
DEFINE_STACK_OF(CRMF_ATTRIBUTETYPEANDVALUE)
CRMF_ATTRIBUTETYPEANDVALUE *CRMF_ATTRIBUTETYPEANDVALUE_dup(
                                              CRMF_ATTRIBUTETYPEANDVALUE *atav);

/*
 * CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
 * CertReqMsg ::= SEQUENCE {
 * certReq   CertRequest,
 * popo           ProofOfPossession  OPTIONAL,
 * -- content depends upon key type
 * regInfo   SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL }
 */
struct crmf_certreqmsg_st {
    CRMF_CERTREQUEST *certReq;
    /* 0 */
    CRMF_PROOFOFPOSSESION *popo;
    /* 1 */
    STACK_OF(CRMF_ATTRIBUTETYPEANDVALUE) *regInfo;
} /* CRMF_CERTREQMSG */;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTREQMSG)
/* DEFINE_STACK_OF(CRMF_CERTREQMSG) */


# ifdef  __cplusplus
}
# endif
#endif
