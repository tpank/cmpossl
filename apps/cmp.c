/*
 * ====================================================================
 * Written by Miikka Viljanen, based on cmpclient by Martin Peylo
 */
/*
 * ====================================================================
 * Copyright (c) 2007-2010 The OpenSSL Project.  All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software must
 * display the following acknowledgment: "This product includes software developed
 * by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 * endorse or promote products derived from this software without prior written
 * permission. For written permission, please contact openssl-core@openssl.org.
 * 5. Products derived from this software may not be called "OpenSSL" nor may
 * "OpenSSL" appear in their names without prior written permission of the
 * OpenSSL Project.
 * 6. Redistributions of any form whatsoever must retain the
 * following acknowledgment: "This product includes software developed by the
 * OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY EXPRESSED
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 * EVENT SHALL THE OpenSSL PROJECT OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim Hudson
 * (tjh@cryptsoft.com).
 */
/*
 * ====================================================================
 * Copyright 2012-2014 Nokia Oy. ALL RIGHTS RESERVED. CMP support in OpenSSL
 * originally developed by Nokia for contribution to the OpenSSL project.
 */

#include <openssl/opensslconf.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "apps.h"
#include "s_apps.h"

#if OPENSSL_VERSION_NUMBER < 0x1010001fL
#define X509_STORE_CTX_set0_verified_chain(ctx, sk) { \
        sk_X509_pop_free((ctx)->chain, X509_free); (ctx)->chain = (sk); }
#define X509_STORE_CTX_get_check_revocation(ctx) ((ctx)->check_revocation)
#define X509_STORE_get_check_revocation(store) ((store)->check_revocation)
#define X509_STORE_set_check_revocation(store,f){(store)->check_revocation=(f);}
#endif

static char *opt_config = NULL;
#define CONFIG_FILE "openssl.cnf"
#define CMP_SECTION "cmp"
#define DEFAULT_SECTION "default"
static char *opt_section = CMP_SECTION;
#define HTTP_HDR "http://"

#undef PROG
#define PROG    cmp_main
char *prog = "cmp";

#include <openssl/crypto.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

static CONF *conf = NULL;       /* OpenSSL config file context structure */
static BIO *bio_c_out = NULL;   /* OpenSSL BIO for printing to STDOUT */

/* a copy from apps.c just for visibility reasons, TODO DvO remove when setup_engine_no_default() has been integrated */
#ifndef OPENSSL_NO_ENGINE
/* Try to load an engine in a shareable library */
static ENGINE *try_load_engine(const char *engine)
{
    ENGINE *e = ENGINE_by_id("dynamic");
    if (e) {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}
#endif
#if !defined(OPENSSL_NO_UI) || !defined(OPENSSL_NO_ENGINE)
static UI_METHOD *ui_method = NULL;
#endif

/* an adapted copy of setup_engine() from apps.c, TODO DvO integrate there */
static ENGINE *setup_engine_no_default(const char *engine, int debug)
{
    ENGINE *e = NULL;

#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (strcmp(engine, "auto") == 0) {
            BIO_printf(bio_err, "enabling auto ENGINE support\n");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(engine)) == NULL
            && (e = try_load_engine(engine)) == NULL) {
            BIO_printf(bio_err, "invalid engine \"%s\"\n", engine);
            ERR_print_errors(bio_err);
            return NULL;
        }
        if (debug) {
            ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, bio_err, 0);
        }
        ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ui_method, 0, 1);
#if 0
        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            BIO_printf(bio_err, "can't use that engine\n");
            ERR_print_errors(bio_err);
            ENGINE_free(e);
            return NULL;
        }
#endif

        BIO_printf(bio_err, "engine \"%s\" set.\n", ENGINE_get_id(e));
    }
#endif
    return e;
}

/*
 * the type of cmp command we want to send
 */
typedef enum {
    CMP_IR,
    CMP_KUR,
    CMP_CR,
    CMP_P10CR,
    CMP_RR,
    CMP_GENM
} cmp_cmd_t;

static char *opt_server = NULL;
static int   server_port = 8080;

static char *opt_proxy = NULL;
static int   proxy_port = 8080;

static int   opt_msgtimeout = -1;
static int   opt_maxpolltime = -1;

static int   opt_use_tls = 0;
static char *opt_tls_cert = NULL;
static char *opt_tls_key = NULL;
static char *opt_tls_keypass = NULL;
static char *opt_tls_trusted = NULL;
static char *opt_tls_host = NULL;

static char *opt_path = "/";
static char *opt_cmd_s = NULL;
static int opt_cmd = -1;

static char *opt_ref = NULL;
static char *opt_secret = NULL;
static char *opt_cert = NULL;
static char *opt_key = NULL;
static char *opt_keypass = NULL;
static char *opt_extracerts = NULL;

static char *opt_certout = NULL;
static char *opt_out_trusted = NULL;
static X509_STORE *out_trusted = NULL;

static char *opt_srvcert = NULL;
static char *opt_trusted = NULL;
static char *opt_untrusted = NULL;
static int opt_ignore_keyusage = 0;

static int opt_crl_download = 0;
static char *opt_crls = NULL;
static int opt_crl_timeout = 10;
static X509_VERIFY_PARAM *vpm = NULL;

#ifndef OPENSSL_NO_OCSP
#include <openssl/ocsp.h>
static int   opt_ocsp_check_all = 0;
static int   opt_ocsp_use_aia = 0;
static char *opt_ocsp_url = NULL;
static int   opt_ocsp_timeout = 10;
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
typedef int (*X509_STORE_CTX_check_revocation_fn)(X509_STORE_CTX *ctx);
#define X509_V_ERR_OCSP_VERIFY_NEEDED 73  /* Need OCSP verification */
#define X509_V_ERR_OCSP_VERIFY_FAILED 74  /* Couldn't verify cert through OCSP*/
#endif
X509_STORE_CTX_check_revocation_fn check_revocation = NULL;
static int opt_ocsp_status = 0; /* unset if OPENSSL_VERSION_NUMBER<0x10100000L*/
#define OCSP_USE_UNTRUSTED_CERTS
#ifdef OCSP_USE_UNTRUSTED_CERTS
static STACK_OF(X509) *ocsp_untrusted_certs = NULL;
#endif
#endif

static char *opt_storepass = NULL;
static char *opt_storeform_s = "PEM";
static char *opt_certform_s = "PEM";
static char *opt_keyform_s = "PEM";
static char *opt_crlform_s = "PEM";
static int opt_storeform = FORMAT_PEM;
static int opt_certform = FORMAT_PEM;
static int opt_keyform = FORMAT_PEM;
static int opt_crlform = FORMAT_PEM;

static char *opt_newkey = NULL;
static char *opt_newkeypass = NULL;
static char *opt_subject = NULL;
static char *opt_issuer = NULL;
static int   opt_days = 0;
static char *opt_recipient = NULL;
static char *opt_expected_sender = NULL;
static int   opt_popo = -1;
static char *opt_reqexts = NULL;
static int opt_disableConfirm = 0;
static int opt_implicitConfirm = 0;
static int opt_unprotectedRequests = 0;
static int opt_unprotectedErrors = 0;
static char *opt_digest = NULL;
static char *opt_oldcert = NULL;
static char *opt_csr = NULL;
static int   opt_revreason = CRL_REASON_NONE;

static char *opt_cacertsout = NULL;
static char *opt_extracertsout = NULL;

static char *opt_infotype_s = NULL;
static int   opt_infotype = NID_undef;
static char *opt_geninfo = NULL;
#ifndef OPENSSL_NO_ENGINE
static char *opt_engine = NULL;
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
int cmp_main(int argc, char *argv[]);
const char OPT_HELP_STR[] = "--";
const char OPT_MORE_STR[] = "---";
typedef struct options_st {
    const char *name;
    int retval;
    /*
     * value type: - no value (also the value zero), n number, p positive
     * number, u unsigned, l long, s string, < input file, > output file,
     * f any format, F der/pem format , E der/pem/engine format identifier.
     * l, n and u include zero; p does not.
     */
    int valtype;
    const char *helpstr;
} OPTIONS;

/*
 * Common verification options.
 */
# define OPT_V_ENUM \
        OPT_V__FIRST=2000, \
        OPT_V_POLICY, OPT_V_PURPOSE, OPT_V_VERIFY_NAME, OPT_V_VERIFY_DEPTH, \
        OPT_V_ATTIME, OPT_V_VERIFY_HOSTNAME, OPT_V_VERIFY_EMAIL, \
        OPT_V_VERIFY_IP, OPT_V_IGNORE_CRITICAL, OPT_V_ISSUER_CHECKS, \
        OPT_V_CRL_CHECK, OPT_V_CRL_CHECK_ALL, OPT_V_POLICY_CHECK, \
        OPT_V_EXPLICIT_POLICY, OPT_V_INHIBIT_ANY, OPT_V_INHIBIT_MAP, \
        OPT_V_X509_STRICT, OPT_V_EXTENDED_CRL, OPT_V_USE_DELTAS, \
        OPT_V_POLICY_PRINT, OPT_V_CHECK_SS_SIG, OPT_V_TRUSTED_FIRST, \
        OPT_V_SUITEB_128_ONLY, OPT_V_SUITEB_128, OPT_V_SUITEB_192, \
        OPT_V_PARTIAL_CHAIN, OPT_V_NO_ALT_CHAINS, OPT_V_NO_CHECK_TIME, \
        OPT_V_VERIFY_AUTH_LEVEL, OPT_V_ALLOW_PROXY_CERTS, \
        OPT_V__LAST

# define OPT_V_OPTIONS \
        { "policy", OPT_V_POLICY, 's', "adds policy to the acceptable policy set"}, \
        { "purpose", OPT_V_PURPOSE, 's', \
            "certificate chain purpose"}, \
        { "verify_name", OPT_V_VERIFY_NAME, 's', "verification policy name"}, \
        { "verify_depth", OPT_V_VERIFY_DEPTH, 'n', \
            "chain depth limit" }, \
        { "auth_level", OPT_V_VERIFY_AUTH_LEVEL, 'n', \
            "chain authentication security level" }, \
        { "attime", OPT_V_ATTIME, 'M', "verification epoch time" }, \
        { "verify_hostname", OPT_V_VERIFY_HOSTNAME, 's', \
            "expected peer hostname" }, \
        { "verify_email", OPT_V_VERIFY_EMAIL, 's', \
            "expected peer email" }, \
        { "verify_ip", OPT_V_VERIFY_IP, 's', \
            "expected peer IP address" }, \
        { "ignore_critical", OPT_V_IGNORE_CRITICAL, '-', \
            "permit unhandled critical extensions"}, \
        { "issuer_checks", OPT_V_ISSUER_CHECKS, '-', "(deprecated)"}, \
        { "crl_check", OPT_V_CRL_CHECK, '-', "check leaf certificate revocation" }, \
        { "crl_check_all", OPT_V_CRL_CHECK_ALL, '-', "check full chain revocation" }, \
        { "policy_check", OPT_V_POLICY_CHECK, '-', "perform rfc5280 policy checks"}, \
        { "explicit_policy", OPT_V_EXPLICIT_POLICY, '-', \
            "set policy variable require-explicit-policy"}, \
        { "inhibit_any", OPT_V_INHIBIT_ANY, '-', \
            "set policy variable inhibit-any-policy"}, \
        { "inhibit_map", OPT_V_INHIBIT_MAP, '-', \
            "set policy variable inhibit-policy-mapping"}, \
        { "x509_strict", OPT_V_X509_STRICT, '-', \
            "disable certificate compatibility work-arounds"}, \
        { "extended_crl", OPT_V_EXTENDED_CRL, '-', \
            "enable extended CRL features"}, \
        { "use_deltas", OPT_V_USE_DELTAS, '-', \
            "use delta CRLs"}, \
        { "policy_print", OPT_V_POLICY_PRINT, '-', \
            "print policy processing diagnostics"}, \
        { "check_ss_sig", OPT_V_CHECK_SS_SIG, '-', \
            "check root CA self-signatures"}, \
        { "trusted_first", OPT_V_TRUSTED_FIRST, '-', \
            "search trust store first (default)" }, \
        { "suiteB_128_only", OPT_V_SUITEB_128_ONLY, '-', "Suite B 128-bit-only mode"}, \
        { "suiteB_128", OPT_V_SUITEB_128, '-', \
            "Suite B 128-bit mode allowing 192-bit algorithms"}, \
        { "suiteB_192", OPT_V_SUITEB_192, '-', "Suite B 192-bit-only mode" }, \
        { "partial_chain", OPT_V_PARTIAL_CHAIN, '-', \
            "accept chains anchored by intermediate trust-store CAs"}, \
        { "no_alt_chains", OPT_V_NO_ALT_CHAINS, '-', "(deprecated)" }, \
        { "no_check_time", OPT_V_NO_CHECK_TIME, '-', "ignore certificate validity time" }, \
        { "allow_proxy_certs", OPT_V_ALLOW_PROXY_CERTS, '-', "allow the use of proxy certificates" }
#endif

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_CONFIG, OPT_SECTION,

    OPT_SERVER, OPT_PROXY, OPT_PATH,
    OPT_MSGTIMEOUT, OPT_MAXPOLLTIME,

    OPT_RECIPIENT, OPT_EXPECTED_SENDER, OPT_SRVCERT,
    OPT_TRUSTED, OPT_UNTRUSTED, OPT_IGNORE_KEYUSAGE,

    OPT_REF, OPT_SECRET, OPT_CERT, OPT_KEY, OPT_KEYPASS, OPT_EXTRACERTS,

    OPT_CMD, OPT_GENINFO, OPT_DIGEST,
    OPT_UNPROTECTEDREQUESTS, OPT_UNPROTECTEDERRORS,
    OPT_EXTRACERTSOUT, OPT_CACERTSOUT,

    OPT_NEWKEY, OPT_NEWKEYPASS, OPT_SUBJECT, OPT_ISSUER,
    OPT_DAYS, OPT_REQEXTS, OPT_POPO,
    OPT_IMPLICITCONFIRM, OPT_DISABLECONFIRM,
    OPT_CERTOUT, OPT_OUT_TRUSTED,

    OPT_OLDCERT, OPT_CSR, OPT_REVREASON, OPT_INFOTYPE,

    OPT_STOREPASS, OPT_STOREFORM, OPT_CERTFORM, OPT_KEYFORM, OPT_CRLFORM,
#ifndef OPENSSL_NO_ENGINE
    OPT_ENGINE,
#endif

    OPT_USETLS, OPT_TLSCERT, OPT_TLSKEY, OPT_TLSKEYPASS,
    OPT_TLSTRUSTED, OPT_TLSHOST,

    OPT_CRL_DOWNLOAD, OPT_CRLS, OPT_CRL_TIMEOUT,
#ifndef OPENSSL_NO_OCSP
    OPT_OCSP_CHECK_ALL,
    OPT_OCSP_USE_AIA,
    OPT_OCSP_URL,
    OPT_OCSP_TIMEOUT,
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPT_OCSP_STATUS,
#endif
#endif
    OPT_V_ENUM/* OPT_CRLALL etc. */
} OPTION_CHOICE;

#if OPENSSL_VERSION_NUMBER >= 0x1010001fL
const
#endif
OPTIONS cmp_options[] = {
    /* OPTION_CHOICE values must be in the same order as enumerated above!! */
    {"help", OPT_HELP, '-', "Display this summary"},
    {"config", OPT_CONFIG, 's', "Configuration file to use; \"\" means none. Default from env variable 'OPENSSL_CONF'"},
    {"section", OPT_SECTION, 's', "Section in config file defining CMP options. \"\" means 'default'. Default 'cmp'"},

    {OPT_MORE_STR, 0, 0, "\nMessage transfer options:"},
    {"server", OPT_SERVER, 's', "'address[:port]' of CMP server. Port default 8080"},
    {"proxy", OPT_PROXY, 's', "'address[:port]' of HTTP proxy, if needed for CMP server. Port default 8080"},
    {"path", OPT_PATH, 's', "HTTP path location inside the server (aka CMP alias). Default '/'"},
    {"msgtimeout", OPT_MSGTIMEOUT, 'n', "Timeout per CMP message round trip (or 0 for none). Default 120 seconds"},
    {"maxpolltime", OPT_MAXPOLLTIME, 'n', "Maximum total number of seconds to poll for certificates (default: 0 = infinite)"},

    {OPT_MORE_STR, 0, 0, "\nRecipient options:"},
    {"recipient", OPT_RECIPIENT, 's', "Distinguished Name of the recipient to use unless the -srvcert option is given."},
    {"expected_sender", OPT_EXPECTED_SENDER, 's', "Distinguished Name of expected response sender. Defaults to recipient determined."},
    {"srvcert", OPT_SRVCERT, 's', "Specific CMP server cert to use and trust directly when verifying responses"},
    {"trusted", OPT_TRUSTED, 's', "Trusted CA certs to use for CMP server authentication when verifying responses,"},
             {OPT_MORE_STR, 0, 0, "unless -srvcert is given"},
    {"untrusted", OPT_UNTRUSTED, 's', "Intermediate certificates for constructing chains for CMP, TLS, and/or CA servers"},
    {"ignore_keyusage", OPT_IGNORE_KEYUSAGE, '-', "Ignore CMP-level cert key usage, else 'digitalSignature' needed for signatures"},

    {OPT_MORE_STR, 0, 0, "\nSender options:"},
    {"ref", OPT_REF, 's', "Reference value for client authentication with a pre-shared key"},
    {"secret", OPT_SECRET, 's', "Password source for client authentication with a pre-shared key (secret)"},
    {"cert", OPT_CERT, 's', "Client's current certificate (needed unless using PSK)"},
    {"key", OPT_KEY, 's', "Private key for the client's current certificate"},
    {"keypass", OPT_KEYPASS, 's', "Client private key pass phrase source"},
    {"extracerts", OPT_EXTRACERTS, 's', "Certificates to append in extraCerts field when signing requests"},

    {OPT_MORE_STR, 0, 0, "\nGeneric message options:"},
    {"cmd", OPT_CMD, 's', "CMP request to send: ir/cr/kur/p10cr/rr/genm"},
    {"geninfo", OPT_GENINFO, 's', "Set generalInfo in request PKIHeader with type and integer value"},
             {OPT_MORE_STR, 0, 0, "given in the form <OID>:int:<n>, e.g., '1.2.3:int:987'"},
    {"digest", OPT_DIGEST, 's', "Digest to use in message protection and POPO signatures. Default 'sha256'"},
    {"unprotectedrequests", OPT_UNPROTECTEDREQUESTS, '-', "Send messages without CMP-level protection"},
    {"unprotectederrors", OPT_UNPROTECTEDERRORS, '-',
                          "Accept unprotected error responses: regular error messages as well as"},
     {OPT_MORE_STR, 0, 0, "negative certificate responses (ip/cp/kup) and revocation responses (rp)."},
     {OPT_MORE_STR, 0, 0, "WARNING: This setting leads to behaviour allowing violation of RFC 4210."},
    {"extracertsout", OPT_EXTRACERTSOUT, 's', "File to save received extra certificates"},
    {"cacertsout", OPT_CACERTSOUT, 's', "File to save received CA certificates"},

    {OPT_MORE_STR, 0, 0, "\nCertificate request options:"},
    {"newkey", OPT_NEWKEY, 's', "Private key for the requested certificate, defaulting to current client's key."},
    {"newkeypass", OPT_NEWKEYPASS, 's', "New private key pass phrase source"},
    {"subject", OPT_SUBJECT, 's', "X509 subject name to use in the requested certificate template"},
    {"issuer", OPT_ISSUER, 's', "Distinguished Name of the issuer, to be put in the requested certificate template."},
           {OPT_MORE_STR, 0, 0, "Also used as recipient if neither -recipient nor -srvcert are given."},
    {"days", OPT_DAYS, 'n', "Number of days the new certificate is asked to be valid for"},
    {"reqexts", OPT_REQEXTS, 's', "Name of section in OpenSSL config file defining certificate request extensions"},
    {"popo", OPT_POPO, 'n', "Set Proof-of-Possession (POPO) method."},
       {OPT_MORE_STR, 0, 0, "0 = NONE, 1 = SIGNATURE (default), 2 = ENCRCERT, 3 = RAVERIFIED"},
    {"implicitconfirm", OPT_IMPLICITCONFIRM, '-', "Request implicit confirmation of newly enrolled certificate"},
    {"disableconfirm", OPT_DISABLECONFIRM, '-', "Do not confirm newly enrolled certificate"},
                           {OPT_MORE_STR, 0, 0, "WARNING: This setting leads to behavior violating RFC 4210."},
    {"certout", OPT_CERTOUT, 's', "File to save the newly enrolled certificate"},
    {"out-trusted", OPT_OUT_TRUSTED, 's', "Trusted certificates to use for verifying the newly enrolled certificate"},

    {OPT_MORE_STR, 0, 0, "\nMisc request options:"},

    {"oldcert", OPT_OLDCERT, 's', "Certificate to be updated in kur (defaulting to -cert) or to be revoked in rr."},
             {OPT_MORE_STR, 0, 0, "Its issuer is used as recipient if neither -srvcert, -recipient, -issuer given."},
    {"csr", OPT_CSR, 's', "PKCS#10 CSR to use in p10cr"},
    {"revreason", OPT_REVREASON, 'n', "Set reason code to be included in revocation request (rr)."},
                 {OPT_MORE_STR, 0, 0, "Values: 0..10 (see RFC5280, 5.3.1) or -1 for none (default)"},
    {"infotype", OPT_INFOTYPE, 's', "InfoType name for requesting specific info in genm, e.g., 'signKeyPairTypes'"},

    {OPT_MORE_STR, 0, 0, "\nCredential format options:"},
    {"storepass", OPT_STOREPASS, 's', "Certificate store password (may be needed with -trusted, -out-trusted, etc.)"},
    {"storeform", OPT_STOREFORM, 's', "Format (PEM/DER/P12) to try first when reading certificate store files. Default PEM."},
    {"certform", OPT_CERTFORM, 's', "Format (PEM/DER/P12) to try first when reading certificate files. Default PEM."},
               {OPT_MORE_STR, 0, 0, "This also determines format to use for writing (not supported for P12)"},
    {"keyform", OPT_KEYFORM, 's', "Format (PEM/DER/P12) to try first when reading key files. Default PEM"},
    {"crlform", OPT_CRLFORM, 's', "Format (PEM/DER) to try first when reading CRL files. Default PEM"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use crypto engine with given identifier, possibly a hardware device."},
           {OPT_MORE_STR, 0, 0, "Engines may be defined in OpenSSL config file engine section."},
           {OPT_MORE_STR, 0, 0, "Options like -key specifying keys held in the engine can give key identifiers"},
           {OPT_MORE_STR, 0, 0, "prefixed by 'engine:', e.g., '-key engine:pkcs11:object=mykey;pin-value=1234'"},
#endif

    {OPT_MORE_STR, 0, 0, "\nTLS options:"},
    {"tls-used", OPT_USETLS, '-', "Force using TLS (even when other TLS options are not set) connecting to server"},
    {"tls-cert", OPT_TLSCERT, 's', "Client's TLS certificate. May include certificate chain to be provided to server"},
    {"tls-key", OPT_TLSKEY, 's', "Private key for the client's TLS certificate"},
    {"tls-keypass", OPT_TLSKEYPASS, 's', "Pass phrase source for the client's private TLS key"},
    {"tls-trusted", OPT_TLSTRUSTED, 's', "Trusted certificates to use for verifying the TLS server certificate."},
                    {OPT_MORE_STR, 0, 0, "This implies host name validation"},
    {"tls-host", OPT_TLSHOST, 's', "Address to be checked (rather than -server) during TLS host name validation"},

    {OPT_MORE_STR, 0, 0, "\nCertificate verification options, for both CMP and TLS:"},
    {"crl_download", OPT_CRL_DOWNLOAD, '-', "Retrieve CRLs from distribution points given in certificates as primary source"},
    {"crls", OPT_CRLS, 's', "Use given CRL(s) as secondary (fallback) source when verifying certificates."},
       {OPT_MORE_STR, 0, 0, "URL may start with 'http:' or point to local file (possibly prefixed by 'file:')."},
    {OPT_MORE_STR, 0, 0, "Note: -crl_download, -crls, and -crl_check require certificate status checking"},
    {OPT_MORE_STR, 0, 0, "for at least the leaf certificate using CRLs unless OCSP is enabled and succeeds."},
    {OPT_MORE_STR, 0, 0, "-crl_check_all requires revocation checks using CRLs for full certificate chain."},
    {"crl_timeout", OPT_CRL_TIMEOUT, 'n', "Request timeout for online CRL retrieval (or 0 for none). Default 10 seconds"},
#ifndef OPENSSL_NO_OCSP
    {"ocsp_check_all", OPT_OCSP_CHECK_ALL, '-', "Require revocation checks (via OCSP) for full certificate chain"},
    {"ocsp_use_aia", OPT_OCSP_USE_AIA, '-', "Use OCSP with AIA entries in certificates as primary URL of OCSP responder"},
    {"ocsp_url", OPT_OCSP_URL, 's', "Use OCSP with given URL as secondary (fallback) URL of OCSP responder."},
    {OPT_MORE_STR, 0, 0, "Note: -ocsp_use_aia and -ocsp_url require certificate status checking"},
    {OPT_MORE_STR, 0, 0, "for at least the leaf certificate using OCSP, with CRLs as fallback if enabled."},
    {"ocsp_timeout", OPT_OCSP_TIMEOUT, 'n', "Timeout for retrieving OCSP responses (or 0 for none). Default 10 seconds"},
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    {"ocsp_status", OPT_OCSP_STATUS, '-', "Enable certificate status from TLS server via OCSP (not multi-)stapling"},
#endif
#endif
    OPT_V_OPTIONS, /* subsumes: {"crl_check_all", OPT_CRLALL, '-', "Check CRLs not only for leaf certificate but for full certificate chain"}, */

    {NULL}
};

typedef union {
    char **txt;
    int *num;
    long *num_long;
} varref;
static varref cmp_vars[]= { /* must be in the same order as enumerated above!! */
    {&opt_config}, {&opt_section},

    {&opt_server}, {&opt_proxy}, {&opt_path},
    { (char **)&opt_msgtimeout}, { (char **)&opt_maxpolltime},

    {&opt_recipient}, {&opt_expected_sender}, {&opt_srvcert},
    {&opt_trusted}, {&opt_untrusted}, { (char **)&opt_ignore_keyusage},

    {&opt_ref}, {&opt_secret}, {&opt_cert}, {&opt_key}, {&opt_keypass},
    {&opt_extracerts},

    {&opt_cmd_s}, {&opt_geninfo}, {&opt_digest},
    { (char **)&opt_unprotectedRequests}, { (char **)&opt_unprotectedErrors},
    {&opt_extracertsout}, {&opt_cacertsout},

    {&opt_newkey}, {&opt_newkeypass}, {&opt_subject}, {&opt_issuer},
    { (char **)&opt_days}, {&opt_reqexts}, { (char **)&opt_popo},
    { (char **)&opt_implicitConfirm}, { (char **)&opt_disableConfirm},
    {&opt_certout}, {&opt_out_trusted},

    {&opt_oldcert}, {&opt_csr}, { (char **)&opt_revreason}, {&opt_infotype_s},

    {&opt_storepass},
    {&opt_storeform_s}, {&opt_certform_s}, {&opt_keyform_s}, {&opt_crlform_s},
#ifndef OPENSSL_NO_ENGINE
    {&opt_engine},
#endif

    { (char **)&opt_use_tls}, {&opt_tls_cert}, {&opt_tls_key}, {&opt_tls_keypass},
    {&opt_tls_trusted}, {&opt_tls_host},

    { (char **)&opt_crl_download}, {&opt_crls}, { (char **)&opt_crl_timeout},
#ifndef OPENSSL_NO_OCSP
    { (char **)&opt_ocsp_check_all}, { (char **)&opt_ocsp_use_aia}, {&opt_ocsp_url},
    { (char **)&opt_ocsp_timeout},
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    { (char **)&opt_ocsp_status},
#endif
#endif
    /* virtually at this point: OPT_CRLALL etc. */
    {NULL}
};

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void opt_help(const OPTIONS *unused_arg) {
    const int ALIGN_COL = 22;
    const OPTIONS *opt;
    int i=0,j=0;
    BIO_printf(bio_err, "\nusage: openssl %s args\n", prog);
    for (i=0, opt=cmp_options; opt->name; i++, opt++) {
        int initlen;
        if (!strcmp(opt->name, OPT_MORE_STR))
            initlen = 0;
        else {
            BIO_printf(bio_err, " -%s", opt->name);
            initlen = 2 + strlen(opt->name);
        }
        for (j=ALIGN_COL-initlen; j > 0; j--)
            BIO_puts(bio_err, " ");
        BIO_printf(bio_err, " %s\n", opt->helpstr);
    }
    BIO_puts(bio_err, "\n");
}
#endif

/*
 * ##########################################################################
 * use the command line option table to read values from the CMP section
 * of openssl.cnf.  Defaults are taken from the config file, they can be
 * overwritten on the command line.
 * ##########################################################################
 */
static int read_config()
{
    unsigned int i;
    long num = 0;
    char *txt = NULL;
    const OPTIONS *opt;
    int verification_option;

    /* starting with offset OPT_SECTION because OPT_CONFIG and OPT_SECTION would
       not make sense within the config file. They have already been handled. */
    for (i = OPT_SECTION-OPT_HELP, opt = &cmp_options[OPT_SECTION];
         opt->name; i++, opt++) {
        if (!strcmp(opt->name, OPT_HELP_STR) || !strcmp(opt->name, OPT_MORE_STR)) {
            i--;
            continue;
        }
        verification_option = (OPT_V__FIRST <= opt->retval && opt->retval < OPT_V__LAST); /* OPT_CRLALL etc. */
        if (verification_option)
            i--;
        if (cmp_vars[i].txt == NULL) {
            BIO_printf(bio_err, "internal error: cmp_vars array too short, i=%d\n", i);
            return 0;
        }
        switch (opt->valtype) {
        case '-':
        case 'n':
        case 'l':
            if (!NCONF_get_number_e(conf, opt_section, opt->name, &num)) {
                ERR_clear_error();
                continue; /* option not provided */
            }
            break;
        case '<': /* do not use '<' in cmp_options. Incorrect treatment
                     somewhere in args_verify() can wrongly set badops = 1 */
        case 's':
        case 'M':
            txt = NCONF_get_string(conf, opt_section, opt->name);
            if (txt == NULL) {
                ERR_clear_error();
                continue; /* option not provided */
            }
            break;
        default:
            BIO_printf(bio_err, "internal error: unsupported type '%c' for option '%s'\n", opt->valtype, opt->name);
            return 0;
            break;
        }
        if (verification_option) {
            int conf_argc = 1;
            char *conf_argv[3];
            char arg1[82];
            BIO_snprintf(arg1, 81, "-%s", (char *)opt->name);
            conf_argv[0] = ""; /* dummy prog name */
            conf_argv[1] = arg1;
            if (opt->valtype == '-') {
                if (num != 0)
                    conf_argc = 2;
            } else {
                conf_argc = 3;
                conf_argv[2] = NCONF_get_string(conf, opt_section, opt->name); /* not NULL */
            }
            if (conf_argc > 1) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                (void)opt_init(conf_argc, conf_argv, cmp_options);
                if (!opt_verify(opt_next(), vpm))
#else
                char **conf_argvp = conf_argv+1;
                int badops = 0;
                (void)args_verify(&conf_argvp, &conf_argc, &badops, bio_err, &vpm);
                if (badops)
#endif
                {
                    BIO_printf(bio_err, "error for option '%s' in config file section '%s'\n", opt->name, opt_section);
                    return 0;
                }
            }
        } else {
            switch (opt->valtype) {
                case '-':
                case 'n':
                    if (num < INT_MIN || INT_MAX < num) {
                        BIO_printf(bio_err, "integer value out of range for option '%s'\n", opt->name);
                        return 0;
                    }
                    *cmp_vars[i].num = (int)num;
                    break;
                case 'l':
                    *cmp_vars[i].num_long = num;
                    break;
                default:
                    if (txt != NULL && txt[0] == '\0')
                        txt = NULL; /* reset option on empty string input */
                    *cmp_vars[i].txt = txt;
                    break;
            }
        }
    }

    return 1;
}

/*
 * ##########################################################################
 * * code for loading certs, keys, and CRLs
 * TODO dvo: the whole Cert, Key and CRL loading logic should be given upstream
 * to be included in apps.c, and then used from here.
 * ##########################################################################
 */

/* TODO dvo: push that separately upstream with the autofmt options */
/* declaration copied from apps/apps.c just for visibility reasons */
static int load_pkcs12(BIO *in, const char *desc,
                       pem_password_cb *pem_cb, void *cb_data,
                       EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    const char *pass;
    char tpass[PEM_BUFSIZE];
    int len, ret = 0;
    PKCS12 *p12;
    p12 = d2i_PKCS12_bio(in, NULL);
    if (p12 == NULL) {
        BIO_printf(bio_err, "Error loading PKCS12 file for %s\n", desc);
        goto die;
    }
    /* See if an empty password will do */
    if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0))
        pass = "";
    else {
        if (!pem_cb)
            pem_cb = (pem_password_cb *)password_callback;
        len = pem_cb(tpass, PEM_BUFSIZE, 0, cb_data);
        if (len < 0) {
            BIO_printf(bio_err, "Passphrase callback error for %s\n", desc);
            goto die;
        }
        if (len < PEM_BUFSIZE)
            tpass[len] = 0;
        if (!PKCS12_verify_mac(p12, tpass, len)) {
            BIO_printf(bio_err,
                       "Mac verify error (wrong password?) in PKCS12 file for %s\n",
                       desc);
            goto die;
        }
        pass = tpass;
    }
    ret = PKCS12_parse(p12, pass, pkey, cert, ca);
 die:
    PKCS12_free(p12);
    return ret;
}

/* TODO dvo: push that separately upstream with the autofmt options */
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
/* adapted from apps/apps.c to include connection timeout */
static int load_cert_crl_http_timeout(const char *url, int req_timeout, X509 **pcert, X509_CRL **pcrl)
{
    char *host = NULL, *port = NULL, *path = NULL;
    BIO *bio = NULL;
    OCSP_REQ_CTX *rctx = NULL;
    int use_ssl, rv = 0;
    time_t max_time = req_timeout > 0 ? time(NULL) + req_timeout : 0;

    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl))
        goto err;
    if (use_ssl) {
        BIO_puts(bio_err, "https not supported\n");
        goto err;
    }
    bio = BIO_new_connect(host);
    if (!bio || !BIO_set_conn_port(bio, port))
        goto err;

    if (bio_connect(bio, req_timeout) <= 0)
        goto err;

    rctx = OCSP_REQ_CTX_new(bio, 1024);
    if (rctx == NULL)
        goto err;
    if (!OCSP_REQ_CTX_http(rctx, "GET", path))
        goto err;
    if (!OCSP_REQ_CTX_add1_header(rctx, "Host", host))
        goto err;

    rv = bio_http(bio, rctx, pcert ? (http_fn)X509_http_nbio : (http_fn)X509_CRL_http_nbio,
                             pcert ? (ASN1_VALUE **)pcert : (ASN1_VALUE **)pcrl, max_time);

 err:
    OPENSSL_free(host);
    OPENSSL_free(path);
    OPENSSL_free(port);
    if (bio)
        BIO_free_all(bio);
    OCSP_REQ_CTX_free(rctx);
    if (rv != 1) {
        BIO_printf(bio_err, "%s loading %s from '%s'\n",
                   rv == 0 ? "Timeout" : rv == -1 ? "Parse Error" : "Transfer error",
                   pcert ? "certificate" : "CRL", url);
        ERR_print_errors(bio_err);
    }
    return rv;
}
#endif

/* TODO dvo: push that separately upstream with the autofmt options */
/* improved version of load_cert() found in apps/apps.c */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static X509 *load_cert_corrected_pkcs12(const char *file, int format, const char *pass, const char *cert_descrip)
{
    X509 *x = NULL;
    BIO *cert = NULL;
    EVP_PKEY *pkey = NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (format == FORMAT_HTTP) {
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
        load_cert_crl_http_timeout(file, opt_crl_timeout, &x, NULL);
#endif
        goto end;
    }

    if (file == NULL) {
        unbuffer(stdin);
        cert = dup_bio_in(format);
    } else
        cert = bio_open_default(file, 'r', format);
    if (cert == NULL)
        goto end;

    if (format == FORMAT_ASN1)
        x = d2i_X509_bio(cert, NULL);
    else if (format == FORMAT_PEM)
        x = PEM_read_bio_X509_AUX(cert, NULL,
                                  (pem_password_cb *)password_callback, &cb_data);
    else if (format == FORMAT_PKCS12) {
        if (!load_pkcs12(cert, cert_descrip, (pem_password_cb *)password_callback, &cb_data, &pkey, &x, NULL))
            goto end;
    } else {
        BIO_printf(bio_err, "bad input format specified for %s\n", cert_descrip);
        goto end;
    }
 end:
    if (x == NULL) {
        BIO_printf(bio_err, "unable to load certificate\n");
        ERR_print_errors(bio_err);
    }
    BIO_free(cert);
    if (pkey)
        EVP_PKEY_free(pkey);
    return (x);
}
#else
static X509 *load_cert_corrected_pkcs12(const char *file, int format, const char *pass, const char *cert_descrip)
{
    X509 *x = NULL;
    BIO *cert = NULL;

    BIO *err = bio_err;
    EVP_PKEY *pkey = NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (format == FORMAT_HTTP) {
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
        load_cert_crl_http_timeout(file, opt_crl_timeout, &x, NULL);
#endif
        goto end;
    }

    if ((cert = BIO_new(BIO_s_file())) == NULL) {
        ERR_print_errors(err);
        goto end;
    }

    if (file == NULL) {
#ifdef _IONBF
# ifndef OPENSSL_NO_SETVBUF_IONBF
        setvbuf(stdin, NULL, _IONBF, 0);
# endif                         /* ndef OPENSSL_NO_SETVBUF_IONBF */
#endif
        BIO_set_fp(cert, stdin, BIO_NOCLOSE);
    } else {
        if (BIO_read_filename(cert, file) <= 0) {
            BIO_printf(err, "Error opening %s '%s'\n", cert_descrip, file);
            ERR_print_errors(err);
            goto end;
        }
    }

    if (format == FORMAT_ASN1)
        x = d2i_X509_bio(cert, NULL);
    else if (format == FORMAT_NETSCAPE) {
        NETSCAPE_X509 *nx;
        nx = ASN1_item_d2i_bio(ASN1_ITEM_rptr(NETSCAPE_X509), cert, NULL);
        if (nx == NULL)
            goto end;

        if ((strncmp(NETSCAPE_CERT_HDR, (char *)nx->header->data,
                     nx->header->length) != 0)) {
            NETSCAPE_X509_free(nx);
            BIO_printf(err, "Error reading header on certificate\n");
            goto end;
        }
        x = nx->cert;
        nx->cert = NULL;
        NETSCAPE_X509_free(nx);
    } else if (format == FORMAT_PEM)
        x = PEM_read_bio_X509_AUX(cert, NULL,
                                  (pem_password_cb *)password_callback, &cb_data);
    else if (format == FORMAT_PKCS12) {
        if (!load_pkcs12(cert, cert_descrip, (pem_password_cb *)password_callback, &cb_data, &pkey, &x, NULL))
            goto end;
    } else {
        BIO_printf(err, "bad input format specified for %s\n", cert_descrip);
        goto end;
    }
 end:
    if (x == NULL) {
        BIO_printf(err, "unable to load certificate\n");
        ERR_print_errors(err);
    }
    if (cert != NULL)
        BIO_free(cert);
    if (pkey)
        EVP_PKEY_free(pkey);
    return (x);
}
#endif

/* TODO dvo: push that separately upstream */
static X509_REQ *load_csr(const char *file, int format, const char *desc)
{
    X509_REQ *req = NULL;
    BIO *in;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    in = bio_open_default(file, 'r', format);
    if (in == NULL)
        goto end;
#else
    in = BIO_new(BIO_s_file());
    if (in == NULL)
        goto end;
    if (file == NULL)
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
    else {
        if (BIO_read_filename(in, file) <= 0) {
            perror(file);
            goto end;
        }
    }
#endif

    if (format == FORMAT_ASN1)
        req = d2i_X509_REQ_bio(in, NULL);
    else if (format == FORMAT_PEM)
        req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
    else if (desc)
        BIO_printf(bio_err, "unsupported format for CSR loading\n");

 end:
    if (req == NULL && desc)
        BIO_printf(bio_err, "unable to load X509 request\n");
    BIO_free(in);
    return req;
}

/* TODO dvo: push that separately upstream with the autofmt options */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L /* compatibility declarations */
static STACK_OF(X509) *load_certs_(const char *file, int format,
                           const char *pass, const char *desc)
{
    STACK_OF(X509) *certs = NULL;
    if (!load_certs(file, &certs, format, pass, desc))
        return NULL;
    return certs;
}
/* TODO dvo: push that separately upstream with the autofmt options */
static STACK_OF(X509_CRL) *load_crls_(const char *file, int format,
                           const char *pass, const char *desc)
{
    STACK_OF(X509_CRL) *crls = NULL;
    if (!load_crls(file, &crls, format, pass, desc))
        return NULL;
    return crls;
}
#define load_crls( bio, file, fmt,        pass, e, desc) load_crls_ (file, fmt,        pass,    desc)
#define load_certs(bio, file, fmt,        pass, e, desc) load_certs_(file, fmt,        pass,    desc)
#define load_cert( bio, file, fmt, stdin,       e, desc) load_cert  (file, fmt,                 desc)
#define load_key(  bio, file, fmt, stdin, pass, e, desc) load_key   (file, fmt, stdin, pass, e, desc)
#endif

/* TODO dvo: push that separately upstream with the autofmt options */
static int adjust_format(const char **infile, int format, int engine_ok) {
    if (!strncmp(*infile, "http://", 7) || !strncmp(*infile, "https://", 8))
        format = FORMAT_HTTP;
    else if (engine_ok && strncmp(*infile, "engine:", 7) == 0) {
        *infile += 7;
        format = FORMAT_ENGINE;
    }
    else {
        if (strncmp(*infile, "file:", 5) == 0)
            *infile += 5;
        /* the following is a heuristic whether first to try PEM or DER or PKCS12 as the input format for files */
        if (strlen(*infile) >= 4) {
            char *extension = (char *)(*infile + strlen(*infile) - 4);
            if (strncmp(extension, ".crt", 4) == 0 ||
                strncmp(extension, ".pem", 4) == 0)
                /* weak recognition of PEM format */
                format = FORMAT_PEM;
            else if (strncmp(extension, ".cer", 4) == 0 ||
                     strncmp(extension, ".der", 4) == 0 ||
                     strncmp(extension, ".crl", 4) == 0)
                /* weak recognition of DER format */
                format = FORMAT_ASN1;
            else if (strncmp(extension, ".p12", 4) == 0)
                /* weak recognition of PKCS#12 format */
                format = FORMAT_PKCS12;
            /* else retain given format */
        }
    }
    return format;
}

static char *get_passwd(const char *pass, const char *desc) {
    char *result = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (!app_passwd(bio_err, (char *)pass, NULL, &result, NULL)) {
#else
    if (!app_passwd((char *)pass, NULL, &result, NULL)) {
#endif
        BIO_printf(bio_err, "Error getting password for %s\n", desc);
    }
    if (pass != NULL && result == NULL) {
        BIO_printf(bio_err, "For compatibility, trying plain input string (better precede with 'pass:')\n");
        result = OPENSSL_strdup(pass);
    }
    return result;
}

#if OPENSSL_VERSION_NUMBER < 0x1010001fL
static void release_engine(ENGINE *e)
{
#ifndef OPENSSL_NO_ENGINE
    if (e != NULL)
        /* Free our "structural" reference. */
        ENGINE_free(e);
#endif
}

 static void OPENSSL_clear_free(void *str, size_t num)
{
    if (str == NULL)
        return;
    if (num)
        OPENSSL_cleanse(str, num);
    CRYPTO_free(str);
}
#endif
/* TODO dvo: push that separately upstream */
/* in apps.c there is load_key which should be used for CMP upstream submission */
static EVP_PKEY *load_key_autofmt(const char *infile, int format, const char *pass, ENGINE *e, const char *desc) {
    EVP_PKEY *pkey;
    /* BIO_printf(bio_c_out, "Loading %s from '%s'\n", desc, infile); */
    char *pass_string = get_passwd(pass, desc);
    BIO *bio_bak = bio_err;
    bio_err = NULL;
    format = adjust_format(&infile, format, 1);
    pkey = load_key(bio_err, infile, format, 0, pass_string, e, desc);
    if (pkey == NULL && format != FORMAT_HTTP && format != FORMAT_ENGINE) {
        ERR_clear_error();
        pkey = load_key(bio_err, infile, format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM, 0, pass_string, NULL, desc);
    }
    bio_err = bio_bak;
    if (!pkey) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from '%s'\n", desc, infile);
    }
    if (pass_string)
        OPENSSL_clear_free(pass_string, strlen(pass_string));
    return pkey;
}

/* TODO dvo: push that separately upstream */
/* this is exclusively used by load_certs_fmt */
static X509 *load_cert_autofmt(const char *infile, int *format,
                               const char *pass, const char *desc) {
    X509 *cert;
    /* BIO_printf(bio_c_out, "Loading %s from file '%s'\n", desc, infile); */
    char *pass_string = get_passwd(pass, desc);
    BIO *bio_bak = bio_err;
    bio_err = NULL;
    *format = adjust_format(&infile, *format, 0);
    cert = load_cert_corrected_pkcs12(infile, *format, pass_string, desc);
    if (cert == NULL && *format != FORMAT_HTTP) {
        ERR_clear_error();
        *format = (*format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM);
        cert = load_cert_corrected_pkcs12(infile, *format, pass_string, desc);
    }
    bio_err = bio_bak;
    if (!cert) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from '%s'\n", desc, infile);
    }
    if (pass_string)
        OPENSSL_clear_free(pass_string, strlen(pass_string));
    return cert;
}

/* TODO dvo: push that separately upstream */
static X509_REQ *load_csr_autofmt(const char *infile, int *format, const char *desc) {
    X509_REQ *csr;
    /* BIO_printf(bio_c_out, "Loading %s from file '%s'\n", desc, infile); */
    BIO *bio_bak = bio_err;
    bio_err = NULL;
    *format = adjust_format(&infile, *format, 0);
    csr = load_csr(infile, *format, desc);
    if (csr == NULL && (*format == FORMAT_PEM || *format == FORMAT_ASN1)) {
        ERR_clear_error();
        *format = (*format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM);
        csr = load_csr(infile, *format, desc);
    }
    bio_err = bio_bak;
    if (!csr) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from file '%s'\n", desc, infile);
    }
    return csr;
}

/* TODO dvo: push that separately upstream */
/* this is exclusively used by load_certs_autofmt */
static STACK_OF(X509) *load_certs_fmt(const char *infile, int format,
                                      const char *pass, const char *desc) {
    X509 *cert;
    if (format == FORMAT_PEM) {
        return load_certs(bio_err, infile, format, pass, NULL, desc);
    }
    else if (format == FORMAT_PKCS12) {
        STACK_OF(X509) *certs = NULL;
        BIO *bio = bio_open_default(infile, 'r', format);
        if (bio != NULL) {
            PW_CB_DATA cb_data;
            cb_data.password = pass;
            cb_data.prompt_info = infile;
            if (!load_pkcs12(bio, desc, (pem_password_cb *)password_callback,
                             &cb_data, NULL, NULL, &certs))
                certs = NULL;
            BIO_free(bio);
        }
        return certs;
    } else {
        STACK_OF(X509) *certs = sk_X509_new_null();
        if (!certs)
            return NULL;
        cert = load_cert_corrected_pkcs12(infile, format, pass, desc);
        if (!cert) {
            sk_X509_free(certs);
            return NULL;
        }
        sk_X509_push(certs, cert);
        return certs;
    }
}

/* TODO dvo: push that separately upstream */
/* in apps.c there is load_certs which should be used for CMP upstream submission */
static STACK_OF(X509) *load_certs_autofmt(const char *infile, int format,
                        int exclude_http, const char *pass, const char *desc) {
    STACK_OF(X509) *certs;
    BIO *bio_bak = bio_err;
    /* BIO_printf(bio_c_out, "Loading %s from file '%s'\n", desc, infile); */
    format = adjust_format(&infile, format, 0);
    if (exclude_http && format == FORMAT_HTTP) {
        BIO_printf(bio_err, "error: HTTP retrieval not allowed for %s\n", desc);
        return NULL;
    }
    bio_err = NULL;
    certs = load_certs_fmt(infile, format, pass, desc);
    if (certs == NULL) {
        int format2 = format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM;
        ERR_clear_error();
        certs = load_certs_fmt(infile, format2, pass, desc);
    }
    bio_err = bio_bak;
    if (!certs) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from '%s'\n",desc,infile);
    }
    return certs;
}

/* TODO dvo: push that separately upstream */
/* this is used by load_crls_fmt and LOCAL_load_crl_crldp */
static X509_CRL *load_crl_autofmt(const char *infile, int format, const char *desc) {
    X509_CRL *crl = NULL;
    BIO *bio_bak = bio_err;
    bio_err = NULL;
    /* BIO_printf(bio_c_out, "Loading %s from '%s'\n", desc, infile); */
    format = adjust_format(&infile, format, 0);
    if (format == FORMAT_HTTP) {
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
        load_cert_crl_http_timeout(infile, opt_crl_timeout, NULL, &crl);
#endif
        goto end;
    }
    crl = load_crl(infile, format);
    if (crl == NULL) {
        ERR_clear_error();
        crl = load_crl(infile, format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM);
    }
 end:
    bio_err = bio_bak;
    if (!crl) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from file '%s'\n", desc, infile);
    }
    return crl;
}

/* TODO dvo: push that separately upstream */
/* this is exclusively used by load_crls_autofmt */
static STACK_OF(X509_CRL) *load_crls_fmt(const char *infile, int format, const char *desc) {
    X509_CRL *crl;
    if (format == FORMAT_PEM) {
        /* BIO_printf(bio_c_out, "Loading %s from '%s'\n", desc, infile); */
        return load_crls(bio_err, infile, format, NULL, NULL, desc);
    } else {
        STACK_OF(X509_CRL) *crls = sk_X509_CRL_new_null();
        if (!crls)
            return NULL;
        crl = load_crl_autofmt(infile, format, desc);
        /* using load_crl_autofmt because of http capabilities including timeout */
        if (!crl) {
            sk_X509_CRL_free(crls);
            return NULL;
        }
        sk_X509_CRL_push(crls, crl);
        return crls;
    }
}

/* TODO dvo: push that separately upstream */
/* in apps.c there is load_crls which should be used for CMP upstream submission */
static STACK_OF(X509_CRL) *load_crls_autofmt(const char *infile, int format, const char *desc) {
    STACK_OF(X509_CRL) *crls;
    BIO *bio_bak = bio_err;
    bio_err = NULL;
    format = adjust_format(&infile, format, 0);
    crls = load_crls_fmt(infile, format, desc);
    if (crls == NULL && format != FORMAT_HTTP) {
        ERR_clear_error();
        crls = load_crls_fmt(infile, format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM, desc);
    }
    bio_err = bio_bak;
    if (!crls) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from '%s'\n", desc, infile);
    }
    return crls;
}

/*
 * ##########################################################################
 * * set the expected host name or IP address in the given cert store.
 * The string must not be freed as long as print_cert_verify_cb() may use it.
 * returns 1 on success, 0 on error.
 * ##########################################################################
 */
#define X509_STORE_EX_DATA_HOST 0
#define X509_STORE_EX_DATA_SBIO 1
static int truststore_set_host(X509_STORE *ts, const char *host) {
    X509_VERIFY_PARAM *ts_vpm = X509_STORE_get0_param(ts);
    /* first clear any host names and IP addresses */
    if (!X509_VERIFY_PARAM_set1_host(ts_vpm, NULL, 0) ||
        !X509_VERIFY_PARAM_set1_ip(ts_vpm, NULL, 0)) {
        return 0;
    }
    X509_VERIFY_PARAM_set_hostflags(ts_vpm,
                                    X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT |
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    /* Unfortunately there is no OpenSSL API function for retrieving the hosts/
       ip entries in X509_VERIFY_PARAM. So we store the host value in ex_data
       for use in print_cert_verify_cb() and backup/restore functions below. */
    if (!X509_STORE_set_ex_data(ts, X509_STORE_EX_DATA_HOST, (void *)host))
        return 0;
    if (host && isdigit(host[0]))
        return X509_VERIFY_PARAM_set1_ip_asc(ts_vpm, host);
    else
        return X509_VERIFY_PARAM_set1_host(ts_vpm, host, 0);
}

#ifndef OPENSSL_NO_OCSP
/*
 * ##########################################################################
 * * code needed for OCSP support
 * ##########################################################################
 */

static int backup_vpm(X509_STORE *ts, X509_VERIFY_PARAM **bak_vpm,
                      const char **bak_host)
{
    /* Unfortunately there is no OpenSSL API function for retrieving the
       hosts/ip entries in X509_VERIFY_PARAM. So we use ts->ex_data. */
    *bak_host = X509_STORE_get_ex_data(ts, X509_STORE_EX_DATA_HOST);
    return (*bak_vpm = X509_VERIFY_PARAM_new()) &&
           X509_VERIFY_PARAM_inherit(*bak_vpm, X509_STORE_get0_param(ts));
}
static int restore_vpm(X509_STORE *ts, X509_VERIFY_PARAM *bak_vpm,
                      const char *bak_host)
{
    return X509_STORE_set_ex_data(ts, X509_STORE_EX_DATA_HOST, (void *)bak_host)
        && X509_STORE_set1_param(ts, bak_vpm);
}

/* Maximum leeway in validity period: default 5 minutes */
# define MAX_OCSP_VALIDITY_PERIOD (5 * 60)

/* Verify an OCSP response rsp obtained either via a classical OCSP request,
 * where req != NULL and the request ID is taken from there,
 * or via OCSP stapling, where req == NULL and the given id is used.
 * Returns 1 on success, 0 on rejection (i.e., cert revoked), -1 on error */
static int check_ocsp_response(X509_STORE *ts, STACK_OF(X509) *untrusted,
                  OCSP_REQUEST *req, OCSP_CERTID *id, OCSP_RESPONSE *rsp)
{
    X509_VERIFY_PARAM *bak_vpm = NULL;
    OCSP_BASICRESP *br;
    int res, status, reason;
    ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;
    int failures = 0;

    if (!rsp)
        return 0;

#if 0 && !defined NDEBUG
    BIO_puts(bio_c_out, "======================================\n");
    OCSP_RESPONSE_print(bio_c_out, rsp, 0);
    BIO_puts(bio_c_out, "======================================\n");
#endif

    status = OCSP_response_status(rsp);
    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        BIO_printf(bio_err, "OCSP responder error: %s (code %d)\n",
                   OCSP_response_status_str(status), status);
        return -1;
    }

    if (!(br = OCSP_response_get1_basic(rsp))) {
        BIO_printf(bio_err, "error getting OCSP basic response\n");
        return -1;
    }
    if (req && ((res = OCSP_check_nonce(req, br)) <= 0)) {
        if (res == -1)
            BIO_printf(bio_c_out, "warning: no nonce in OCSP response\n");
        else {
            BIO_printf(bio_err, "nonce verification error\n");
            failures++;
            goto end;
        }
    }

    {  /* workaround for a bug in OCSP_basic_verify()
        * neglecting the certs argument if br->certs is NULL */
       X509 *dummy = X509_new();
       (void)OCSP_basic_add1_cert(br, dummy);
       X509_free(dummy);
    }
    if (ts) {
        const char *bak_host;
        X509_STORE_CTX_check_revocation_fn bak_revfn =
            X509_STORE_get_check_revocation(ts);
        if (!backup_vpm(ts, &bak_vpm, &bak_host) ||
            !truststore_set_host(ts, NULL/* host not relevant for OCSP chk */))
            goto end;
        /* no OCSP/CRL-based revocation checking on OCSP responder cert chain */
        X509_STORE_set_check_revocation(ts, NULL);
        (void)X509_VERIFY_PARAM_clear_flags(X509_STORE_get0_param(ts),
                                            X509_V_FLAG_CRL_CHECK);
        res = OCSP_basic_verify(br, untrusted, ts, 0/* OCSP flags */);
        if (!restore_vpm(ts, bak_vpm, bak_host))
            goto end;
        X509_STORE_set_check_revocation(ts, bak_revfn);
        if (res <= 0) {
            BIO_printf(bio_err, "OCSP response verify failure\n");
            ERR_print_errors(bio_err);
            failures++;
            goto end;
        } else {
#if 0 && !defined NDEBUG
            BIO_printf(bio_c_out, "OCSP response verify OK\n");
#endif
        }
    }

    if (!OCSP_resp_find_status(br, req ? OCSP_onereq_get0_id(
                                         OCSP_request_onereq_get0(req, 0)) : id,
                               &status, &reason, &rev, &thisupd, &nextupd)) {
        BIO_puts(bio_err, "OCSP status not found\n");
        failures++;
        goto end;
    }
    if (!OCSP_check_validity(thisupd, nextupd, MAX_OCSP_VALIDITY_PERIOD, -1)) {
        BIO_puts(bio_err, "OCSP status times invalid.\n");
        ERR_print_errors(bio_err);
        failures++;
        goto end;
    } else {
        switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
#if 0 && !defined NDEBUG
            BIO_printf(bio_c_out, "OCSP status good\n");
#endif
            break;
        case V_OCSP_CERTSTATUS_REVOKED:
            BIO_printf(bio_err, "OCSP status: revoked, reason=%s\n",
                       reason != -1 ? OCSP_crl_reason_str(reason) : "");
            failures++;
            break;
        case V_OCSP_CERTSTATUS_UNKNOWN:
        default:
            BIO_printf(bio_err, "OCSP status unknown (value %d)\n", status);
            failures++;
            break;
        }
    }

end:
    OCSP_BASICRESP_free(br);
    X509_VERIFY_PARAM_free(bak_vpm);
    return (failures == 0);
}

/*
 * ##########################################################################
 * * callback function for verify stapled OCSP responses
 * Returns 1 on success, 0 on rejection (i.e., cert revoked), -1 on error,
 * -2 on no stapled OCSP response available
 * ##########################################################################
 */
static int ocsp_resp_cb(SSL *ssl, void *arg)
{
    X509_STORE_CTX *ctx = arg;
    X509_STORE *ts = X509_STORE_CTX_get0_store(ctx);
    STACK_OF(X509) *untrusted;
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    X509 *issuer = X509_STORE_CTX_get0_current_issuer(ctx);
    OCSP_CERTID *id = NULL;
    const unsigned char *resp;
    OCSP_RESPONSE *rsp = NULL;
    int ret = -1; /* tls_process_initial_server_flight reports this as malloc failure */
    int len = SSL_get_tlsext_status_ocsp_resp(ssl, &resp);
    if (!resp) {
        BIO_puts(bio_err, "no OCSP response has been stapled\n");
#ifdef LATE_OCSP_STAPLING_CHECK
        return 0;
#endif
        return -2;
    }
    rsp = d2i_OCSP_RESPONSE(NULL, &resp, len);
    if (!rsp) {
        BIO_puts(bio_err, "error parsing stapled OCSP response\n");
        BIO_dump_indent(bio_err, (char *)resp, len, 4);
        /* well, this is likely not an internal error (malloc failure) */
        goto end;
    }
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
    /* feature seems not available, stapling does not work anyway for <1.1 */
#define SSL_get0_verified_chain(ssl) NULL
#endif
    untrusted = SSL_get0_verified_chain(ssl);
#ifdef OCSP_USE_UNTRUSTED_CERTS
    /* help cert chain building when list of certs is insufficient
     * from SSL_get0_verified_chain(ssl) and OCSP_resp_get0_certs(br) */
    if (ocsp_untrusted_certs &&
        (!(untrusted = sk_X509_dup(untrusted)) ||
         !CMP_sk_X509_add1_certs(untrusted, ocsp_untrusted_certs, 0, 1)))
            goto end; /* ERR_R_MALLOC_FAILURE */
#endif

    if (!(id = OCSP_cert_to_id(NULL, cert, issuer)))
        goto end;
    ret = check_ocsp_response(ts, untrusted, NULL, id, rsp);
    OCSP_CERTID_free(id);
#ifdef OCSP_USE_UNTRUSTED_CERTS
    if (ocsp_untrusted_certs)
        sk_X509_free(untrusted);
#endif
 end:
    OCSP_RESPONSE_free(rsp);
    return ret;
}

#endif /* !defined OPENSSL_NO_OCSP */

static X509_STORE *sk_X509_to_store(X509_STORE *store/* may be NULL*/,
                                    const STACK_OF(X509) *certs/* may be NULL*/)
{
    int i;

    if (!store)
        store = X509_STORE_new();
    if (!store)
        return NULL;
    for (i = 0; i < sk_X509_num(certs); i++) {
        if (!X509_STORE_add_cert(store, sk_X509_value(certs, i))) {
            X509_STORE_free(store);
            return NULL;
        }
    }
    return store;
}

/* TODO dvo: push that separately upstream */
/* ##########################################################################
 * * code for loading CRL via HTTP or from file, slightly adapted from apps/apps.c
 * ##########################################################################
 * This is exclusively used in load_crl_crldp()
 */

static const char *LOCAL_get_dp_url(DIST_POINT *dp)
{
    GENERAL_NAMES *gens;
    GENERAL_NAME *gen;
    int i, gtype;
    ASN1_STRING *uri;
    if (!dp->distpoint || dp->distpoint->type != 0)
        return NULL;
    gens = dp->distpoint->name.fullname;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        uri = GENERAL_NAME_get0_value(gen, &gtype);
        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
            char *uptr = (char *)ASN1_STRING_get0_data(uri);
            if (strncmp(uptr, "http://", 7) == 0  || strncmp(uptr, "file:", 5) == 0)
                return uptr;
        }
    }
    return NULL;
}

/* TODO dvo: push that separately upstream */
/* THIS IS an extension of load_crl_crldp() FROM AND LOCAL TO apps.c,
 * with support for loading local CRL files, logging of URL use, and use of *_autofmt */

/* Look through a CRLDP structure and attempt to find an http URL to
 * downloads a CRL from.
 */

static X509_CRL *LOCAL_load_crl_crldp(STACK_OF(DIST_POINT) *crldp)
{
    int i;
    const char *urlptr = NULL;
    for (i = 0; i < sk_DIST_POINT_num(crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        urlptr = LOCAL_get_dp_url(dp);
        if (urlptr) {
            /* BIO_printf(bio_c_out, "Loading CRL via CDP entry in cert from URL '%s'\n", urlptr); */
            return load_crl_autofmt(urlptr, FORMAT_HTTP, "CRL via CDP entry in certificate");
        }
    }
    return NULL;
}

/* TODO dvo: push that separately upstream */
/* THIS IS crls_http_cb() FROM AND LOCAL TO apps.c,
 * but using LOCAL_load_crl_crldp instead of the one from apps.c
 * This variant does support non-blocking I/O using a timeout, yet note
 * that if opt_crl_timeout > opt_msgtimeout the latter is overridden. */
/*
 * Example of downloading CRLs from CRLDP: not usable for real world as it
 * always downloads and doesn't cache anything.
 */

static STACK_OF(X509_CRL) *LOCAL_crls_http_cb(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    X509 *x;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_CRL *crl;
    STACK_OF(DIST_POINT) *crldp;

    crls = sk_X509_CRL_new_null();
    if (!crls)
        return NULL;
    x = X509_STORE_CTX_get_current_cert(ctx);
    crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
    crl = LOCAL_load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (!crl) {
        sk_X509_CRL_free(crls);
        return NULL;
    }
    sk_X509_CRL_push(crls, crl);
    /* Try to download delta CRL */
    crldp = X509_get_ext_d2i(x, NID_freshest_crl, NULL, NULL);
    crl = LOCAL_load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl)
        sk_X509_CRL_push(crls, crl);
    return crls;
}

/* TODO dvo: push that separately upstream */
/*
 * This allows for local CRLs and remote lookup through the callback.
 * In upstream openssl, X509_STORE_CTX_init() sets up the STORE_CTX
 * so that CRLs already loaded to the store get ignored if a callback is set.
 *
 * First try downloading CRLs from any CDP entries, then local CRLs from store.
 */

static STACK_OF(X509_CRL) *get_crls_cb(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    STACK_OF(X509_CRL) *crls;
    crls = LOCAL_crls_http_cb(ctx, nm);
    if (crls == NULL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_STORE_CTX_get1_crls X509_STORE_get1_crls
#endif
        crls = X509_STORE_CTX_get1_crls(ctx, nm);
    }
    return crls;
}

#ifndef OPENSSL_NO_OCSP
/*
 * ##########################################################################
 * * code implementing OCSP support
 * ##########################################################################
 */

#define OCSP_err(ok) \
    (ok == -2 ? X509_V_ERR_OCSP_VERIFY_NEEDED : /* no OCSP response available*/\
     ok !=  0 ? X509_V_ERR_OCSP_VERIFY_FAILED : X509_V_ERR_CERT_REVOKED)
/* emulate the internal verify_cb_cert() of crypto/cmp/x509_vfy.c;
   depth already set */
static int verify_cb_cert(X509_STORE_CTX *ctx, const X509 *cert, int err)
{
    X509_STORE_CTX_verify_cb verify_cb = X509_STORE_CTX_get_verify_cb(ctx);
    X509_STORE_CTX_set_error(ctx, err);
    X509_STORE_CTX_set_current_cert(ctx, (X509 *)cert);
    return verify_cb && (*verify_cb)(0, ctx);
}

/*
 * Get an OCSP_RESPONSE from a responder for the given cert and trust store.
 * This is a simplified version. It examines certificates each time and makes
 * one OCSP responder query for each request. A full version would store details
 * such as the OCSP certificate IDs and minimise the number of OCSP responses
 * by caching them until they were considered "expired".
 * Returns 1 on success, 0 on rejection (i.e., cert revoked), -1 on error,
 * -2 on no OCSP response available
 */
static int verify_cert_status_ocsp(X509_STORE_CTX *ctx,
                                   const X509 *cert, const X509 *issuer) {
    char *host = NULL, *path = NULL, *port = NULL;
    int use_ssl;
    STACK_OF(OPENSSL_STRING) *aia = NULL;
    OCSP_REQUEST *req = NULL;
    OCSP_CERTID *id = NULL;
    int ret = -1;
    char *url = opt_ocsp_url;
    OCSP_RESPONSE *resp = NULL;

    aia = X509_get1_ocsp((X509 *)cert);
    if (aia && opt_ocsp_use_aia)
        url = sk_OPENSSL_STRING_value(aia, 0);
    if (!url) {
        BIO_puts(bio_err,
                 "cert_status: no AIA in cert and no default responder URL\n");
        return -2;
    }
#if 0 && !defined NDEBUG
    {
        char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        BIO_printf(bio_c_out, "%s  ", subj);
        BIO_printf(bio_c_out, "cert_status: AIA URL: %s\n\n", url);
        OPENSSL_free(subj);
    }
#endif
    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl)) {
        BIO_printf(bio_err, "cert_status: can't parse AIA URL: %s\n", url);
        goto end;
    }

    if (!(req = OCSP_REQUEST_new()))
        goto end;
    if (!(id = OCSP_cert_to_id(NULL, (X509 *)cert, (X509 *)issuer)))
        goto end;
    if (!OCSP_request_add0_id(req, id))
        goto end;
    id = NULL;
    if (!OCSP_request_add1_nonce(req, NULL, -1))
        goto end;
#if 0
    STACK_OF(X509_EXTENSION) *exts;
    int i;
    /* Add any extensions to the request */
    SSL_get_tlsext_status_exts(s, &exts);
    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
        if (!OCSP_REQUEST_add_ext(req, ext, -1))
            goto end;
    }
#endif
    /* process_responder is defined ocsp.c */
    resp = process_responder(
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
                             bio_err,
#endif
                             req, host, path, port, use_ssl, NULL,
                             opt_ocsp_timeout == 0 ? -1 : opt_ocsp_timeout);
    if (resp == NULL) {
        BIO_puts(bio_err, "cert_status: error querying responder\n");
        goto end;
    }

    ret = check_ocsp_response(X509_STORE_CTX_get0_store(ctx),
                              X509_STORE_CTX_get0_chain(ctx),
                              req, id, resp);
 end:
    if (url) {
        OPENSSL_free(host);
        OPENSSL_free(path);
        OPENSSL_free(port);
    }
    if (aia)
        X509_email_free(aia);
    OCSP_CERTID_free(id);
    OCSP_REQUEST_free(req);
    OCSP_RESPONSE_free(resp);
    return ret;
}

/*
 * check revocation status of cert at current error depth in ctx using CRLs.
 * Emulates the internal check_cert() function from crypto/x509/x509_vfy.c
 */
static int check_cert(X509_STORE_CTX *ctx)
{
    int i, ok;
    X509 *cert;
    STACK_OF(X509) *chain = X509_STORE_CTX_get1_chain(ctx);
    int cnum = X509_STORE_CTX_get_error_depth(ctx);
    STACK_OF(X509) *tmp_chain = sk_X509_new_null();

    if (!chain || !tmp_chain) {
    oom:
        BIO_printf(bio_err, "internal error: out of memory\n");
        sk_X509_pop_free(chain, X509_free);
        sk_X509_pop_free(tmp_chain, X509_free);
        return 0;
    }
    for (i = 0; i < sk_X509_num(chain); i++) {
        cert = sk_X509_value(chain, i);
        if (i == cnum) {
            if (!sk_X509_push(tmp_chain, cert))
                goto oom;
            X509_up_ref(cert);
        } else {
            cert = X509_dup(cert);
            X509_set_proxy_flag(cert);/* do not check revocation of this cert */
            if (!sk_X509_push(tmp_chain, cert)) {
                X509_free(cert);
                goto oom;
            }
        }
    }
    X509_STORE_CTX_set0_verified_chain(ctx, tmp_chain);
    /* call internal check_cert() effectively only for the (cnum)-th cert: */
    ok = check_revocation(ctx);
    /* restore original chain, freeing tmp_chain: */
    X509_STORE_CTX_set0_verified_chain(ctx, chain);
    return ok;
}

/* As a generalization of check_revocation() in in crypto/x509/x509_vfy.c,
   check revocation status on each cert in ctx->chain, trying first
   OCSP stapling if enabled, then OCSP if enabled, then using CRLs if enabled */
static int check_ocsp_crls(X509_STORE_CTX *ctx)
{
    STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(ctx);
    int i, last, num = sk_X509_num(chain);
    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
    int ocsp_check = opt_ocsp_use_aia || opt_ocsp_url || opt_ocsp_check_all;
    unsigned long flags = X509_VERIFY_PARAM_get_flags(param);
    int crl_check = flags & X509_V_FLAG_CRL_CHECK;
    int crl_check_all = flags & X509_V_FLAG_CRL_CHECK_ALL;
       /* when set, usually CRL_CHECK is set as well, e.g., via opt_verify() */

    if (!opt_ocsp_status && !ocsp_check && !crl_check)
        return 1;

    if (opt_ocsp_check_all || crl_check_all)
        last = num - 1;
    else {
        /* If checking CRL paths this isn't the EE certificate */
        if (X509_STORE_CTX_get0_parent_ctx(ctx))
            return 1;
        last = 0;
    }
    for (i = 0; i <= last; i++) {
        X509 *cert = sk_X509_value(chain, i);
        X509 *issuer = sk_X509_value(chain, i < num-1 ? i+1 : num-1);
        int must_check_ocsp = ocsp_check && (i == 0 || opt_ocsp_check_all);
        int must_check_crls =  crl_check && (i == 0 ||      crl_check_all);
        int ok = 1;
        SSL *ssl = X509_STORE_CTX_get_ex_data(ctx,
                                              SSL_get_ex_data_X509_STORE_CTX_idx());
        if (i==last && X509_check_issued(cert, cert) == X509_V_OK)
            break;

        X509_STORE_CTX_set_error_depth(ctx, i); /* on current cert i in chain,
                  first try OCSP stapling if i == 0, then OCSP, then CRLs */

#ifndef LATE_OCSP_STAPLING_CHECK
        if (ssl && i == 0 && opt_ocsp_status) { /* OCSP (not multi-)stapling */
            ok = ocsp_resp_cb(ssl, ctx);
            if (ok == 1) /* cert status ok */
                continue;
            if (ok == 0 || /* cert revoked, thus clear failure */
                (ok < 1 && !must_check_ocsp
                        && !must_check_crls)){/* OCSP stapling is the only check
                                                 and it was inconclusive */
                return verify_cb_cert(ctx, cert, OCSP_err(ok));
            }
            ok = 1;
        }
#else
        ssl = ssl; /* prevent compiler warning/error */
#endif
        if (must_check_ocsp) {
            ok =  verify_cert_status_ocsp(ctx, cert, issuer);
            if (ok == 1) /* cert status ok */
                continue;
            if (ok == 0 || /* cert revoked, thus clear failure */
                (ok < 1 && !must_check_crls)) { /* OCSP is the only check
                                                   and it was inconclusive */
                return verify_cb_cert(ctx, cert, OCSP_err(ok));
            }
        }
        if (must_check_crls &&
            (!must_check_ocsp || ok <= 0)) /* OCSP disabled or not positive */
            ok = check_cert(ctx);
        if (!ok)
            return 0;
        chain = X509_STORE_CTX_get0_chain(ctx); /* for some reason need again */

    }
    return 1;
}

#endif /* !defined OPENSSL_NO_OCSP */

/*
 * ##########################################################################
 * * code for improving certificate error diagnostics
 * ##########################################################################
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

/*
 * This function is a callback used by OpenSSL's verify_cert function.
 * It's called at the end of a cert verification to allow an opportunity
 * to gather more information regarding a failing cert verification,
 * and to possibly change the result of the verification (not done here).
 * This callback is also activated when constructing our own TLS chain:
 * tls_construct_client_certificate() -> ssl3_output_cert_chain() ->
 * ssl_add_cert_chain() -> X509_verify_cert() where errors are ignored.
 */

static int print_cert_verify_cb (int ok, X509_STORE_CTX *ctx)
{
    if (ok == 0 && ctx != NULL) {
        int cert_error = X509_STORE_CTX_get_error(ctx);
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
        SSL *ssl = X509_STORE_CTX_get_ex_data(ctx,
                    SSL_get_ex_data_X509_STORE_CTX_idx());
        X509_STORE *ts = X509_STORE_CTX_get0_store(ctx);
        BIO *sbio = X509_STORE_get_ex_data(ts, X509_STORE_EX_DATA_SBIO);
        const char *expected = NULL;

        if (sbio && BIO_next(sbio) /* CMP_PKIMESSAGE_http_perform() is active */
            && !ssl) /* ssl_add_cert_chain() is active */
            return ok; /* avoid printing spurious errors */

#ifndef OPENSSL_NO_OCSP
#ifdef LATE_OCSP_STAPLING_CHECK
        if (cert_error == X509_V_ERR_OCSP_VERIFY_NEEDED ||
            cert_error == X509_V_ERR_UNABLE_TO_GET_CRL) {
            if (opt_ocsp_status && depth == 0)
                return 1; /* status of EE cert will be handled by ocsp_resp_cb()
                         * strictly requiring stapled OCSP response.
                         * In the (rare) case of multi-stapling the checks here
                         * would overlap for the further certs in the chain */
        }
#endif
#endif

        BIO_printf(bio_err, "%s at depth=%d error=%d (",
                   depth < 0 ? "signature verification" :
                   X509_STORE_CTX_get0_parent_ctx(ctx) ?
                   "CRL path validation" : "certificate verification",
                   depth, cert_error);
        switch(cert_error) {
        case X509_V_ERR_HOSTNAME_MISMATCH:
        case X509_V_ERR_IP_ADDRESS_MISMATCH:
            /* Unfortunately there is no OpenSSL API function for retrieving the
               hosts/ip entries in X509_VERIFY_PARAM. So we use ts->ex_data.
               This works for names we set ourselves but not verify_hostname. */
            expected = X509_STORE_get_ex_data(ts, X509_STORE_EX_DATA_HOST);
            break;
        default:
            break;
        }
        BIO_printf(bio_err, "%s%s%s)\n",
                   X509_verify_cert_error_string(cert_error),
                   expected ? "; expected: " : "",
                   expected ? expected : "");

        BIO_printf(bio_err, "failure for:\n");
        print_cert(bio_err, cert, X509_FLAG_NO_EXTENSIONS);
        if (cert_error == X509_V_ERR_CERT_UNTRUSTED ||
            cert_error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
            cert_error == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
            cert_error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ||
            cert_error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
            cert_error == X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER ||
            cert_error == X509_V_ERR_STORE_LOOKUP) {
            BIO_printf(bio_err, "chain store:\n");
            print_certs(bio_err, X509_STORE_CTX_get0_untrusted(ctx));
            BIO_printf(bio_err, "trust store:\n");
            print_store_certs(bio_err, X509_STORE_CTX_get0_store(ctx));
        }
    }
    return ok;
}

/*
 * callback validating that the new certificate can be verified,
 * using ctx->trusted_store (which may consist of ctx->srvCert) and
 * ctx->untrusted_certs which at this point already contain ctx->extraCertsIn.
 * Returns -1 on acceptance, else a CMP_PKIFAILUREINFO bit number.
 * Quoting from RFC 4210 section 5.1. Overall PKI Message:
       The extraCerts field can contain certificates that may be useful to
       the recipient.  For example, this can be used by a CA or RA to
       present an end entity with certificates that it needs to verify its
       own new certificate (if, for example, the CA that issued the end
       entity's certificate is not a root CA for the end entity).  Note that
       this field does not necessarily contain a certification path; the
       recipient may have to sort, select from, or otherwise process the
       extra certificates in order to use them.
* Note: While often handy, there is no hard default requirement than an EE must
*       be able to validate its own certificate.
*/
static int certConf_cb(CMP_CTX *ctx, int status, const X509 *cert,
                       const char **text)
{
    int res = -1; /* indicating "ok" here */
    STACK_OF(X509) *untrusted = sk_X509_new_null();
    if (!untrusted ||
        !CMP_sk_X509_add1_certs(untrusted, CMP_CTX_get0_untrusted_certs(ctx),
                                0, 1/* no dups */)) {
        sk_X509_pop_free(untrusted, X509_free);
        /* BIO_puts(bio_err, "error: out of memory\n"); */
        return CMP_PKIFAILUREINFO_systemFailure;
    }
    /* TODO: load caPubs [CMP_CTX_caPubs_get1(ctx)] as additional trusted certs
       during IR and if MSG_SIG_ALG is used, cf. RFC 4210, 5.3.2 */

    if (out_trusted && !CMP_validate_cert_path(ctx, out_trusted,untrusted,cert))
        res = CMP_PKIFAILUREINFO_incorrectData;

    sk_X509_pop_free(untrusted, X509_free);

    if (res >= 0)
        BIO_puts(bio_c_out,
                 "error: failed to validate newly enrolled certificate\n");
    return res;
}

static int parse_addr(char **opt_string, int port, const char* name)
{
    char *port_string;
    if (strncmp(*opt_string, HTTP_HDR, strlen(HTTP_HDR)) == 0) {
        (*opt_string) += strlen(HTTP_HDR);
    }
    if ((port_string = strrchr(*opt_string, ':')) == NULL) {
        BIO_printf(bio_err, "info: using default %s port '%d'\n",
                   name, port);
        return port;
    }
    *(port_string++) = '\0';
    port = atoi(port_string);
    if ((port <= 0) || (port > 65535)) {
        BIO_printf(bio_err,
                   "error: invalid %s port '%s' given, sane range 1-65535\n",
                   name, port_string);
        return 0;
    }
    return port;
}

/* verbatim from apps/s_cb.c */ /* does not consume the crls */
static int add_crls_store(X509_STORE *st, STACK_OF(X509_CRL) *crls)
{
    X509_CRL *crl;
    int i;
    for (i = 0; i < sk_X509_CRL_num(crls); i++) {
        crl = sk_X509_CRL_value(crls, i);
        if (!X509_STORE_add_crl(st, crl))
            return 0;
    }
    return 1;
}

static int set_store_parameters_crls(X509_STORE *ts, STACK_OF(X509_CRL) *crls) {
    if (!ts || !vpm)
        return 0;

    /* copy vpm to store */
    if (!X509_STORE_set1_param(ts, (X509_VERIFY_PARAM *)vpm)) {
        BIO_printf(bio_err, "Error setting verify params\n");
        ERR_print_errors(bio_err);
        return 0;
    }

    X509_STORE_set_verify_cb(ts, print_cert_verify_cb);

    if (crls && !add_crls_store(ts, crls)) /* ups the references to crls */
        return 0;

    if (opt_crl_download)
        X509_STORE_set_lookup_crls(ts, get_crls_cb);
    /* TODO dvo: to be replaced with "store_setup_crl_download(ts)" from apps.h,
              after extended version of crls_http_cb has been pushed upstream */

#ifndef OPENSSL_NO_OCSP
    if (check_revocation) { /* this means opt_ocsp_use_aia || opt_ocsp_url */
        X509_STORE_set_check_revocation(ts, &check_ocsp_crls);
    }
#endif

    return 1;
}

#define OPT_ITERATE(curr_opt, CMD) \
while(*curr_opt != '\0') { \
    char *next_opt = curr_opt;                                            \
    while(*next_opt != ',' && !isspace(*next_opt) && *next_opt != '\0') { \
        if(*next_opt++ ==  '\\' && *next_opt != '\0') {                   \
            next_opt++;                                                   \
        }                                                                 \
    }                                                                     \
    if (*next_opt != '\0') {                                              \
        *next_opt++ = '\0';                                               \
        while(isspace(*next_opt)) {                                       \
            next_opt++;                                                   \
        }                                                                 \
    }                                                                     \
    CMD \
    curr_opt = next_opt; \
}

static int set_name(const char *str,
                    int (*set_fn)(CMP_CTX *ctx, const X509_NAME *name),
                    CMP_CTX *ctx, const char *desc) {
    if (str) {
        X509_NAME *n = parse_name(str, MBSTRING_ASC, 0);
        if (n == NULL) {
            BIO_printf(bio_err, "error: unable to parse %s name '%s'\n",
                       desc, str);
            return 0;
        }
        if (!(*set_fn)(ctx, n)) {
            X509_NAME_free(n);
            return 0;
        }
        X509_NAME_free(n);
    }
    return 1;
}

/*
 * ##########################################################################
 * * create cert store structure with certificates read from given file(s)
 * returns pointer to created X509_STORE on success, NULL on error
 * ##########################################################################
 */
static X509_STORE *load_certstore(char *input, const char *desc)
{
    X509_STORE *store = NULL;
    STACK_OF(X509) *certs = NULL;

    if (!input)
        return NULL;

    /* BIO_printf(bio_c_out, "Loading %s from file '%s'\n", desc, input); */
    OPT_ITERATE(input,
        if (!(certs = load_certs_autofmt(input, opt_storeform, 1,
                                         opt_storepass, desc)) ||
            !(store = sk_X509_to_store(store, certs))) {
            /* BIO_puts(bio_err, "error: out of memory\n"); */
            sk_X509_pop_free(certs, X509_free);
            X509_STORE_free(store);
            return NULL;
        }
        sk_X509_pop_free(certs, X509_free);
    )
    return store;
}

static int load_untrusted(char *input,
                          int (*set_fn)(CMP_CTX *ctx, const STACK_OF(X509) *certs),
                          CMP_CTX *ctx, const char *desc)
{
    STACK_OF(X509) *certs, *all_certs;
    int ret = 0;
    if (!input)
        return 1;

    /* BIO_printf(bio_c_out, "Loading %s from file '%s'\n", desc, input); */
    if (!(all_certs = sk_X509_new_null())) {
        goto oom;
    }
    OPT_ITERATE(input,
        if (!(certs = load_certs_autofmt(input, opt_storeform, 0,
                                         opt_storepass, desc)) ||
            !CMP_sk_X509_add1_certs(all_certs, certs, 0, 1/*no dups*/)) {
                goto oom;
        }
        sk_X509_pop_free(certs, X509_free);
    )
    if ((*set_fn)(ctx, all_certs)) {
        ret = 1;
    } else {
    oom:
        /* BIO_puts(bio_err, "error: out of memory\n"); */
        ret = 0;
    }
    sk_X509_pop_free(all_certs, X509_free);
    return ret;
}

/*
 * ##########################################################################
 * * set up the CMP_CTX structure based on options from config file/CLI
 * while parsing options and checking their consistency.
 * Prints reason for error to bio_err.
 * Returns 1 on success, 0 on error
 * ##########################################################################
 */
static int setup_ctx(CMP_CTX *ctx, ENGINE *e)
{
    int certform;
    STACK_OF(X509_CRL) *all_crls = NULL;
    int ret = 0;

    if (!opt_server) {
        BIO_puts(bio_err, "error: missing server address[:port]\n");
        goto err;
    } else if (!(server_port = parse_addr(&opt_server, server_port, "server"))) {
        goto err;
    }
    CMP_CTX_set1_serverName(ctx, opt_server);
    CMP_CTX_set_serverPort(ctx, server_port);
    CMP_CTX_set1_serverPath(ctx, opt_path);

    if (opt_proxy) {
        if (!(proxy_port = parse_addr(&opt_proxy, proxy_port, "proxy"))) {
            goto err;
        }
        CMP_CTX_set1_proxyName(ctx, opt_proxy);
        CMP_CTX_set_proxyPort(ctx, proxy_port);
    }

    if (opt_cmd_s) {
        if (!strcmp(opt_cmd_s, "ir"))
            opt_cmd = CMP_IR;
        else if (!strcmp(opt_cmd_s, "kur"))
            opt_cmd = CMP_KUR;
        else if (!strcmp(opt_cmd_s, "cr"))
            opt_cmd = CMP_CR;
        else if (!strcmp(opt_cmd_s, "p10cr"))
            opt_cmd = CMP_P10CR;
        else if (!strcmp(opt_cmd_s, "rr"))
            opt_cmd = CMP_RR;
        else if (!strcmp(opt_cmd_s, "genm"))
            opt_cmd = CMP_GENM;
        else {
            BIO_printf(bio_err, "error: unknown cmp command '%s'\n",
                       opt_cmd_s);
            goto err;
        }
    } else {
        BIO_puts(bio_err, "error: no cmp command to execute\n");
        goto err;
    }

    if (!opt_unprotectedRequests &&
            !(opt_ref && opt_secret) && !(opt_cert && opt_key)) {
        BIO_puts(bio_err, "error: missing -unprotectedrequests, or -ref and -secret, or -cert and -key, for client authentication\n");
        goto err;
    }
    if (opt_cmd == CMP_IR || opt_cmd == CMP_CR || opt_cmd == CMP_KUR) {
        if (!opt_newkey && !opt_key) {
            BIO_puts(bio_err, "error: missing -key or -newkey to be certified\n");
            goto err;
        }
        if (!opt_certout) {
            BIO_puts(bio_err,
                     "error: -certout not given, nowhere to save certificate\n");
            goto err;
        }
    }
    if (opt_cmd == CMP_KUR && !opt_cert && !opt_oldcert) {
        BIO_puts(bio_err, "error: missing certificate to be updated\n");
        goto err;
    }
    if (opt_cmd == CMP_RR && !opt_oldcert) {
        BIO_puts(bio_err, "error: missing certificate to be revoked\n");
        goto err;
    }
    if (opt_cmd == CMP_P10CR && !opt_csr) {
        BIO_puts(bio_err, "error: missing PKCS#10 CSR for p10cr\n");
        goto err;
    }

    if (!opt_unprotectedRequests && !(opt_ref && opt_secret) && !(opt_cert && opt_key)) {
        BIO_puts(bio_err,
                 "error: missing -ref/-secret or -cert/-key for client authentication\n");
        goto err;
    }
    if (!opt_recipient && !opt_srvcert && !opt_issuer && !opt_oldcert && !opt_cert) {
        BIO_puts(bio_err,
                 "warning: missing -recipient, -srvcert, -issuer, -oldcert or -cert; recipient will be set to \"NULL-DN\"\n");
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (opt_keyform_s
        && !opt_format(opt_keyform_s, OPT_FMT_PEMDER | OPT_FMT_PKCS12
#ifndef OPENSSL_NO_ENGINE
            | OPT_FMT_ENGINE
#endif
            , &opt_keyform)) {
        BIO_puts(bio_err, "error: unknown option given for key format\n");
        goto err;
    }

    if (opt_certform_s
        && !opt_format(opt_certform_s, OPT_FMT_PEMDER | OPT_FMT_PKCS12, &opt_certform)) {
        BIO_puts(bio_err, "error: unknown option given for certificate format\n");
        goto err;
    }

    if (opt_storeform_s
        && !opt_format(opt_storeform_s, OPT_FMT_PEMDER | OPT_FMT_PKCS12, &opt_storeform)) {
        BIO_puts(bio_err,
                 "error: unknown option given for certificate store format\n");
        goto err;
    }

    if (opt_crlform_s
        && !opt_format(opt_crlform_s, OPT_FMT_PEMDER, &opt_crlform)) {
        BIO_puts(bio_err, "error: unknown option given for CRL format\n");
        goto err;
    }

#else
    if (opt_keyform_s)
        opt_keyform = str2fmt(opt_keyform_s);

    if (opt_certform_s)
        opt_certform = str2fmt(opt_certform_s);

    if (opt_storeform_s)
        opt_storeform = str2fmt(opt_storeform_s);

    if (opt_crlform_s)
        opt_crlform = str2fmt(opt_crlform_s);
#endif

    if (opt_infotype_s) {
        char id_buf[87] = "id-it-";
        strncat(id_buf, opt_infotype_s, 80);
        if ((opt_infotype = OBJ_sn2nid(id_buf)) == NID_undef) {
            BIO_puts(bio_err, "error: unknown OID name in -infotype option\n");
            goto err;
        }
    }

    if (opt_crls || opt_crl_download)
        X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK);
    else if (X509_VERIFY_PARAM_get_flags(vpm) & X509_V_FLAG_CRL_CHECK) {
            BIO_printf(bio_c_out, "must use -crl_download or -crls when -crl_check is given\n");
#if 0
            X509_VERIFY_PARAM_clear_flags(vpm, X509_V_FLAG_CRL_CHECK);
#else
            goto err;
#endif
    }
    { /* just as a precaution in case CRL_CHECK_ALL is set without CRL_CHECK */
        unsigned long flags = X509_VERIFY_PARAM_get_flags(vpm);
        if ((flags & X509_V_FLAG_CRL_CHECK_ALL) &&
           !(flags & X509_V_FLAG_CRL_CHECK))
            BIO_printf(bio_c_out,
"warning: -crl_check_all has no effect without -crls, -crl_download, or -crl_check\n");
    }
    if (opt_crl_timeout == 0)
        opt_crl_timeout = -1;
    if (opt_crls) {
        X509_CRL *crl;
        STACK_OF(X509_CRL) *crls;
        if (!(all_crls = sk_X509_CRL_new_null())) {
            goto err;
        }
        OPT_ITERATE(opt_crls,
            if (!(crls = load_crls_autofmt(opt_crls, opt_crlform,
                               "CRL(s) for checking certificate revocation"))) {
                goto err;
            }
            while((crl = sk_X509_CRL_shift(crls))) {
                if (!sk_X509_CRL_push(all_crls, crl)) {
                    sk_X509_CRL_pop_free(crls, X509_CRL_free);
                    goto err;
                }
            }
            sk_X509_CRL_free(crls);
        )
    }

    if (!load_untrusted(opt_untrusted, CMP_CTX_set1_untrusted_certs, ctx,
                        "untrusted certificates"))
        goto err;

#ifndef OPENSSL_NO_OCSP
#ifdef OCSP_USE_UNTRUSTED_CERTS
    ocsp_untrusted_certs = CMP_CTX_get0_untrusted_certs(ctx);
#endif
    if (opt_ocsp_use_aia || opt_ocsp_url || opt_ocsp_status) {
        X509_STORE_CTX *tmp_ctx = X509_STORE_CTX_new();
        if (opt_crl_download || opt_crls)
            BIO_printf(bio_c_out,
    "info: will try first OCSP then CRLs for certificate status checking\n");
        /* Unfortunately, check_cert() in crypto/x509/x509_vfy.c is static, yet
           we can access it indirectly via check_revocation() with a trick. */
        if (tmp_ctx && X509_STORE_CTX_init(tmp_ctx, NULL, NULL, NULL))
            check_revocation = X509_STORE_CTX_get_check_revocation(tmp_ctx);
        X509_STORE_CTX_free(tmp_ctx);
        if (!check_revocation) {
            BIO_printf(bio_err,"internal error: cannot get check_revocation\n");
            goto err;
        }
    } else if (opt_ocsp_check_all)
        BIO_printf(bio_c_out,
  "warning: -ocsp_check_all has little sense without -ocsl-aia or -ocsp_url\n");
#endif

    if (opt_tls_trusted || opt_tls_host) {
        opt_use_tls = 1;
    }
    if (opt_tls_cert || opt_tls_key || opt_tls_keypass) {
        opt_use_tls = 1;
        if (!opt_tls_key) {
            BIO_printf(bio_err, "error: missing -tls-key option\n");
            goto err;
         }
        else if (!opt_tls_cert) {
            BIO_printf(bio_err, "error: missing -tls-cert option\n");
        }
    }
    if (opt_use_tls) {
        X509 *cert = NULL;
        EVP_PKEY *pkey = NULL;
        X509_STORE *store = NULL;
        SSL_CTX *ssl_ctx;
        BIO *sbio;

        /* initialize OpenSSL's SSL lib */
        OpenSSL_add_ssl_algorithms();
        SSL_load_error_strings();

#if OPENSSL_VERSION_NUMBER < 0x1010001fL
#define TLS_client_method SSLv23_client_method
#endif
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (ssl_ctx == NULL) {
            goto err;
        }
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
        SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

#ifndef OPENSSL_NO_OCSP
#ifdef LATE_OCSP_STAPLING_CHECK
            if (opt_ocsp_status) {
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
/* The following does not work:
                #define SSL_CTX_set_tlsext_status_type(ssl, type) \
                        SSL_CTX_ctrl(ssl, SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE, type, NULL)
   Instead, we would have to set TLSEXT_STATUSTYPE_ocsp directly in the SSL struct:
                SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
 */
#else
                SSL_CTX_set_tlsext_status_type(ssl_ctx, TLSEXT_STATUSTYPE_ocsp);
#endif
                SSL_CTX_set_tlsext_status_cb(ssl_ctx, ocsp_resp_cb);
             /* TODO: must set also X509_STORE_CTX *ctx via
                SSL_CTX_set_tlsext_status_arg(ssl_ctx, ctx);
                which likely can be done via an SSL_CTX cert_verify_callback */
            }
#endif
#endif

        if (opt_tls_trusted) {
            if (!(store = load_certstore(opt_tls_trusted,
                                         "trusted TLS certificates"))) {
                goto tls_err;
            }
            /* do immediately for automatic cleanup in case of errors: */
            SSL_CTX_set_cert_store(ssl_ctx, store);
            if (!set_store_parameters_crls(store, all_crls))
                goto tls_err;
#if OPENSSL_VERSION_NUMBER >= 0x10002000
            /* enable and parameterize server hostname/IP address check */
            if (!truststore_set_host(store, opt_tls_host ? opt_tls_host
                                     : opt_server))
            /* TODO: is the server host name correct for TLS via proxy? */
                goto tls_err;
#endif
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        }

        {
            X509_STORE *untrusted =
                sk_X509_to_store(NULL, CMP_CTX_get0_untrusted_certs(ctx));
            /* do immediately for automatic cleanup in case of errors: */
            if (!SSL_CTX_set0_chain_cert_store(ssl_ctx, untrusted/*may be 0*/))
                goto tls_err;
        }

        if (opt_tls_cert && opt_tls_key) {
            certform = adjust_format((const char **)&opt_tls_cert, opt_certform, 0);
            if (certform == FORMAT_PEM) {
                if (SSL_CTX_use_certificate_chain_file(ssl_ctx, opt_tls_cert) <= 0) {
                    BIO_printf(bio_err, "error: unable to load and use client TLS certificate (and possibly extra certificates) '%s'\n", opt_tls_cert);
                    goto tls_err;
                }
            } else {
                /* opt_tls_keypass is needed here in case opt_tls_cert is an encrypted PKCS#12 file */
                /* TODO: add any extra certs, e.g., from P12 file, using SSL_CTX_add_extra_chain_cert() */
                if (!(cert=load_cert_autofmt(opt_tls_cert, &certform, opt_tls_keypass, "TLS client certificate"))) {
                    goto tls_err;
                }
                if (SSL_CTX_use_certificate(ssl_ctx, cert) <= 0) {
                    BIO_printf(bio_err, "error: unable to use client TLS certificate '%s'\n", opt_tls_cert);
                    X509_free(cert);
                    goto tls_err;
                }
                X509_free(cert); /* we don't need the handle any more */
                cert = NULL;
            }

            pkey = load_key_autofmt(opt_tls_key, opt_keyform, opt_tls_keypass, e, "TLS client private key");
            if (opt_tls_keypass) {
                OPENSSL_cleanse(opt_tls_keypass, strlen(opt_tls_keypass));
                opt_tls_keypass = NULL;
            }
            if (!pkey)
                goto tls_err;
            /* verify the key matches the cert,
               not using SSL_CTX_check_private_key(ssl_ctx)
               because it gives poor and sometimes misleading diagnostics */
            if (!X509_check_private_key(SSL_CTX_get0_certificate(ssl_ctx),
                                        pkey)) {
                BIO_printf(bio_err,
       "error: TLS private key '%s' does not match the TLS certificate '%s'\n",
                           opt_tls_key, opt_tls_cert);
                EVP_PKEY_free(pkey);
                pkey = NULL; /* otherwise, for some reason double free! */
                goto tls_err;
            }
            if (SSL_CTX_use_PrivateKey(ssl_ctx, pkey) <= 0) {
                BIO_printf(bio_err, "error: unable to use TLS client private key '%s'\n", opt_tls_key);
                EVP_PKEY_free(pkey);
                pkey = NULL; /* otherwise, for some reason double free! */
                goto tls_err;
            }
            EVP_PKEY_free(pkey); /* we don't need the handle any more */
        }

        sbio = BIO_new_ssl(ssl_ctx, 1);
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
        if (!sbio || (store &&
            !X509_STORE_set_ex_data(store, X509_STORE_EX_DATA_SBIO, sbio))) {
            BIO_printf(bio_err, "error: cannot initialize SSL BIO");
        tls_err:
            SSL_CTX_free(ssl_ctx);
            goto err;
        }
        CMP_CTX_set0_tlsBIO(ctx, sbio);
    }

    if ((!opt_ref) != (!opt_secret)) {
        BIO_puts(bio_err, "error: must give both -ref and -secret options or neither of them\n");
        goto err;
    }
    if (opt_ref && opt_secret) {
        char *pass_string = NULL;
        if ((pass_string = get_passwd(opt_secret, "PBMAC"))) {
        OPENSSL_cleanse(opt_secret, strlen(opt_secret));
        opt_secret = NULL;
        CMP_CTX_set1_referenceValue(ctx, (unsigned char *)opt_ref,
                                    strlen(opt_ref));
        CMP_CTX_set1_secretValue(ctx, (unsigned char *)pass_string,
                                 strlen(pass_string));
        OPENSSL_clear_free(pass_string, strlen(pass_string));
        }
    }

    if (opt_newkey) {
        EVP_PKEY *pkey = load_key_autofmt(opt_newkey, opt_keyform, opt_newkeypass, e, "new private key for certificate to be enrolled");
        if (opt_newkeypass) {
            OPENSSL_cleanse(opt_newkeypass, strlen(opt_newkeypass));
            opt_newkeypass = NULL;
        }
        if (!pkey || !CMP_CTX_set0_newPkey(ctx, pkey)) {
            EVP_PKEY_free(pkey);
            goto err;
        }
    }

    if ((!opt_cert) != (!opt_key)) {
        BIO_puts(bio_err, "error: must give both -cert and -key options or neither of them\n");
        goto err;
    }
    if (opt_key) {
        EVP_PKEY *pkey = load_key_autofmt(opt_key, opt_keyform, opt_keypass, e, "private key for CMP client certificate");
        if (!pkey || !CMP_CTX_set0_pkey(ctx, pkey)) {
            EVP_PKEY_free(pkey);
            goto err;
        }
    }
    if ((opt_cert || opt_unprotectedRequests) && !(opt_srvcert || opt_trusted)) {
        BIO_puts(bio_err,
                 "error: no server certificate or trusted certificates set\n");
        goto err;
    }
    certform = opt_certform;
    if (opt_cert) {
        X509 *clcert;
        /* opt_keypass is needed here in case opt_cert is an encrypted PKCS#12 file */
        clcert = load_cert_autofmt(opt_cert, &certform, opt_keypass, "CMP client certificate");
        if (!clcert || !CMP_CTX_set1_clCert(ctx, clcert)) {
            X509_free(clcert);
            goto err;
        }
        X509_free(clcert);
    }

    if (!load_untrusted(opt_extracerts, CMP_CTX_set1_extraCertsOut, ctx,
                        "extra certificates"))
        goto err;

    certform = opt_certform;
    if (opt_srvcert || opt_trusted) {
        X509_STORE *ts = NULL;
        if (opt_srvcert) {
            X509 *srvcert;
            if (opt_trusted) {
                BIO_puts(bio_err,
      "warning: -trusted option is ignored since -srvcert option is present\n");
                opt_trusted = NULL;
            }
            if (opt_recipient) {
                BIO_puts(bio_err,
    "warning: -recipient option is ignored since -srvcert option is present\n");
                opt_recipient = NULL;
            }
            /* opt_keypass is needed here in case opt_srvcert is an encrypted PKCS#12 file */
            srvcert = load_cert_autofmt(opt_srvcert, &certform, NULL,
                                        "trusted CMP server certificate");
            if (!srvcert || !CMP_CTX_set1_srvCert(ctx, srvcert)) {
                X509_free(srvcert);
                goto err;
            }
            X509_free(srvcert);
            ts = X509_STORE_new();
        }
        if (opt_trusted) {
            ts = load_certstore(opt_trusted, "trusted certificates");
        }
        if (!set_store_parameters_crls(ts/* may be NULL */, all_crls) ||
            !truststore_set_host(ts, NULL/* for CMP level, no host */) ||
            !CMP_CTX_set0_trustedStore(ctx, ts)) {
            X509_STORE_free(ts);
            goto err;
        }
    }

    if (opt_out_trusted) { /* in preparation for use in certConf_cb() */
        out_trusted = load_certstore(opt_out_trusted,
                             "trusted certs for verifying newly enrolled cert");
        if (!out_trusted || !set_store_parameters_crls(out_trusted, all_crls))
            goto err;
        /* any -verify_hostname, -verify_ip, and -verify_email apply here */
    }
    if (opt_storepass) {
        OPENSSL_cleanse(opt_storepass, strlen(opt_storepass));
        opt_storepass = NULL;
    }

    if (!set_name(opt_subject, CMP_CTX_set1_subjectName, ctx, "subject"))
        goto err;


    if (!set_name(opt_issuer, CMP_CTX_set1_issuer, ctx, "issuer"))
        goto err;

    if (!set_name(opt_recipient, CMP_CTX_set1_recipient, ctx, "recipient"))
        goto err;

    if (!set_name(opt_expected_sender, CMP_CTX_set1_expected_sender, ctx,
                  "expected sender"))
        goto err;

    if (opt_days > 0)
        (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_VALIDITYDAYS, opt_days);

    if (opt_popo < -1 || opt_popo > 3) {
        BIO_printf(bio_err, "error: invalid value '%d' for popo method (must be between 0 and 3)\n", opt_popo);
        goto err;
    }
    if (opt_popo >= 0)
        (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_POPOMETHOD, opt_popo);
    if (opt_reqexts) {
        X509V3_CTX ext_ctx;
        X509_EXTENSIONS *exts = sk_X509_EXTENSION_new_null();
        X509V3_set_ctx(&ext_ctx, NULL, NULL, NULL, NULL, 0);
        X509V3_set_nconf(&ext_ctx, conf);
        if (!X509V3_EXT_add_nconf_sk(conf, &ext_ctx, opt_reqexts, &exts)) {
            BIO_printf(bio_err, "error loading extension section '%s'\n", opt_reqexts);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            goto err;
        }
        CMP_CTX_set0_reqExtensions(ctx, exts);
    }

    if (opt_disableConfirm)
        (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_DISABLECONFIRM, 1);

    if (opt_implicitConfirm)
        (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_IMPLICITCONFIRM, 1);

    if (opt_unprotectedRequests)
        (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_UNPROTECTED_REQUESTS, 1);

    if (opt_unprotectedErrors)
        (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_UNPROTECTED_ERRORS, 1);

    if (opt_ignore_keyusage)
        (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_IGNORE_KEYUSAGE, 1);

    if (opt_digest) {
        int digest = OBJ_ln2nid(opt_digest);
        if (digest == NID_undef) {
            BIO_printf(bio_err, "error: digest algorithm name not recognized: '%s'\n", opt_digest);
            goto err;
        }
        (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_DIGEST_ALGNID, digest);
    }

    certform = opt_certform;
    if (opt_oldcert) {
        if (opt_cmd == CMP_KUR || opt_cmd == CMP_RR) {
            /* opt_keypass is needed here in case opt_oldcert is an encrypted PKCS#12 file */
            X509 *oldcert = load_cert_autofmt(opt_oldcert, &certform, opt_keypass, "certificate to be updated/revoked");
            if (!oldcert)
                goto err;
            if (!CMP_CTX_set1_oldClCert(ctx, oldcert)) {
                X509_free(oldcert);
                goto err;
            }
            X509_free(oldcert);
        } else {
            BIO_printf(bio_c_out, "warning: -oldcert option is ignored for commands other than KUR and RR\n");
        }
    }
    if (opt_keypass) {
        OPENSSL_cleanse(opt_keypass, strlen(opt_keypass));
        opt_keypass = NULL;
    }

    if (opt_csr) {
        if (opt_cmd != CMP_P10CR)
            BIO_puts(bio_c_out, "warning: -csr option is ignored for command other than p10cr\n");
        else {
            X509_REQ *csr = load_csr_autofmt(opt_csr, &certform, "PKCS#10 CSR for p10cr");
            if (!csr ||!CMP_CTX_set1_p10CSR(ctx, csr)) {
                X509_REQ_free(csr);
                goto err;
            }
            X509_REQ_free(csr);
        }
    }

    if (opt_revreason > CRL_REASON_NONE)
        (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_REVOCATION_REASON, opt_revreason);

    if (opt_geninfo) {
        long value;
        ASN1_OBJECT *type;
        ASN1_INTEGER *aint;
        ASN1_TYPE *val;
        CMP_INFOTYPEANDVALUE *itav;
        char *endstr;
        char *valptr = strchr(opt_geninfo, ':');
        if (!valptr) {
            BIO_puts(bio_err, "error: missing ':' in -geninfo option\n");
            goto err;
        }
        valptr[0] = '\0';
        valptr++;

        if (strncmp(valptr, "int:", 4) != 0) {
            BIO_puts(bio_err, "error: missing 'int:' in -geninfo option\n");
            goto err;
        }
        valptr += 4;

        value = strtol(valptr, &endstr, 10);
        if (endstr == valptr || *endstr) {
            BIO_puts(bio_err, "error: cannot parse int in -geninfo option\n");
            goto err;
        }

        type = OBJ_txt2obj(opt_geninfo, 1);
        if (!type) {
            BIO_puts(bio_err, "error: cannot parse OID in -geninfo option\n");
            goto err;
        }

        aint = ASN1_INTEGER_new();
        if (!aint || !ASN1_INTEGER_set(aint, value)) {
            goto err;
        }

        val = ASN1_TYPE_new();
        if (!val) {
            ASN1_INTEGER_free(aint);
            goto err;
        }
        ASN1_TYPE_set(val, V_ASN1_INTEGER, aint);

        itav = CMP_ITAV_new(type, val);
        if (!itav) {
            ASN1_TYPE_free(val);
            goto err;
        }

        if (!CMP_CTX_geninfo_itav_push0(ctx, itav)) {
            CMP_INFOTYPEANDVALUE_free(itav);
            goto err;
        }
    }

    if (opt_msgtimeout >= 0)
        (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_MSGTIMEOUT, opt_msgtimeout);
    if (opt_maxpolltime >= 0)
        (void)CMP_CTX_set_option(ctx, CMP_CTX_OPT_MAXPOLLTIME, opt_maxpolltime);

    if (opt_out_trusted)
        (void)CMP_CTX_set_certConf_callback(ctx, certConf_cb);

    ret = 1;

 err:
    sk_X509_CRL_pop_free(all_crls, X509_CRL_free);
    return ret;
}

/*
 * ##########################################################################
 * * write out the given certificate to the output specified by bio.
 * Depending on options use either PEM or DER format.
 * Returns 1 on success, 0 on error
 * ##########################################################################
 */
static int write_cert(BIO *bio, X509 *cert)
{
    if ((opt_certform == FORMAT_PEM && PEM_write_bio_X509(bio, cert))
        || (opt_certform == FORMAT_ASN1 && i2d_X509_bio(bio, cert)))
        return 1;
    if (opt_certform != FORMAT_PEM && opt_certform != FORMAT_ASN1)
        BIO_printf(bio_err, "error: unsupported type '%s' for writing certificates\n", opt_certform_s);
    return 0;
}

/*
 * ##########################################################################
 * * writes out a stack of certs to the given file.
 * Depending on options use either PEM or DER format,
 * where DER does not make much sense for writing more than one cert!
 * Returns number of written certificates on success, 0 on error.
 * ##########################################################################
 */
static int save_certs(STACK_OF(X509) *certs, char *destFile, char *desc)
{
    BIO *bio = NULL;
    int i;
    int n = sk_X509_num(certs);

    BIO_printf(bio_c_out, "Received %d %s certificate%s, saving to file '%s'\n",
               n, desc, n == 1 ? "" : "s", destFile);
    if (n > 1 && opt_certform != FORMAT_PEM)
        BIO_printf(bio_c_out, "warning: saving more than one certificate in non-PEM format\n");

    if (!destFile || (bio = BIO_new(BIO_s_file())) == NULL ||
        !BIO_write_filename(bio, (char *)destFile)) {
        BIO_printf(bio_err, "error: could not open file '%s' for writing\n", destFile);
        n = -1;
        goto err;
    }

    for (i = 0; i < n; i++) {
        if (!write_cert(bio, sk_X509_value(certs, i))) {
            BIO_printf(bio_err, "error writing certificate to file '%s'\n", destFile);
            n = -1;
            goto err;
        }
    }

 err:
    if (bio)
        BIO_free(bio);
    return n;
}

static void print_itavs(STACK_OF(CMP_INFOTYPEANDVALUE) *itavs) {
    CMP_INFOTYPEANDVALUE *itav = NULL;
    int n, i;

    n = sk_CMP_INFOTYPEANDVALUE_num(itavs); /* itavs == NULL leads to 0 */
    if (n == 0) {
        BIO_printf(bio_c_out, "GenRep contains no ITAV\n");
        return;
    }

    for (i = 0; i < n; i++) {
        char buf[128];
        itav = sk_CMP_INFOTYPEANDVALUE_value(itavs, i);
        OBJ_obj2txt(buf, 128, CMP_INFOTYPEANDVALUE_get0_type(itav), 0);
        BIO_printf(bio_c_out, "GenRep contains ITAV of type: %s\n", buf);
    }
}

#if OPENSSL_VERSION_NUMBER >= 0x1010001fL
static char *opt_str(char *opt) {
    char *arg = opt_arg();
    if (arg[0] == '\0') {
        BIO_printf(bio_c_out,
                   "Warning: argument of -%s option is empty string, resetting option\n", opt);
        arg = NULL;
    } else if (arg[0] == '-') {
        BIO_printf(bio_c_out,
                   "Warning: argument of -%s option starts with hyphen\n", opt);
    }
    return arg;
}

static int opt_nat() {
    int result;
    if (!opt_int(opt_arg(), &result))
        result = -1;
    else if (result < 0)
        BIO_printf(bio_err, "error: argument '%s' must be positive\n", opt_arg());
    return result;
}
#endif

/*
 * ##########################################################################
 * *
 * ##########################################################################
 */
int cmp_main(int argc, char **argv)
{
    char *configfile = NULL;
    long errorline = -1;
    char *tofree = NULL;        /* used as getenv returns a direct pointer to
                                 * the environment setting */
    int badops = 0;
    int i, ret = EXIT_FAILURE;
    CMP_CTX *cmp_ctx = NULL;
    X509 *newcert = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPTION_CHOICE o;
#endif
    ENGINE *e = NULL;

    if (argc <= 1) {
        badops = 1;
        goto bad_ops;
    }

    bio_c_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* handle OPT_CONFIG and OPT_SECTION upfront to take effect for other opts*/
    for (i = 1; i < argc-1; i++)
        if (*argv[i] == '-') {
            if (!strcmp(argv[i]+1, cmp_options[OPT_CONFIG-OPT_HELP].name))
                opt_config = argv[i+1];
            else if (!strcmp(argv[i]+1, cmp_options[OPT_SECTION-OPT_HELP].name))
                opt_section = argv[i+1];
        }
    if (opt_section[0] == '\0') /* empty string */
        opt_section = DEFAULT_SECTION;

    vpm = X509_VERIFY_PARAM_new();
    if (vpm == NULL) {
        BIO_printf(bio_err, "%s: out of memory\n", prog);
        goto err;
    }

    if (opt_config) {
        configfile = strdup(opt_config);
        tofree = configfile;
    }
    /* TODO dvo: the following would likely go to openssl.c make_config_name() */
    if (configfile == NULL)
        configfile = getenv("OPENSSL_CONF");
    if (configfile == NULL)
        configfile = getenv("SSLEAY_CONF");
    if (configfile == NULL) {
        const char *s = X509_get_default_cert_area();
        size_t len;

        len = strlen(s) + sizeof(CONFIG_FILE) + 1;
        tofree = OPENSSL_malloc(len);
        BUF_strlcpy(tofree, s, len);
        BUF_strlcat(tofree, "/" CONFIG_FILE, len);
        configfile = tofree;
    }

    /*
     * read default values for options from openssl.cnf
     */
    /* TODO dvo: the following would likely go to apps.c app_load_config_() */
    if (configfile && configfile[0] != '\0') { /* non-empty string */
        BIO_printf(bio_c_out, "Using OpenSSL configuration file '%s'\n", configfile);
        conf = NCONF_new(NULL);
        if (NCONF_load(conf, configfile, &errorline) <= 0) {
            if (errorline <= 0)
                BIO_printf(bio_err, "error loading the config file '%s'\n",
                           configfile);
            else
                BIO_printf(bio_err, "error on line %ld of config file '%s'\n",
                           errorline, configfile);
        } else {
            if (!NCONF_get_section(conf, opt_section)) {
                BIO_printf(bio_c_out, "Warning: no [%.40s] section found in config file '%s'; will thus use just [default] and unnamed section if present\n",
                           opt_section, configfile);
            }
            if (!read_config())
                goto err;
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    prog = opt_init(argc, argv, cmp_options);

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opt_err:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto err;
        case OPT_HELP:
            ret = EXIT_SUCCESS;
            opt_help(cmp_options);
            goto err;
        case OPT_CONFIG: /* has already been handled */
            break;
        case OPT_SECTION: /* has already been handled */
            break;

        case OPT_SERVER:
            opt_server = opt_str("server");
            break;
        case OPT_PROXY:
            opt_proxy = opt_str("proxy");
            break;
        case OPT_MSGTIMEOUT:
            if ((opt_msgtimeout = opt_nat()) < 0)
                goto opt_err;
            break;
        case OPT_MAXPOLLTIME:
            if ((opt_maxpolltime = opt_nat()) < 0)
                goto opt_err;
            break;

        case OPT_USETLS:
            opt_use_tls = 1;
            break;
        case OPT_TLSCERT:
            opt_tls_cert = opt_str("tls-cert");
            break;
        case OPT_TLSKEY:
            opt_tls_key = opt_str("tls-key");
            break;
        case OPT_TLSKEYPASS:
            opt_tls_keypass = opt_str("tls-keypass");
            break;
        case OPT_TLSTRUSTED:
            opt_tls_trusted = opt_str("tls-trusted");
            break;
        case OPT_TLSHOST:
            opt_tls_host = opt_str("tls-host");
            break;

        case OPT_PATH:
            opt_path = opt_str("path");
            break;
        case OPT_CMD:
            opt_cmd_s = opt_str("cmd");
            break;

        case OPT_REF:
            opt_ref = opt_str("ref");
            break;
        case OPT_SECRET:
            opt_secret = opt_str("secret");
            break;
        case OPT_CERT:
            opt_cert = opt_str("cert");
            break;
        case OPT_KEY:
            opt_key = opt_str("key");
            break;
        case OPT_KEYPASS:
            opt_keypass = opt_str("keypass");
            break;

        case OPT_CERTOUT:
            opt_certout = opt_str("certout");
            break;
        case OPT_OUT_TRUSTED:
            opt_out_trusted = opt_str("out_trusted");
            break;
        case OPT_NEWKEY:
            opt_newkey = opt_str("newkey");
            break;
        case OPT_NEWKEYPASS:
            opt_newkeypass = opt_str("newkeypass");
            break;
        case OPT_SRVCERT:
            opt_srvcert = opt_str("srvcert");
            break;
        case OPT_TRUSTED:
            opt_trusted = opt_str("trusted");
            break;
        case OPT_UNTRUSTED:
            opt_untrusted = opt_str("untrusted");
            break;
        case OPT_IGNORE_KEYUSAGE:
            opt_ignore_keyusage = 1;
            break;
        case OPT_CRL_DOWNLOAD:
            opt_crl_download = 1;
            break;
        case OPT_CRLS:
            opt_crls = opt_str("crls");
            break;
        case OPT_CRL_TIMEOUT:
            if ((opt_crl_timeout = opt_nat()) < 0)
                goto opt_err;
            break;
#ifndef OPENSSL_NO_OCSP
        case OPT_OCSP_CHECK_ALL:
            opt_ocsp_check_all = 1;
            break;
        case OPT_OCSP_USE_AIA:
            opt_ocsp_use_aia = 1;
            break;
        case OPT_OCSP_URL:
            opt_ocsp_url = opt_str("ocsp_url");;
            break;
        case OPT_OCSP_TIMEOUT:
            if ((opt_ocsp_timeout = opt_nat()) < 0)
                goto opt_err;
            break;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        case OPT_OCSP_STATUS:
            opt_ocsp_status = 1;
            break;
#endif
#endif
        case OPT_V_CASES/* OPT_CRLALL etc. */:
            if (!opt_verify(o, vpm))
                goto bad_ops;
            break;
        case OPT_STOREPASS:
            opt_storepass = opt_str("storepass");
            break;
        case OPT_STOREFORM:
            opt_storeform_s = opt_str("storeform");
            break;
        case OPT_CERTFORM:
            opt_certform_s = opt_str("certform");
            break;
        case OPT_KEYFORM:
            opt_keyform_s = opt_str("keyform");
            break;
        case OPT_CRLFORM:
            opt_crlform_s = opt_str("crlform");
            break;
        case OPT_EXTRACERTS:
            opt_extracerts = opt_str("extracerts");
            break;
        case OPT_SUBJECT:
            opt_subject = opt_str("subject");
            break;
        case OPT_ISSUER:
            opt_issuer = opt_str("issuer");
            break;
        case OPT_RECIPIENT:
            opt_recipient = opt_str("recipient");
            break;
        case OPT_EXPECTED_SENDER:
            opt_expected_sender = opt_str("expected_sender");
            break;
        case OPT_REQEXTS:
            opt_reqexts = opt_str("reqexts");
            break;

        case OPT_EXTRACERTSOUT:
            opt_extracertsout = opt_str("extracertsout");
            break;
        case OPT_CACERTSOUT:
            opt_cacertsout = opt_str("cacertsout");
            break;

        case OPT_DISABLECONFIRM:
            opt_disableConfirm = 1;
            break;
        case OPT_IMPLICITCONFIRM:
            opt_implicitConfirm = 1;
            break;
        case OPT_UNPROTECTEDREQUESTS:
            opt_unprotectedRequests = 1;
            break;
        case OPT_UNPROTECTEDERRORS:
            opt_unprotectedErrors = 1;
            break;
        case OPT_DAYS:
            if (!opt_int(opt_arg(), &opt_days))
                goto opt_err;
            break;
        case OPT_POPO:
            if ((opt_popo = opt_nat()) < 0)
                goto opt_err;
            break;

        case OPT_DIGEST:
            opt_digest = opt_str("digest");
            break;
        case OPT_OLDCERT:
            opt_oldcert = opt_str("oldcert");
            break;
        case OPT_CSR:
            opt_csr = opt_arg();
            break;
        case OPT_REVREASON:
            if (!opt_int(opt_arg(), &opt_revreason))
                goto opt_err;
            break;
        case OPT_INFOTYPE:
            opt_infotype_s = opt_str("infotype");
            break;
        case OPT_GENINFO:
            opt_geninfo = opt_str("geninfo");
            break;
#ifndef OPENSSL_NO_ENGINE
        case OPT_ENGINE:
            opt_engine = opt_str("engine");
            break;
#endif
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    if (argc != 0) {
        BIO_printf(bio_err, "%s: Unknown parameter %s\n", prog, argv[0]);
        goto opt_err;
    }
#else /* OPENSSL_VERSION_NUMBER */
    /* parse commandline options */
    ++argv;
    while (--argc > 0) {
        int found = 0;
        const OPTIONS *opt;
        char *arg;
        if (args_verify(&argv, &argc, &badops, bio_err, &vpm)) { /* OPT_CRLALL etc. */
            if (badops)
                goto bad_ops;
            continue;
        }
        arg = *argv;

        if (*arg == 0 || *arg++ != '-')
            {
            badops=1;
            break;
            }

        /* starting with index 0 to consume also OPT_CONFIG and OPT_SECTION,
           which have already been handled */
        for (i = 0, opt = &cmp_options[0+OPT_HELP]; opt->name; i++, opt++) {
            if (!strcmp(opt->name, OPT_HELP_STR) || !strcmp(opt->name, OPT_MORE_STR)) {
                i--;
                continue;
            }
            if (OPT_V__FIRST < opt->retval && opt->retval < OPT_V__LAST)
                opt += (OPT_V__LAST-1) - (OPT_V__FIRST+1);
            if (opt->name && !strcmp(arg, opt->name)) {
                if (argc <= 1 && opt->valtype != '-') {
                    BIO_printf(bio_err, "missing argument for '-%s'\n", opt->name);
                    badops = 1;
                    goto bad_ops;
                }
                switch(opt->valtype) {
                case '-':
                    *cmp_vars[i].num = 1;
                    break;
                case 'n':
                    *cmp_vars[i].num = atoi(*++argv);
                    argc--;
                    break;
                case 'l':
                    *cmp_vars[i].num_long = atol(*++argv);
                    argc--;
                    break;
                case 's':
                    *cmp_vars[i].txt = *++argv;
                    if (**argv == '\0') {
                        BIO_printf(bio_c_out,
                                   "Warning: argument of -%s option is empty string, resetting option\n",
                                   opt->name);
                        *cmp_vars[i].txt = NULL;
                    }
                    else if (**argv == '-') {
                        BIO_printf(bio_c_out,
                                   "Warning: argument of -%s option starts with hyphen\n", opt->name);
                    }
                    argc--;
                    break;
                default:
                    badops = 1;
                    break;
                }
                found = 1;
            }
        }

        if (!found) {
            BIO_printf(bio_err, "unknown argument: '%s'\n", *argv);
            badops = 1;
            goto bad_ops;
        }
        ++argv;
    }
#endif /* OPENSSL_VERSION_NUMBER */

 bad_ops:
    if (badops) {
        opt_help(cmp_options);
        goto err;
    }

    if (opt_engine)
        e = setup_engine_no_default(opt_engine, 0);
    cmp_ctx = CMP_CTX_create();
    if (!cmp_ctx || !setup_ctx(cmp_ctx, e)) {
        BIO_puts(bio_err, "error creating new cmp context\n");
        goto err;
    }

    /*
     * everything is ready, now connect and perform the command!
     */
    switch (opt_cmd) {
    case CMP_IR:
        newcert = CMP_exec_IR_ses(cmp_ctx);
        if (!newcert)
            goto err;
        break;
    case CMP_KUR:
        newcert = CMP_exec_KUR_ses(cmp_ctx);
        if (!newcert)
            goto err;
        break;
    case CMP_CR:
        newcert = CMP_exec_CR_ses(cmp_ctx);
        if (!newcert)
            goto err;
        break;
    case CMP_P10CR:
        newcert = CMP_exec_P10CR_ses(cmp_ctx);
        if (!newcert)
            goto err;
        break;
    case CMP_RR:
        if (!CMP_exec_RR_ses(cmp_ctx))
            goto err;
        break;
    case CMP_GENM:
        {
        STACK_OF(CMP_INFOTYPEANDVALUE) *itavs;
        if (opt_infotype != NID_undef) {
            CMP_INFOTYPEANDVALUE *itav = CMP_ITAV_new(OBJ_nid2obj(opt_infotype), NULL);
            if (!itav)
                goto err;
            CMP_CTX_genm_itav_push0(cmp_ctx, itav);
        }

        if (!(itavs = CMP_exec_GENM_ses(cmp_ctx)))
            goto err;
        print_itavs(itavs);
        sk_CMP_INFOTYPEANDVALUE_pop_free(itavs, CMP_INFOTYPEANDVALUE_free);
        break;
        }
    default:
        break;
    }

    if (opt_cacertsout && CMP_CTX_caPubs_num(cmp_ctx) > 0) {
        STACK_OF(X509) *certs = CMP_CTX_caPubs_get1(cmp_ctx);
        if (certs == NULL || save_certs(certs, opt_cacertsout, "CA") < 0) {
            sk_X509_pop_free(certs, X509_free);
            goto err;
        }
        sk_X509_pop_free(certs, X509_free);
    }

    if (opt_extracertsout && CMP_CTX_extraCertsIn_num(cmp_ctx) > 0) {
        STACK_OF(X509) *certs = CMP_CTX_extraCertsIn_get1(cmp_ctx);
        if (certs == NULL || save_certs(certs, opt_extracertsout, "extra") < 0) {
            sk_X509_pop_free(certs, X509_free);
            goto err;
        }
        sk_X509_pop_free(certs, X509_free);
    }

    if (opt_certout && newcert) {
        STACK_OF(X509) *certs = sk_X509_new_null();
        if (certs == NULL || !sk_X509_push(certs, X509_dup(newcert)) ||
                save_certs(certs, opt_certout, "enrolled") < 0) {
            sk_X509_pop_free(certs, X509_free);
            goto err;
        }
        sk_X509_pop_free(certs, X509_free);
    }

    ret = EXIT_SUCCESS;
 err:
    if (ret != EXIT_SUCCESS)
        ERR_print_errors_fp(stderr);

    CMP_CTX_delete(cmp_ctx);
    X509_VERIFY_PARAM_free(vpm);
    X509_STORE_free(out_trusted);
    BIO_free(bio_c_out);
    release_engine(e);

    /* if we ended up here without proper cleaning */
    if (opt_storepass)
        OPENSSL_cleanse(opt_storepass, strlen(opt_storepass));
    if (opt_keypass)
        OPENSSL_cleanse(opt_keypass, strlen(opt_keypass));
    if (opt_newkeypass)
        OPENSSL_cleanse(opt_newkeypass, strlen(opt_newkeypass));
    if (opt_tls_keypass)
        OPENSSL_cleanse(opt_tls_keypass, strlen(opt_tls_keypass));
    if (opt_secret)
        OPENSSL_cleanse(opt_secret, strlen(opt_secret));
    NCONF_free(conf); /* must not do as long as opt_... variables are used */
    OPENSSL_free(tofree);

    return ret;
}
