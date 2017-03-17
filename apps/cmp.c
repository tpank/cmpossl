/*
 * vim: set cinoptions={1s: 
 */
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

/*
 * ============================== TODO List ==============================
 * TODO: actually send the genm for requesting the CKUANN message 
 */

#include <openssl/opensslconf.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include "s_apps.h"

#define CONFIG_FILE "openssl.cnf"
#define CMP_SECTION "cmp"
static char *opt_section = CMP_SECTION;

#undef PROG
#define PROG    cmp_main
char *prog = "cmp";

#include <openssl/crypto.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static CONF *conf = NULL;       /* OpenSSL config file context structure */
static BIO *bio_c_out = NULL;   /* OpenSSL BIO for printing to STDOUT */

/*
 * the type of cmp command we want to send 
 */
typedef enum { CMP_IR,
    CMP_KUR,
    CMP_CR,
    CMP_RR,
    CMP_CKUANN,
} cmp_cmd_t;

static char *opt_server = NULL;
static char *server_address = NULL;
static long server_port = 0;

static long  opt_use_tls = 0;
static char *opt_tls_cert = NULL;
static char *opt_tls_key = NULL;
static char *opt_tls_keypass = NULL;
static char *opt_tls_trusted = NULL;
static char *opt_tls_crls = NULL;
static long  opt_tls_cdps = 0;
static long  opt_tls_crl_all = 0;

static char *opt_path = "/";
static char *opt_cmd_s = NULL;
static int opt_cmd = -1;

static char *opt_user = NULL;
static char *opt_pass = NULL;
static char *opt_cert = NULL;
static char *opt_key = NULL;
static char *opt_keypass = NULL;

static char *opt_certout = NULL;
static char *opt_newkey = NULL;
static char *opt_newkeypass = NULL;

static char *opt_srvcert = NULL;
static char *opt_trusted = NULL;
static char *opt_untrusted = NULL;
static char *opt_crls = NULL;
static long  opt_cdps = 0;
static long  opt_crl_all = 0;

static char *opt_keyfmt_s = "PEM";
static char *opt_certfmt_s = "PEM";
static int opt_keyfmt = FORMAT_PEM;
static int opt_certfmt = FORMAT_PEM;
static int opt_crlfmt = FORMAT_PEM; // default to be tried first for file input; TODO maybe add cmd line arg

static char *opt_extcerts = NULL;
static char *opt_subject = NULL;
static char *opt_issuer = NULL;
static char *opt_recipient = NULL;
static long  opt_popo = -1;
static char *opt_reqexts = NULL;
static long  opt_disableConfirm = 0;
static long  opt_implicitConfirm = 0;
static long  opt_unprotectedErrors = 0;
static char *opt_digest = NULL;
static char *opt_oldcert = NULL;
static long  opt_revreason = -1;

static char *opt_cacertsout = NULL;
static char *opt_extracertsout = NULL;

static char *opt_proxy = NULL;
static long opt_proxyPort = 0;

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_SECTION,
    OPT_SERVER, OPT_PROXY, OPT_PROXYPORT,
    OPT_USETLS, OPT_TLSCERT, OPT_TLSKEY, OPT_TLSKEYPASS,
    OPT_TLSTRUSTED, OPT_TLSCRLS, OPT_TLSCDPS, OPT_TLSCRLALL,
    OPT_USER, OPT_PASS, OPT_CERT, OPT_KEY, OPT_KEYPASS, OPT_EXTCERTS,
    OPT_SRVCERT, OPT_TRUSTED, OPT_UNTRUSTED, 
    OPT_CRLS, OPT_CDPS, OPT_CRLALL,
    OPT_RECIPIENT, OPT_PATH, OPT_CMD,
    OPT_NEWKEY, OPT_NEWKEYPASS, OPT_SUBJECT, OPT_ISSUER, 
    OPT_POPO,
    OPT_REQEXTS,
    OPT_DISABLECONFIRM, OPT_IMPLICITCONFIRM, OPT_UNPROTECTEDERRORS,
    OPT_DIGEST, OPT_OLDCERT, OPT_REVREASON,
    OPT_CACERTSOUT, OPT_CERTOUT, OPT_EXTRACERTSOUT,
    OPT_KEYFMT, OPT_CERTFMT,
} OPTION_CHOICE;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
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
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
const
#endif
OPTIONS cmp_options[] = {
    // OPTION_CHOICE values must be in the same order as enumerated above!!
    {"help", OPT_HELP, '-', "Display this summary"},
    {"section", OPT_SECTION, 's', "Name of section in OpenSSL config file defining cmp default options. Default 'cmp'"},

    {"server", OPT_SERVER, 's', "The 'address:port' of the CMP server (domain name or IP address)"},
    {"proxy", OPT_PROXY, 's', "Address of HTTP proxy server, if needed for accessing the CMP server"},
    {"proxyport", OPT_PROXYPORT, 'l', "Port of the HTTP proxy server"},

    {"use-tls", OPT_USETLS, '-', "Force using TLS (even when other TLS-related options are not set) when connecting to CMP server"},
    {"tls-cert", OPT_TLSCERT, 's', "Client's TLS certificate. PEM format may also include certificate chain to be provided to server"},
    {"tls-key", OPT_TLSKEY, 's', "Key for the client's TLS certificate"},
    {"tls-keypass", OPT_TLSKEYPASS, 's', "Password for the client's TLS key"},

    {"tls-trusted", OPT_TLSTRUSTED, 's', "Client's trusted certificates for verifying TLS certificates.\n"
                                "\t\t     This implies host name validation"},
    {"tls-crls", OPT_TLSCRLS, 's', "Use given CRL(s) as primary source when verifying TLS certificates.\n"
                          "\t\t     URL may point to local file if prefixed by 'file:'"},
    {"tls-cdps", OPT_TLSCDPS, '-', "Retrieve CRLs from distribution points given in certificates as secondary source\n"
                          "\t\t     while verifying TLS certificates"},
    {"tls-crl-all", OPT_TLSCRLALL, '-', "Check CRLs not only for TLS server but also for TLS CA certificates"},

    {"user", OPT_USER, 's', "Username for client authentication with a pre-shared key"},
    {"pass", OPT_PASS, 's', "Password for client authentication with a pre-shared key (password-based MAC)"},
    {"cert", OPT_CERT, 's', "Client's current certificate (needed unless using PSK)"},
    {"key", OPT_KEY, 's', "Key for the client's current certificate"},
    {"keypass", OPT_KEYPASS, 's', "Password for the client key"},
    {"extcerts", OPT_EXTCERTS, 's', "Certificates to include in the extraCerts field of request"},

    {"srvcert", OPT_SRVCERT, 's', "certificate of CMP server to be used as recipient and for verifying the protection of replies"},
    {"trusted", OPT_TRUSTED, 's', "Trusted certificates for CMP server authentication"},
    {"untrusted", OPT_UNTRUSTED, 's', "Untrusted certificates for path construction in CMP server authentication"},
    {"crls", OPT_CRLS, 's', "Use given CRL(s) as primary source when verifying CMP server certificates.\n"
                   "\t\t     URL may point to local file if prefixed by 'file:'"},
    {"cdps", OPT_CDPS, '-', "Retrieve CRLs from distribution points given in certificates as secondary source\n"
                   "\t\t     when verifying CMP server certificates"},
    {"crl-all", OPT_CRLALL, '-', "Check CRLs not only for CMP server but also for the whole certificate chain"},

    {"recipient", OPT_RECIPIENT, 's', "Distinguished Name of the recipient to use unless the -srvcert option is given.\n"
                             "\t\t     If both are not set, the recipient defaults to the -issuer argument.\n"
                             "\t\t     For RR, the recipient defaults to the issuer of the certificate to be revoked"},
    {"path", OPT_PATH, 's', "HTTP path location inside the server (aka CMP alias)"},
    {"cmd", OPT_CMD, 's', "CMP command to execute: ir/cr/kur/rr/..."},

    {"newkey", OPT_NEWKEY, 's', "Key corresponding to the requested certificate. Default is current client certificate's key if given."},
    {"newkeypass", OPT_NEWKEYPASS, 's', "Password for the key for corresponding to the requested certificate"},
    {"subject", OPT_SUBJECT, 's', "X509 subject name to be used in the requested certificate template"},
    {"issuer", OPT_ISSUER, 's', "Distinguished Name of the issuer, to be put in the requested certificate template"},
    {"popo", OPT_POPO, 'l', "Set Proof-of-Possession (POPO) method.\n"
                   "\t\t     0 = NONE, 1 = SIGNATURE (default), 2 = ENCRCERT, 3 = RAVERIFIED"},
    {"reqexts", OPT_REQEXTS, 's', "Name of section in OpenSSL config file defining certificate request extensions"},

    {"disableconfirm", OPT_DISABLECONFIRM, '-', "Do not confirm enrolled certificates"},
    {"implicitconfirm", OPT_IMPLICITCONFIRM, '-', "Request implicit confirmation of enrolled certificate"},
    {"unprotectederrors", OPT_UNPROTECTEDERRORS, '-', "Accept unprotected error responses: regular error messages as well as\n"
                       "\t\t     certificate responses (IP/CP/KUP) and revocation responses (RP) with rejection"},

    {"digest", OPT_DIGEST, 's', "Digest to be used in message protection and Proof-of-Possession signatures. Defaults to 'sha256'"},
    {"oldcert", OPT_OLDCERT, 's', "Certificate to be renewed in KUR or to be revoked in RR"},
    {"revreason", OPT_REVREASON, 'l', "Set reason code to be included in revocation request (RR).\n"
                       "\t\t     Values: 0..10 (see RFC5280, 5.3.1). None set by default"},

    {"cacertsout", OPT_CACERTSOUT, 's', "File to save received CA certificates"},
    {"certout", OPT_CERTOUT, 's', "File to save the newly enrolled certificate"},
    {"extracertsout", OPT_EXTRACERTSOUT, 's', "File to save received extra certificates"},

    // TODO: should be aligned to "keyform" as in other OpenSSL apps
    {"keyfmt", OPT_KEYFMT, 's', "Format (PEM/DER/P12) to try first when reading key files. Default PEM"},
    {"certfmt", OPT_CERTFMT, 's', "Format (PEM/DER/P12) to try first when reading certificate files. Default PEM.\n"
                             "\t\t     This also determines format to use for writing (not supported for P12)"},
    {NULL}
};

typedef union {
    char **txt;
    long *num;
} varref;
static varref cmp_vars[]= { // must be in the same order as enumerated above!!
    {&opt_section},
    {&opt_server}, {&opt_proxy}, { (char **)&opt_proxyPort},
    { (char **)&opt_use_tls}, {&opt_tls_cert}, {&opt_tls_key}, {&opt_tls_keypass},
    {&opt_tls_trusted}, {&opt_tls_crls}, { (char **)&opt_tls_cdps}, { (char **)&opt_tls_crl_all},
    {&opt_user}, {&opt_pass}, {&opt_cert}, {&opt_key}, {&opt_keypass}, {&opt_extcerts},
    {&opt_srvcert}, {&opt_trusted}, {&opt_untrusted},
    {&opt_crls}, { (char **)&opt_cdps}, { (char **)&opt_crl_all},
    {&opt_recipient}, {&opt_path}, {&opt_cmd_s},
    {&opt_newkey}, {&opt_newkeypass}, {&opt_subject}, {&opt_issuer},
    { (char **)&opt_popo},
    {&opt_reqexts},
    { (char **)&opt_disableConfirm}, { (char **)&opt_implicitConfirm}, { (char **)&opt_unprotectedErrors},
    {&opt_digest}, {&opt_oldcert}, { (char **)&opt_revreason},
    {&opt_cacertsout}, {&opt_certout}, {&opt_extracertsout},
    {&opt_keyfmt_s}, {&opt_certfmt_s},
};

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void opt_help(const OPTIONS *unused_arg) {
    const int ALIGN_COL = 18;
    const OPTIONS *o = cmp_options;
    int i=0,j=0;

    BIO_printf(bio_err, "\nusage: openssl %s args\n", prog);
    for (i=0; i < sizeof(cmp_options)/sizeof(cmp_options[0])-1; i++,o++)  {
        BIO_printf(bio_err, " -%s", o->name);
        for (j=ALIGN_COL-strlen(o->name); j > 0; j--)
            BIO_puts(bio_err, " ");
        BIO_printf(bio_err, " %s\n", o->helpstr);
    }
    BIO_puts(bio_err, "\n");
}
#endif

/*
 * ########################################################################## 
 * use the command line option table to read values from the [cmp] section 
 * of openssl.cnf.  Defaults are taken from the config file, they can be
 * overwritten on the command line.
 * ########################################################################## 
 */
static int read_config()
{
    unsigned int i = 0;

    // starting with i = 1 because OPT_SECTION has already been handled
    for (i = 1; i   < sizeof(cmp_vars   )/sizeof(cmp_vars   [0]) &&
         i+OPT_HELP < sizeof(cmp_options)/sizeof(cmp_options[0]); i++) {
        const OPTIONS *opt = &cmp_options[i+OPT_HELP];
        switch (opt->valtype) {
        case '-':
        case 'l':
            NCONF_get_number_e(conf, opt_section, opt->name, cmp_vars[i].num);
            break;
        case 's':
            *cmp_vars[i].txt = NCONF_get_string(conf, opt_section, opt->name);
            break;
        default:
            BIO_printf(bio_err, "internal error: unsupported type '%c' for option '%s'\n", opt->valtype, opt->name);
            return 0;
            break;
        }
    }

    ERR_clear_error();
    return 1;
}

/*
 * ########################################################################## 
 * * verify that all the necessary options have been set.
 * Prints reason for error to bio_err returns 1 on success, 0 on error
 * ########################################################################## 
 */
static int check_options(void)
{
    if (opt_server) {
        char *p = strrchr(opt_server, ':');
        size_t addrlen = 0;
        if (p == NULL) {
            BIO_puts(bio_err, "error: missing server port\n");
            goto err;
        }
        addrlen = (size_t)p - (size_t)opt_server;
        server_address = OPENSSL_malloc(addrlen + 1);
        if (server_address == NULL) {
            BIO_puts(bio_err, "error: out of memory\n");
            goto err;
        }
        strncpy(server_address, opt_server, addrlen);
        server_address[addrlen] = 0;
        server_port = atoi(++p);
	if (server_port <= 0) {
            BIO_printf(bio_err, "error: invalid server port number: %s\n", p);
            goto err;
	}
    } else {
        BIO_puts(bio_err, "error: missing server address:port\n");
        goto err;
    }

    if (opt_tls_trusted || opt_tls_crls || opt_tls_cdps || opt_tls_crl_all) {
        opt_use_tls = 1;
    }

    if (opt_tls_cert || opt_tls_key || opt_tls_keypass) {
        opt_use_tls = 1;
        if (!opt_tls_cert) {
            BIO_printf(bio_err, "error: missing -tls-cert option\n");
            goto err;
        }
        else if (!opt_tls_key) {
            BIO_printf(bio_err, "error: missing -tls-key option\n");
            goto err;
        }
    }

    if (opt_recipient && opt_srvcert) {
        BIO_puts(bio_err, "warning: -recipient option is ignored since -srvcert option is present\n");
    }

    if (opt_cmd_s) {
        if (!strcmp(opt_cmd_s, "ir"))
            opt_cmd = CMP_IR;
        else if (!strcmp(opt_cmd_s, "kur"))
            opt_cmd = CMP_KUR;
        else if (!strcmp(opt_cmd_s, "cr"))
            opt_cmd = CMP_CR;
        else if (!strcmp(opt_cmd_s, "rr"))
            opt_cmd = CMP_RR;
#if 0 // TODO
        else if (!strcmp(opt_cmd_s, "ckuann"))
            opt_cmd = CMP_CKUANN;
#endif
        else {
            BIO_printf(bio_err, "error: unknown cmp command '%s'\n",
                       opt_cmd_s);
            goto err;
        }
    } else {
        BIO_puts(bio_err, "error: no cmp command to execute\n");
        goto err;
    }

    if ((!opt_user) != (!opt_pass)) {
        BIO_puts(bio_err, "error: must give both -user and -pass options or neither of them\n");
        goto err;
    }
    if ((!opt_cert) != (!opt_key)) {
        BIO_puts(bio_err, "error: must give both -cert and -key options or neither of them\n");
        goto err;
    }
    if (opt_cmd != CMP_IR && !(opt_user && opt_pass) && !(opt_cert && opt_key)) {
        BIO_puts(bio_err,
                 "error: missing user/pass or certificate/key for client authentication\n");
        goto err;
    }
    if (opt_cert && !(opt_srvcert || opt_trusted)) {
        BIO_puts(bio_err,
                 "error: using client certificate but no server certificate or trusted certificates set\n");
        goto err;
    }

    if (opt_cmd == CMP_IR || opt_cmd == CMP_CR || opt_cmd == CMP_KUR) {
        if (!opt_newkey && !opt_key) {
            BIO_puts(bio_err, "error: missing key to be certified\n");
            goto err;
        }
        if (!opt_certout) {
            BIO_puts(bio_err,
                     "error: certout not given, nowhere to save certificate\n");
            goto err;
        }
    }

    if (opt_cmd == CMP_RR) {
        if (!opt_oldcert) {
            BIO_puts(bio_err, "error: missing certificate to be revoked\n");
            goto err;
        }
    }

    if (opt_popo < -1 || opt_popo > 3) {
        BIO_printf(bio_err, "error: invalid value for popo method (must be between 0 and 3): %ld\n", opt_popo);
        goto err;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (opt_keyfmt_s
        && !opt_format(opt_keyfmt_s, OPT_FMT_PEMDER | OPT_FMT_PKCS12, &opt_keyfmt)) {
        BIO_puts(bio_err, "error: unknown option given for key format\n");
        goto err;
    }

    if (opt_certfmt_s
        && !opt_format(opt_certfmt_s, OPT_FMT_PEMDER | OPT_FMT_PKCS12, &opt_certfmt)) {
        BIO_puts(bio_err, "error: unknown option given for key format\n");
        goto err;
    }
#else
    if (opt_keyfmt_s)
        opt_keyfmt=str2fmt(opt_keyfmt_s);

    if (opt_certfmt_s)
        opt_certfmt=str2fmt(opt_certfmt_s);
#endif

    return 1;

 err:
    return 0;
}

#if OPENSSL_VERSION_NUMBER < 0x1010001fL
#define X509_STORE_set_lookup_crls X509_STORE_set_lookup_crls_cb
#define ASN1_STRING_get0_data ASN1_STRING_data
#endif

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
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
/* declaration copied from apps/apps.c just for visibility reasons */
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
static int load_cert_crl_http(const char *url, X509 **pcert, X509_CRL **pcrl)
{
    char *host = NULL, *port = NULL, *path = NULL;
    BIO *bio = NULL;
    OCSP_REQ_CTX *rctx = NULL;
    int use_ssl, rv = 0;
    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl))
        goto err;
    if (use_ssl) {
        BIO_puts(bio_err, "https not supported\n");
        goto err;
    }
    bio = BIO_new_connect(host);
    if (!bio || !BIO_set_conn_port(bio, port))
        goto err;
    rctx = OCSP_REQ_CTX_new(bio, 1024);
    if (rctx == NULL)
        goto err;
    if (!OCSP_REQ_CTX_http(rctx, "GET", path))
        goto err;
    if (!OCSP_REQ_CTX_add1_header(rctx, "Host", host))
        goto err;
    if (pcert) {
        do {
            rv = X509_http_nbio(rctx, pcert);
        } while (rv == -1);
    } else {
        do {
            rv = X509_CRL_http_nbio(rctx, pcrl);
        } while (rv == -1);
    }

 err:
    OPENSSL_free(host);
    OPENSSL_free(path);
    OPENSSL_free(port);
    if (bio)
        BIO_free_all(bio);
    OCSP_REQ_CTX_free(rctx);
    if (rv != 1) {
        BIO_printf(bio_err, "Error loading %s from '%s'\n",
                   pcert ? "certificate" : "CRL", url);
        ERR_print_errors(bio_err);
    }
    return rv;
}
#endif
#else
#define load_cert_crl_http(url, pcert, pcrl) load_cert_crl_http(url, bio_err, pcert, pcrl)
#endif

/* TODO dvo: push that separately upstream with the autofmt options */
/* improved version of load_cert() found in apps/apps.c */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static X509 *load_cert_corrected_pkcs12(const char *file, int format, const char *pass, const char *cert_descrip)
{
    X509 *x = NULL;
    BIO *cert;
    EVP_PKEY *pkey = NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (format == FORMAT_HTTP) {
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
        load_cert_crl_http(file, &x, NULL);
#endif
        return x;
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
X509 *load_cert_corrected_pkcs12(const char *file, int format, const char *pass, const char *cert_descrip)
{
    X509 *x = NULL;
    BIO *cert;
  
    BIO *err = bio_err;
    EVP_PKEY *pkey = NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (format == FORMAT_HTTP) {
        load_cert_crl_http(file, &x, NULL);
        return x;
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

/* TODO dvo: push that separately upstream with the autofmt options */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L // compatibility declarations
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
    if (strncmp(*infile, "http://", 7) == 0)
        format = FORMAT_HTTP;
    else if (engine_ok && strncmp(*infile, "engine:", 7) == 0) {
        *infile += 7;
        format = FORMAT_ENGINE;
    }
    else {
        if (strncmp(*infile, "file:", 5) == 0)
            *infile += 5;
        // the following is a heuristic whether first to try PEM or DER or PKCS12 as the input format for files
        if (strlen(*infile) >= 4) {
            char *extension = (char *)(*infile + strlen(*infile) - 4);
            if (strncmp(extension, ".pem", 4) == 0) // weak recognition of PEM format
                format = FORMAT_PEM;
            else if (strncmp(extension, ".der", 4) == 0 ||
                     strncmp(extension, ".crt", 4) == 0 ||
                     strncmp(extension, ".crl", 4) == 0) // weak recognition of DER format
                format = FORMAT_ASN1;
            else if (strncmp(extension, ".p12", 4) == 0) // weak recognition of PKCS#12 format
                format = FORMAT_PKCS12;
            // else retain given format
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

<<<<<<< HEAD
/* TODO dvo: push that separately upstream */
/* in apps.c there is load_key which should be used for CMP upstream submission */
EVP_PKEY *load_key_autofmt(const char *infile, int format, const char *pass, const char *desc) {
    // BIO_printf(bio_c_out, "Loading %s from '%s'\n", desc, infile);
    char *pass_string = get_passwd(pass, desc);
    format = adjust_format(&infile, format, 1);
    EVP_PKEY *pkey = load_key(bio_err, infile, format, 0, pass_string, NULL, desc);
    if (pkey == NULL && format != FORMAT_HTTP && format != FORMAT_ENGINE)
        pkey = load_key(bio_err, infile, format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM, 0, pass_string, NULL, desc);
    if (!pkey) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from '%s'\n", desc, infile);
    }
    if (pass_string)
        OPENSSL_free(pass_string);
    return pkey;
}

/* TODO dvo: push that separately upstream */
/* this is exclusively used by load_certs_fmt */
X509 *load_cert_autofmt(const char *infile, int *format, const char *pass, const char *desc) {
    // BIO_printf(bio_c_out, "Loading %s from file '%s'\n", desc, infile);
    char *pass_string = get_passwd(pass, desc);
    *format = adjust_format(&infile, *format, 0);
    X509 *cert = load_cert_corrected_pkcs12(infile, *format, pass_string, desc);
    if (cert == NULL && *format != FORMAT_HTTP) {
        *format = (*format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM);
        cert = load_cert_corrected_pkcs12(infile, *format, pass_string, desc);
    }
    if (!cert) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from file '%s'\n", desc, infile);
    }
    OPENSSL_free(pass_string);
    return cert;
}

/* TODO dvo: push that separately upstream */
/* this is exclusively used by load_certs_autofmt */
STACK_OF(X509) *load_certs_fmt(const char *infile, int format, const char *desc) {
    if (format == FORMAT_PEM) {
        return load_certs(bio_err, infile, format, NULL, NULL, desc);
    } else {
        STACK_OF(X509) *certs = sk_X509_new_null();
        if (!certs)
            return NULL;
        X509 *cert = load_cert(bio_err, infile, format, NULL, NULL, desc);
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
STACK_OF(X509) *load_certs_autofmt(const char *infile, int format, const char *desc) {
    // BIO_printf(bio_c_out, "Loading %s from file '%s'\n", desc, infile);
    format = adjust_format(&infile, format, 0);
    STACK_OF(X509) *certs = load_certs_fmt(infile, format, desc);
    if (certs == NULL)
        certs = load_certs_fmt(infile, format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM, desc);
    if (!certs) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from file '%s'\n", desc, infile);
    }
    return certs;
}

<<<<<<< HEAD
/* TODO dvo: push that separately upstream */
/* this is exclusively used by load_crls_fmt */
X509_CRL *load_crl_autofmt(const char *infile, int format, const char *desc) {
    // BIO_printf(bio_c_out, "Loading %s from '%s'\n", desc, infile);
    format = adjust_format(&infile, format, 0);
    X509_CRL *crl = load_crl(infile, format);
    if (crl == NULL && format != FORMAT_HTTP)
        crl = load_crl(infile, format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM);
    return crl;
}

/* TODO dvo: push that separately upstream */
/* this is exclusively used by load_crls_autofmt */
STACK_OF(X509_CRL) *load_crls_fmt(const char *infile, int format, const char *desc) {
    if (format == FORMAT_PEM) {
        // BIO_printf(bio_c_out, "Loading %s from '%s'\n", desc, infile);
        return load_crls(bio_err, infile, format, NULL, NULL, desc);
    } else {
        STACK_OF(X509_CRL) *crls = sk_X509_CRL_new_null();
        if (!crls)
            return NULL;
        X509_CRL *crl = load_crl_autofmt(infile, format, desc);
        if (!crl) {
            sk_X509_CRL_free(crls);
            return NULL;
        }
        sk_X509_CRL_push(crls, crl);
        return crls;
    }
}

<<<<<<< HEAD
<<<<<<< HEAD
/* TODO dvo: push that separately upstream */
/* in apps.c there is load_crls which should be used for CMP upstream submission */
STACK_OF(X509_CRL) *load_crls_autofmt(const char *infile, int format, const char *desc) {
    format = adjust_format(&infile, format, 0);
    STACK_OF(X509_CRL) *crls = load_crls_fmt(infile, format, desc);
    if (crls == NULL && format != FORMAT_HTTP)
        crls = load_crls_fmt(infile, format == FORMAT_PEM ? FORMAT_ASN1 : FORMAT_PEM, desc);
    if (!crls) {
        ERR_print_errors(bio_err);
        BIO_printf(bio_err, "error: unable to load %s from '%s'\n", desc, infile);
    }
    return crls;
}

/*
 * ########################################################################## 
 * * create cert store structure with certificates read from given file
 * returns pointer to created X509_STORE on success, NULL on error
 * ########################################################################## 
 */
static X509_STORE *create_cert_store(const char *infile, const char *desc)
{
    X509_STORE *cert_ctx = NULL;
    X509_LOOKUP *lookup = NULL;

    if (opt_certfmt != FORMAT_PEM && opt_certfmt != FORMAT_ASN1)
        BIO_printf(bio_c_out, "warning: unsupported type '%s' for reading certificates, trying PEM, then DER\n", opt_certfmt_s);
    // BIO_printf(bio_c_out, "Loading %s from file '%s'\n", desc, infile);
    cert_ctx = X509_STORE_new();
    if (cert_ctx == NULL)
        goto err;

    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
    if (lookup == NULL)
        goto err;

    if (!X509_LOOKUP_load_file(lookup, infile,
                          opt_certfmt == FORMAT_ASN1 ? X509_FILETYPE_ASN1 : X509_FILETYPE_PEM)) {
        if (!X509_LOOKUP_load_file(lookup, infile,
                          opt_certfmt == FORMAT_ASN1 ? X509_FILETYPE_PEM : X509_FILETYPE_ASN1)) {
            goto err;
        }
    }

    return cert_ctx;

 err:
    ERR_print_errors(bio_err);
    BIO_printf(bio_err, "error: unable to load %s from file '%s'\n", desc, infile);
    return NULL;
}

/* TODO dvo: push that separately upstream
 * ########################################################################## 
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
            BIO_printf(bio_c_out, "Loading CRL via CDP entry in cert from URL '%s'\n", urlptr);
            return load_crl_autofmt(urlptr, FORMAT_HTTP, "CRL via CDP entry in certificate");
        }
    }
    return NULL;
}

/* TODO dvo: push that separately upstream */
/* THIS IS crls_http_cb() FROM AND LOCAL TO apps.c,
 * but using LOCAL_load_crl_crldp instead of the one from apps.c */
/*
 * Example of downloading CRLs from CRLDP: not usable for real world as it
 * always downloads, doesn't support non-blocking I/O and doesn't cache
 * anything.
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

/* TODO dvo: push that separately upstream
 *
 * This allows for local CRLs and remote lookup through the callback.
 * In upstream openssl, X509_STORE_CTX_init() sets up the STORE_CTX
 * so that CRLs already loaded to the store get ignored if a callback is set.
 *
 * First try local CRLs from store, then try downloading CRLs from CRLDP
 */

static STACK_OF(X509_CRL) *crls_local_then_http_cb(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    STACK_OF(X509_CRL) *crls;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    crls = X509_STORE_CTX_get1_crls(ctx, nm);
#else
    crls = X509_STORE_get1_crls(ctx, nm);
#endif
    if (crls == NULL)
        crls = LOCAL_crls_http_cb(ctx, nm);
    return crls;
}

/*
 * ########################################################################## 
 * * code for improving certificate error diagnostics
 * ########################################################################## 
 */

/*
 * This function is a callback used by OpenSSL's verify_cert function.
 * It's called at the end of a cert verification to allow an opportunity
 * to gather more information regarding a failing cert verification,
 * and to possibly change the result of the verification (not done here).
 */
static int print_cert_verify_cb (int ok, X509_STORE_CTX *ctx)
{
    if (ok == 0 && ctx != NULL) {
        int cert_error = X509_STORE_CTX_get_error(ctx);
        X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);
        BIO_printf(bio_err, "%s error=%d (%s) at depth=%d for subject='%s' issuer='%s'\n",
                   X509_STORE_CTX_get0_parent_ctx(ctx) ? "CRL path validation" : "cert verification",
                   cert_error, X509_verify_cert_error_string(cert_error),
                   X509_STORE_CTX_get_error_depth(ctx),
                   current_cert ? X509_NAME_oneline(X509_get_subject_name(current_cert), NULL, 0) : "(unknown)" ,
                   current_cert ? X509_NAME_oneline(X509_get_issuer_name(current_cert), NULL, 0) : "(unknown)");
    }
    return (ok);
}

/*
 * ########################################################################## 
 * * set up the CMP_CTX structure based on options from config file/CLI
 * prints reason for error to bio_err returns 1 on success, 0 on error
 * ########################################################################## 
 */
static int setup_ctx(CMP_CTX * ctx)
{
    int certfmt;

    CMP_CTX_set1_serverName(ctx, server_address);
    CMP_CTX_set1_serverPath(ctx, opt_path);
    CMP_CTX_set1_serverPort(ctx, server_port);

    if (opt_use_tls) {
        X509 *cert = NULL;
        EVP_PKEY *pkey = NULL;

        /* initialize OpenSSL's SSL lib */
        OpenSSL_add_ssl_algorithms();
        SSL_load_error_strings();

        SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_client_method());
        if (ssl_ctx == NULL) {
            goto err;
        }
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
        SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

        if (opt_tls_trusted) {
            X509_STORE *store;
            if (!(store=create_cert_store(opt_tls_trusted, "trusted TLS certificates"))) {
                goto tls_err;
            }
            SSL_CTX_set_cert_store(ssl_ctx, store);

#if OPENSSL_VERSION_NUMBER >= 0x10002000
            /* enable and parameterize server hostname/IP address check */
            X509_VERIFY_PARAM *param = SSL_CTX_get0_param(ssl_ctx);
            X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT|X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            X509_VERIFY_PARAM_set1_host(param, server_address, 0);
#endif
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, print_cert_verify_cb);
        }

        if (opt_tls_crls) {
            STACK_OF(X509_CRL) *crls = load_crls_autofmt(opt_tls_crls, opt_crlfmt, "CRL(s) for TLS");
            if (!crls) {
                goto tls_err;
            }
            ssl_ctx_add_crls(ssl_ctx, crls, 0);
        }
        if (opt_tls_cdps)
            X509_STORE_set_lookup_crls(SSL_CTX_get_cert_store(ssl_ctx), crls_local_then_http_cb);
            /* TODO dvo: to be replaced with "store_setup_crl_download(ts)" from apps.h,
               after extended version of crls_http_cb has been pushed upstream */
        if (opt_tls_crls || opt_tls_cdps || opt_tls_crl_all)
            X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ssl_ctx),
                                        X509_V_FLAG_CRL_CHECK | (opt_tls_crl_all ? X509_V_FLAG_CRL_CHECK_ALL: 0));

        if (opt_tls_cert && opt_tls_key) {
            certfmt = opt_certfmt;
            if (!(cert=load_cert_autofmt(opt_tls_cert, &certfmt, opt_tls_keypass, "TLS client certificate"))) {
                goto tls_err;
            }
            if (!(pkey=load_key_autofmt(opt_tls_key, opt_keyfmt, opt_tls_keypass, "TLS client private key"))) {
                goto tls_err;
            }

            if (certfmt == FORMAT_PEM) {
                if (SSL_CTX_use_certificate_chain_file(ssl_ctx, opt_tls_cert) <= 0) {
                    BIO_printf(bio_err, "error: unable to load and use client TLS certificate (and possibly extra certificates) '%s'\n", opt_tls_cert);
                    goto tls_err;
                }
            } else {
                if (SSL_CTX_use_certificate(ssl_ctx, cert) <= 0) {
                    BIO_printf(bio_err, "error: unable to use client TLS certificate '%s'\n", opt_tls_cert);
                    goto tls_err;
                }
                X509_free(cert); // we don't need the handle any more
                cert = NULL;
            }
            if (SSL_CTX_use_PrivateKey(ssl_ctx, pkey) <= 0) { 
                BIO_printf(bio_err, "error: unable to use TLS client private key '%s'\n", opt_tls_key);
                pkey = NULL; // otherwise, for some reason double free!
                goto tls_err;
            }
            // verify the key matches the cert
            if (!SSL_CTX_check_private_key(ssl_ctx)) {
                BIO_printf(bio_err, "error: TLS private key '%s' does not match the TLS certificate '%s'\n", opt_tls_key, opt_tls_cert);
                goto tls_err;
            }
            EVP_PKEY_free(pkey); // we don't need the handle any more
        }

        BIO *sbio = BIO_new_ssl(ssl_ctx, 1);
        if (!sbio) {
            BIO_printf(bio_err, "error: cannot initialize SSL BIO");
        tls_err:
            if (cert)
                X509_free(cert);
            if (pkey)
                EVP_PKEY_free(pkey);
            SSL_CTX_free(ssl_ctx);
            goto err;
        }
        CMP_CTX_set0_tlsBIO(ctx, sbio);
    }

    if (opt_user && opt_pass) {
        char *pass_string = NULL;
        if ((pass_string = get_passwd(opt_pass, "PBMAC"))) {
        CMP_CTX_set1_referenceValue(ctx, (unsigned char *)opt_user,
                                    strlen(opt_user));
        CMP_CTX_set1_secretValue(ctx, (unsigned char *)pass_string,
                                 strlen(pass_string));
        OPENSSL_free(pass_string);
        }
    }

    if (opt_key) {
        EVP_PKEY *pkey = load_key_autofmt(opt_key, opt_keyfmt, opt_keypass, "private key for CMP client certificate");
        if (!pkey || !CMP_CTX_set0_pkey(ctx, pkey))
            goto err;
    }
    if (opt_newkey) {
        EVP_PKEY *newPkey = load_key_autofmt(opt_newkey, opt_keyfmt, opt_newkeypass, "new private key for certificate to be enrolled");
        if (!newPkey || !CMP_CTX_set0_newPkey(ctx, newPkey))
            goto err;
    }
    
    certfmt = opt_certfmt;
    if (opt_cert) {
        X509 *clcert = load_cert_autofmt(opt_cert, &certfmt, opt_keypass, "CMP client certificate");
        if (!clcert || !CMP_CTX_set1_clCert(ctx, clcert))
            goto err;
        X509_free(clcert);
    }

    if (opt_extcerts) {
        STACK_OF(X509) *extracerts = load_certs_autofmt(opt_extcerts, opt_certfmt, "extra certificates");
        if (!extracerts || !CMP_CTX_set1_extraCertsOut(ctx, extracerts))
            goto err;
        sk_X509_pop_free(extracerts, X509_free);
    }

    certfmt = opt_certfmt;
    if (opt_srvcert) {
        X509 *srvcert = load_cert_autofmt(opt_srvcert, &certfmt, opt_keypass, "CMP server certificate");
        if (!srvcert || !CMP_CTX_set1_srvCert(ctx, srvcert))
            goto err;
        X509_free(srvcert);
    }

    if (opt_crls) {
        STACK_OF(X509_CRL) *crls = load_crls_autofmt(opt_crls, opt_crlfmt, "CRL(s) for CMP protection");
        if (!crls) {
            goto err;
        }
        CMP_CTX_set0_crls(ctx, crls);
    }

    if (opt_trusted) {
        X509_STORE *ts = create_cert_store(opt_trusted, "trusted certificates");

        X509_STORE_set_flags(ts,
                             opt_crls || opt_cdps || opt_crl_all ?
                               X509_V_FLAG_CRL_CHECK |
                                 (opt_crl_all ? X509_V_FLAG_CRL_CHECK_ALL : 0)
                               : 0);

        if (opt_cdps) {
            X509_STORE_set_lookup_crls(ts, crls_local_then_http_cb);
            /* TODO dvo: to be replaced with "store_setup_crl_download(ts)" from apps.h,
               after extended version of crls_http_cb has been pushed upstream */
        }

        if( !CMP_CTX_set0_trustedStore(ctx, ts))
            goto err;
    }

    if (opt_untrusted
        && !CMP_CTX_set0_untrustedStore(ctx, create_cert_store(opt_untrusted, "untrusted certificates"))) {
        goto err;
    }

    CMP_CTX_set_certVerify_callback(ctx, print_cert_verify_cb);

    if (opt_subject) {
        X509_NAME *n = parse_name(opt_subject, MBSTRING_ASC, 0);
        if (n == NULL) {
            BIO_printf(bio_err, "error: unable to parse subject name '%s'\n",
                       opt_subject);
            goto err;
        }
        if (!CMP_CTX_set1_subjectName(ctx, n))
            goto err;
        X509_NAME_free(n);
    }

    if (opt_issuer) {
        X509_NAME *n=parse_name(opt_issuer, MBSTRING_ASC, 0);
        if (n == NULL) {
            BIO_printf(bio_err, "error: unable to parse issuer name '%s'\n", opt_issuer);
            goto err;
        }
        CMP_CTX_set1_issuer(ctx, n);
        X509_NAME_free(n);
    }

    if (opt_recipient) {
        X509_NAME *n = parse_name(opt_recipient, MBSTRING_ASC, 0);
        if (n == NULL) {
            BIO_printf(bio_err,
                       "error: unable to parse recipient name '%s'\n",
                       opt_recipient);
            goto err;
        }
        if (!CMP_CTX_set1_recipient(ctx, n))
            goto err;
        X509_NAME_free(n);
    }

    if (opt_popo >= 0)
        CMP_CTX_set1_popoMethod(ctx, opt_popo);
    if (opt_reqexts) {
        X509V3_CTX ext_ctx;
        X509_EXTENSIONS *exts = sk_X509_EXTENSION_new_null();
        X509V3_set_ctx(&ext_ctx, NULL, NULL, NULL, NULL, 0);
        X509V3_set_nconf(&ext_ctx, conf);
        if (!X509V3_EXT_add_nconf_sk(conf, &ext_ctx, opt_reqexts, &exts)) {
            BIO_printf(bio_err, "error loading extension section '%s'\n", opt_reqexts);
            goto err;
        }
        CMP_CTX_set0_reqExtensions(ctx, exts);
    }

    if (opt_disableConfirm)
        CMP_CTX_set_option(ctx, CMP_CTX_OPT_DISABLECONFIRM, 1);

    if (opt_implicitConfirm)
        CMP_CTX_set_option(ctx, CMP_CTX_OPT_IMPLICITCONFIRM, 1);

    if (opt_unprotectedErrors)
        CMP_CTX_set_option(ctx, CMP_CTX_OPT_UNPROTECTED_ERRORS, 1);

    if (opt_digest) {
        int digest = OBJ_ln2nid(opt_digest);
        if (digest == NID_undef) {
            BIO_printf(bio_err, "error: digest algorithm name not recognized: '%s'\n", opt_digest);
            goto err;
        }
        CMP_CTX_set1_digest(ctx, digest);
    }

    certfmt = opt_certfmt;
    if (opt_oldcert) {
        X509 *oldcert = load_cert_autofmt(opt_oldcert, &certfmt, opt_keypass, "certificate to be renewed/revoked");
        if (!oldcert || !CMP_CTX_set1_oldClCert(ctx, oldcert))
            goto err;
        X509_free(oldcert);
    }

    if (opt_revreason >= 0)
        CMP_CTX_set_option(ctx, CMP_CTX_OPT_REVOCATION_REASON, opt_revreason);

    if (opt_proxy) {
        if (opt_proxyPort != 0) {
            CMP_CTX_set1_proxyName(ctx, opt_proxy);
            CMP_CTX_set1_proxyPort(ctx, opt_proxyPort);
        } else {
            BIO_printf(bio_err, "error: no port given for proxy at '%s'\n",
                       opt_proxy);
            goto err;
        }
    }

    CMP_CTX_set_HttpTimeOut(ctx, 5 * 60);

    return 1;

 err:
    return 0;
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
    if ((opt_certfmt == FORMAT_PEM && PEM_write_bio_X509(bio, cert))
        || (opt_certfmt == FORMAT_ASN1 && i2d_X509_bio(bio, cert)))
        return 1;
    if (opt_certfmt != FORMAT_PEM && opt_certfmt != FORMAT_ASN1)
        BIO_printf(bio_err, "error: unsupported type '%s' for writing certificates\n", opt_certfmt_s);
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
    X509 *cert = NULL;
    BIO *bio = NULL;
    int n = sk_X509_num(certs);

    BIO_printf(bio_c_out, "Received %d %s certificate%s, saving to file '%s'\n",
               n, desc, n == 1 ? "" : "s", destFile);
    if (n > 1 && opt_certfmt != FORMAT_PEM)
        BIO_printf(bio_c_out, "warning: saving more than one certificate in non-PEM format\n");

    if (!destFile || (bio = BIO_new(BIO_s_file())) == NULL ||
        !BIO_write_filename(bio, (char *)destFile)) {
        BIO_printf(bio_err, "ERROR: could not open file '%s' for writing\n", destFile);
        n = -1;
        goto err;
    }

    while ((cert = sk_X509_pop(certs)) != NULL) {
        if (!write_cert(bio, cert)) {
            BIO_printf(bio_err, "ERROR writing certificate to file '%s'\n", destFile);
            n = -1;
            goto err;
        }
    }

 err:
    if (bio)
        BIO_free(bio);
    return n;
}

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
    int ret = 1;
    CMP_CTX *cmp_ctx = NULL;
    X509 *newcert = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPTION_CHOICE o;
#endif

    if (argc <= 1) {
        badops = 1;
        goto bad_ops;
    }

    if (!strcmp(argv[1], "-help")) {
        opt_help(cmp_options);
        goto err;
    }

    bio_c_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    int i; // must handle OPT_SECTION upfront to take effect for all other args
    for (i = argc-2; i >= 0; i--)
        if (argv[i][0] == '-' && !strcmp(argv[i]+1, cmp_options[OPT_SECTION-OPT_HELP].name)) {
            opt_section = argv[i+1];
            break;
         }

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
    if (configfile) {
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
            if (!read_config())
                goto err;
        }
    }

    if (tofree) {
        OPENSSL_free(tofree);
        tofree = NULL;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    prog = opt_init(argc, argv, cmp_options);
    
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opt_err:
            // BIO_printf(bio_err, "%s: Use -help for the following summary.\n", prog);
            // goto err;
        case OPT_HELP:
            ret = 0;
            opt_help(cmp_options);
            goto err;
        case OPT_SECTION: // has already been handled
            break;

        case OPT_SERVER:
            opt_server = opt_arg();
            break;

        case OPT_USETLS:
            opt_use_tls = 1;
            break;
        case OPT_TLSCERT:
            opt_tls_cert = opt_arg();
            break;
        case OPT_TLSKEY:
            opt_tls_key = opt_arg();
            break;
        case OPT_TLSKEYPASS:
            opt_tls_keypass = opt_arg();
            break;
        case OPT_TLSTRUSTED:
            opt_tls_trusted = opt_arg();
            break;
        case OPT_TLSCRLS:
            opt_tls_crls = opt_arg();
            break;
        case OPT_TLSCDPS:
            opt_tls_cdps = 1;
            break;
        case OPT_TLSCRLALL:
            opt_tls_crl_all = 1;
            break;

        case OPT_PATH:
            opt_path = opt_arg();
            break;
        case OPT_CMD:
            opt_cmd_s = opt_arg();
            break;

        case OPT_USER:
            opt_user = opt_arg();
            break;
        case OPT_PASS:
            opt_pass = opt_arg();
            break;
        case OPT_CERT:
            opt_cert = opt_arg();
            break;
        case OPT_KEY:
            opt_key = opt_arg();
            break;
        case OPT_KEYPASS:
            opt_keypass = opt_arg();
            break;

        case OPT_CERTOUT:
            opt_certout = opt_arg();
            break;
        case OPT_NEWKEY:
            opt_newkey = opt_arg();
            break;
        case OPT_NEWKEYPASS:
            opt_newkeypass = opt_arg();
            break;
        case OPT_SRVCERT:
            opt_srvcert = opt_arg();
            break;
        case OPT_TRUSTED:
            opt_trusted = opt_arg();
            break;
        case OPT_UNTRUSTED:
            opt_untrusted = opt_arg();
            break;
        case OPT_CRLS:
            opt_crls = opt_arg();
            break;
        case OPT_CDPS:
            opt_cdps = 1;
            break;
        case OPT_CRLALL:
            opt_crl_all = 1;
            break;
        case OPT_KEYFMT:
            opt_keyfmt_s = opt_arg();
            break;
        case OPT_CERTFMT:
            opt_certfmt_s = opt_arg();
            break;
        case OPT_EXTCERTS:
            opt_extcerts = opt_arg();
            break;
        case OPT_SUBJECT:
            opt_subject = opt_arg();
            break;
        case OPT_ISSUER:
            opt_issuer = opt_arg();
            break;
        case OPT_RECIPIENT:
            opt_recipient = opt_arg();
            break;
        case OPT_REQEXTS:
            opt_reqexts = opt_arg();
            break;

        case OPT_EXTRACERTSOUT:
            opt_extracertsout = opt_arg();
            break;
        case OPT_CACERTSOUT:
            opt_cacertsout = opt_arg();
            break;
        case OPT_PROXY:
            opt_proxy = opt_arg();
            break;
        case OPT_PROXYPORT:
            if (!opt_long(opt_arg(), &opt_proxyPort))
                goto opt_err;
            break;

        case OPT_DISABLECONFIRM:
            opt_disableConfirm = 1;
            break;
        case OPT_IMPLICITCONFIRM:
            opt_implicitConfirm = 1;
            break;
        case OPT_UNPROTECTEDERRORS:
            opt_unprotectedErrors = 1;
            break;
        case OPT_POPO:
            if (!opt_long(opt_arg(), &opt_popo))
                goto opt_err;
            break;

        case OPT_DIGEST:
            opt_digest = opt_arg();
            break;
        case OPT_OLDCERT:
            opt_oldcert = opt_arg();
            break;
        case OPT_REVREASON:
            if (!opt_long(opt_arg(), &opt_revreason))
                goto opt_err;
            break;
        }
    }
#else /* OPENSSL_VERSION_NUMBER */
    /* parse commandline options */
    while (--argc > 0 && ++argv) {
        char *arg=*argv;
        int found,i;

        if (*arg++ != '-' || *arg == 0)
            {
            badops=1;
            break;
            }

        found=0;
        // starting with i = 1 because OPT_SECTION has already been handled
        for (i = 1; i   < sizeof(cmp_vars   )/sizeof(cmp_vars   [0]) &&
             i+OPT_HELP < sizeof(cmp_options)/sizeof(cmp_options[0]); i++) {
            const OPTIONS *opt = &cmp_options[i+OPT_HELP];
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
                case 'l':
                    *cmp_vars[i].num = atoi(*++argv);
                    argc--;
                    break;
                case 's':
                    *cmp_vars[i].txt = *++argv;
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
    }
#endif /* OPENSSL_VERSION_NUMBER */

    if (!badops)
        badops = check_options() == 0;

 bad_ops:
    if (badops) {
        opt_help(cmp_options);
        goto err;
    }

    if (!(cmp_ctx = CMP_CTX_create()) || !setup_ctx(cmp_ctx)) {
        BIO_puts(bio_err, "error creating new cmp context\n");
        goto err;
    }

    /*
     * everything is ready, now connect and perform the command! 
     */
    switch (opt_cmd) {
    case CMP_IR:
        newcert = CMP_doInitialRequestSeq(cmp_ctx);
        if (!newcert)
            goto err;
        break;
    case CMP_KUR:
        newcert = CMP_doKeyUpdateRequestSeq(cmp_ctx);
        if (!newcert)
            goto err;
        break;
    case CMP_CR:
        newcert = CMP_doCertificateRequestSeq(cmp_ctx);
        if (!newcert)
            goto err;
        break;
    case CMP_RR:
        if (CMP_doRevocationRequestSeq(cmp_ctx) == 0)
            goto err;
        break;
    case CMP_CKUANN:
        /*
         * TODO: sending the empty GENM to request the CKUANN 
         */
        break;
    default:
        break;
    }

    if (opt_cacertsout && CMP_CTX_caPubs_num(cmp_ctx) > 0 &&
        save_certs(CMP_CTX_caPubs_get1(cmp_ctx), opt_cacertsout, "CA") < 0)
        goto err;

    if (opt_extracertsout && CMP_CTX_extraCertsIn_num(cmp_ctx) > 0 &&
        save_certs(CMP_CTX_extraCertsIn_get1(cmp_ctx), opt_extracertsout, "extra") < 0)
        goto err;

    if (opt_certout && newcert) {
        STACK_OF(X509) *newcerts = sk_X509_new_null();
        if (!newcerts)
            goto err;
        sk_X509_push(newcerts, newcert);
        if (save_certs(newcerts, opt_certout, "enrolled") < 0)
            goto err;
        sk_X509_free(newcerts);
    }

    ret = 0;
 err:
    if (ret != 0)
        ERR_print_errors_fp(stderr);
    if (cmp_ctx)
        CMP_CTX_delete(cmp_ctx);

    return ret;
}
