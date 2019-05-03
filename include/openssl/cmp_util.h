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

#ifndef OSSL_HEADER_CMP_UTIL_H
# define OSSL_HEADER_CMP_UTIL_H

# include <openssl/opensslconf.h>
# ifndef OPENSSL_NO_CMP

#  include <openssl/x509.h>

#  ifdef  __cplusplus
extern "C" {
#  endif

/*
 * logging - could be generally useful
 */

/* declarations resemble those from bio/bss_log.c and syslog.h */
typedef enum {OSSL_LOG_EMERG, OSSL_LOG_ALERT, OSSL_LOG_CRIT, OSSL_LOG_ERR,
              OSSL_LOG_WARNING, OSSL_LOG_NOTICE, OSSL_LOG_INFO, OSSL_LOG_DEBUG}
    OSSL_CMP_severity;

# if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901)
#  define OSSL_CMP_FUNC __func__
# elif defined(__STDC__) && defined(PEDANTIC)
#  define OSSL_CMP_FUNC "(PEDANTIC disallows function name)"
# elif defined(WIN32) || defined(__GNUC__) || defined(__GNUG__)
#  define OSSL_CMP_FUNC __FUNCTION__
# elif defined(__FUNCSIG__)
#  define OSSL_CMP_FUNC __FUNCSIG__
# else
#  define OSSL_CMP_FUNC "(unknown function)"
# endif
# define OSSL_CMP_FUNC_FILE_LINE OSSL_CMP_FUNC, OPENSSL_FILE, OPENSSL_LINE
# define OSSL_CMP_FL_EMERG OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_EMERG
# define OSSL_CMP_FL_ALERT OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_ALERT
# define OSSL_CMP_FL_CRIT  OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_CRIT
# define OSSL_CMP_FL_ERR   OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_ERR
# define OSSL_CMP_FL_WARN  OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_WARNING
# define OSSL_CMP_FL_NOTE  OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_NOTICE
# define OSSL_CMP_FL_INFO  OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_INFO
# define OSSL_CMP_FL_DEBUG OSSL_CMP_FUNC_FILE_LINE, OSSL_LOG_DEBUG

int  OSSL_CMP_log_open(void);
void OSSL_CMP_log_close(void);
int OSSL_CMP_puts(const char *component, const char *file, int lineno,
                  OSSL_CMP_severity level, const char *msg);
typedef int (*OSSL_cmp_log_cb_t) (const char *component,
                                  const char *file, int lineno,
                                  OSSL_CMP_severity level, const char *msg);
int OSSL_CMP_log_printf(OSSL_cmp_log_cb_t log_fn,
                        const char *func, const char *file, int lineno,
                        OSSL_CMP_severity level, const char *fmt, va_list argp);

void OSSL_CMP_add_error_txt(const char *separator, const char *txt);
# define OSSL_CMP_add_error_data(txt) OSSL_CMP_add_error_txt(" : ", txt)
# define OSSL_CMP_add_error_line(txt) OSSL_CMP_add_error_txt("\n", txt)
void OSSL_CMP_print_errors_cb(OSSL_cmp_log_cb_t log_fn);

/*
 * misc other functions that could be generally useful
 */

int OSSL_CMP_sk_X509_add1_cert (STACK_OF(X509) *sk, X509 *cert,
                                int not_duplicate, int prepend);
int OSSL_CMP_sk_X509_add1_certs(STACK_OF(X509) *sk, const STACK_OF(X509) *certs,
                                int no_self_signed, int no_duplicates);
int OSSL_CMP_X509_STORE_add1_certs(X509_STORE *store, STACK_OF(X509) *certs,
                                   int only_self_signed);
STACK_OF(X509) *OSSL_CMP_X509_STORE_get1_certs(X509_STORE *store);
X509_EXTENSIONS *OSSL_CMP_X509_EXTENSIONS_dup(const X509_EXTENSIONS *e);
int OSSL_CMP_ASN1_OCTET_STRING_set1(ASN1_OCTET_STRING **tgt,
                                    const ASN1_OCTET_STRING *src);
int OSSL_CMP_ASN1_OCTET_STRING_set1_bytes(ASN1_OCTET_STRING **tgt,
                                          const unsigned char *bytes,
                                          size_t len);

#   ifdef  __cplusplus
}
#   endif
# endif /* !defined OPENSSL_NO_CMP */
#endif /* !defined OSSL_HEADER_CMP_UTIL_H */
