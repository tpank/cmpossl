/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright Nokia 2007-2019
 * Copyright Siemens AG 2015-2019
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CMP_UTIL_H
# define OPENSSL_CMP_UTIL_H

# include <openssl/opensslconf.h>
# ifndef OPENSSL_NO_CMP

# ifndef CMP_STANDALONE
#  include <openssl/macros.h>
#  include <openssl/trace.h>
#endif
#  include <openssl/x509.h>

#  ifdef  __cplusplus
extern "C" {
#  endif

# ifdef CMP_STANDALONE
/*
 * logging
 */

/* declarations resemble those from bio/bss_log.c and syslog.h */
typedef int OSSL_CMP_severity;
#  define OSSL_CMP_LOG_EMERG   0
#  define OSSL_CMP_LOG_ALERT   1
#  define OSSL_CMP_LOG_CRIT    2
#  define OSSL_CMP_LOG_ERR     3
#  define OSSL_CMP_LOG_WARNING 4
#  define OSSL_CMP_LOG_NOTICE  5
#  define OSSL_CMP_LOG_INFO    6
#  define OSSL_CMP_LOG_DEBUG   7

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901)
# define OSSL_CMP_FUNC __func__
#elif defined(__STDC__) && defined(PEDANTIC)
# define OSSL_CMP_FUNC "(PEDANTIC disallows function name)"
#elif defined(WIN32) || defined(__GNUC__) || defined(__GNUG__)
# define OSSL_CMP_FUNC __FUNCTION__
#elif defined(__FUNCSIG__)
# define OSSL_CMP_FUNC __FUNCSIG__
#else
# define OSSL_CMP_FUNC "(unknown function)"
#endif
#define OSSL_CMP_FUNC_FILE_LINE OSSL_CMP_FUNC, OPENSSL_FILE, OPENSSL_LINE
#define OSSL_CMP_FL_EMERG OSSL_CMP_FUNC_FILE_LINE, OSSL_CMP_LOG_EMERG
#define OSSL_CMP_FL_ALERT OSSL_CMP_FUNC_FILE_LINE, OSSL_CMP_LOG_ALERT
#define OSSL_CMP_FL_CRIT  OSSL_CMP_FUNC_FILE_LINE, OSSL_CMP_LOG_CRIT
#define OSSL_CMP_FL_ERR   OSSL_CMP_FUNC_FILE_LINE, OSSL_CMP_LOG_ERR
#define OSSL_CMP_FL_WARN  OSSL_CMP_FUNC_FILE_LINE, OSSL_CMP_LOG_WARNING
#define OSSL_CMP_FL_NOTE  OSSL_CMP_FUNC_FILE_LINE, OSSL_CMP_LOG_NOTICE
#define OSSL_CMP_FL_INFO  OSSL_CMP_FUNC_FILE_LINE, OSSL_CMP_LOG_INFO
#define OSSL_CMP_FL_DEBUG OSSL_CMP_FUNC_FILE_LINE, OSSL_CMP_LOG_DEBUG

int OSSL_CMP_puts(const char *component, const char *file, int lineno,
                  OSSL_CMP_severity level, const char *msg);
int OSSL_CMP_printf(const OSSL_CMP_CTX *ctx,
                    const char *func, const char *file, int lineno,
                    OSSL_CMP_severity level, const char *fmt, ...);
#define ossl_cmp_alert(ctx, msg) OSSL_CMP_printf(ctx, OSSL_CMP_FL_ALERT, msg)
#define ossl_cmp_err(ctx, msg)   OSSL_CMP_printf(ctx, OSSL_CMP_FL_ERR  , msg)
#define ossl_cmp_warn(ctx, msg)  OSSL_CMP_printf(ctx, OSSL_CMP_FL_WARN , msg)
#define ossl_cmp_info(ctx, msg)  OSSL_CMP_printf(ctx, OSSL_CMP_FL_INFO , msg)
#define ossl_cmp_debug(ctx, msg) OSSL_CMP_printf(ctx, OSSL_CMP_FL_DEBUG, msg)
int  OSSL_CMP_log_init(void);
void OSSL_CMP_log_close(void);

typedef int (*OSSL_CMP_log_cb_t) (const char *component,
                                  const char *file, int lineno,
                                  OSSL_CMP_severity level, const char *msg);

STACK_OF(X509) *ossl_cmp_build_cert_chain(X509_STORE *store,
                                          STACK_OF(X509) *certs, X509 *cert);
# else /* ifdef CMP_STANDALONE */
/*
 * convenience functions for CMP-specific logging via the trace API
 */

/* Helper macros for CPP string composition */
#  define OSSL_CMP_MSTR_HELPER(x) #x
#  define OSSL_CMP_MSTR(x) OSSL_CMP_MSTR_HELPER(x)

int  OSSL_CMP_log_open(void);
void OSSL_CMP_log_close(void);
#  define OSSL_CMP_LOG_PREFIX "CMP "
/* in OSSL_CMP_LOG_START, cannot use OPENSSL_FUNC when expands to __func__ */
#  define OSSL_CMP_LOG_START "%s:" OPENSSL_FILE ":" \
    OSSL_CMP_MSTR(OPENSSL_LINE) ":" OSSL_CMP_LOG_PREFIX
#  define ossl_cmp_alert(msg) ossl_cmp_log(ALERT, msg)
#  define ossl_cmp_err(msg)   ossl_cmp_log(ERROR, msg)
#  define ossl_cmp_warn(msg)  ossl_cmp_log(WARN, msg)
#  define ossl_cmp_info(msg)  ossl_cmp_log(INFO, msg)
#  define ossl_cmp_debug(msg) ossl_cmp_log(DEBUG, msg)
#  define ossl_cmp_log(level, msg) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": %s\n", \
                      OPENSSL_FUNC, msg))
#  define ossl_cmp_log1(level, fmt, arg1) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": " fmt "\n", \
                      OPENSSL_FUNC, arg1))
#  define ossl_cmp_log2(level, fmt, arg1, arg2) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": " fmt "\n", \
                      OPENSSL_FUNC, arg1, arg2))
#  define ossl_cmp_log3(level, fmt, arg1, arg2, arg3) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": " fmt "\n", \
                      OPENSSL_FUNC, arg1, arg2, arg3))
#  define ossl_cmp_log4(level, fmt, arg1, arg2, arg3, arg4) \
    OSSL_TRACEV(CMP, (trc_out, OSSL_CMP_LOG_START#level ": " fmt "\n", \
                      OPENSSL_FUNC, arg1, arg2, arg3, arg4))

/*
 * generalized logging/error callback mirroring the severity levels of syslog.h
 */
typedef int OSSL_CMP_severity;
#  define OSSL_CMP_LOG_EMERG   0
#  define OSSL_CMP_LOG_ALERT   1
#  define OSSL_CMP_LOG_CRIT    2
#  define OSSL_CMP_LOG_ERR     3
#  define OSSL_CMP_LOG_WARNING 4
#  define OSSL_CMP_LOG_NOTICE  5
#  define OSSL_CMP_LOG_INFO    6
#  define OSSL_CMP_LOG_DEBUG   7
typedef int (*OSSL_CMP_log_cb_t)(const char *func, const char *file, int line,
                                 OSSL_CMP_severity level, const char *msg);

/* use of the logging callback for outputting error queue */
void OSSL_CMP_print_errors_cb(OSSL_CMP_log_cb_t log_fn);
# endif /* ifdef CMP_STANDALONE */

#  ifdef  __cplusplus
}
#  endif
# endif /* !defined OPENSSL_NO_CMP */
#endif /* !defined OPENSSL_CMP_UTIL_H */
