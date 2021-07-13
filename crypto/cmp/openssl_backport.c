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

#include <string.h>
#include <openssl/cmp_util.h>
#include "cmp_local.h" /* just for decls of internal functions defined here */
#include "../crmf/crypto/crmferr.h"
#include "crypto/cmperr.h"
#include <openssl/err.h> /* should be implied by cmperr.h */
#include <openssl/x509v3.h>

#include "e_os.h" /* ossl_sleep() */

#if OPENSSL_VERSION_NUMBER < 0x10101000L
/* used below and needed also by crmf_err.c and cmp_err.c */
int ERR_load_strings_const(const ERR_STRING_DATA *str)
{
#  if OPENSSL_VERSION_NUMBER < 0x10100006L
    ERR_load_strings(0, (ERR_STRING_DATA *)(str));
    return 1;
#  else
    return ERR_load_strings(0, (ERR_STRING_DATA *)str);
#  endif
}
# endif

/*
 * auxiliary function for incrementally reporting texts via the error queue
 */
static void put_error(int lib, const char *func, int reason,
                      const char *file, int line)
{
#if 0
    ERR_new();
    ERR_set_debug(file, line, func);
    ERR_set_error(lib, reason, NULL /* no data here, so fmt is NULL */);
#else
    ERR_put_error(lib, 0*strlen(func), reason, file, line);
#endif
}

#define ERR_PRINT_BUF_SIZE 4096 /* size of char buf[] variable there */
#define TYPICAL_MAX_OUTPUT_BEFORE_DATA 100
#define MAX_DATA_LEN (ERR_PRINT_BUF_SIZE-TYPICAL_MAX_OUTPUT_BEFORE_DATA)
void ossl_cmp_add_error_txt(const char *separator, const char *txt)
{
    const char *file = NULL;
    int line;
    const char *func = NULL;
    const char *data = NULL;
    int flags;
    unsigned long err = ERR_peek_last_error();

    if (separator == NULL)
        separator = "";
    if (err == 0)
        put_error(ERR_LIB_CMP, NULL, 0, "", 0);

    do {
        size_t available_len, data_len;
        const char *curr = txt, *next = txt;
        char *tmp;

        ERR_peek_last_error_all(&file, &line, &func, &data, &flags);
        if ((flags & ERR_TXT_STRING) == 0) {
            data = "";
            separator = "";
        }
        data_len = strlen(data);

        /* workaround for limit of ERR_print_errors_cb() */
        if (data_len >= MAX_DATA_LEN
                || strlen(separator) >= (size_t)(MAX_DATA_LEN - data_len))
            available_len = 0;
        else
            available_len = MAX_DATA_LEN - data_len - strlen(separator) - 1;
        /* MAX_DATA_LEN > available_len >= 0 */

        if (separator[0] == '\0') {
            const size_t len_next = strlen(next);

            if (len_next <= available_len) {
                next += len_next;
                curr = NULL; /* no need to split */
            }
            else {
                next += available_len;
                curr = next; /* will split at this point */
            }
        } else {
            while (*next != '\0' && (size_t)(next - txt) <= available_len) {
                curr = next;
                next = strstr(curr, separator);
                if (next != NULL)
                    next += strlen(separator);
                else
                    next = curr + strlen(curr);
            }
            if ((size_t)(next - txt) <= available_len)
                curr = NULL; /* the above loop implies *next == '\0' */
        }
        if (curr != NULL) {
            /* split error msg at curr since error data would get too long */
            if (curr != txt) {
                tmp = OPENSSL_strndup(txt, curr - txt);
                if (tmp == NULL)
                    return;
                ERR_add_error_data(2, separator, tmp);
                OPENSSL_free(tmp);
            }
            put_error(ERR_LIB_CMP, func, err, file, line);
            txt = curr;
        } else {
            ERR_add_error_data(2, separator, txt);
            txt = next; /* finished */
        }
    } while (*txt != '\0');
}

int ossl_x509_print_ex_brief(BIO *bio, X509 *cert, unsigned long neg_cflags)
{
    unsigned long flags = ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_ESC_QUOTE |
        XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN;

    if (cert == NULL)
        return BIO_printf(bio, "    (no certificate)\n") > 0;
    if (BIO_printf(bio, "    certificate\n") <= 0
            || !X509_print_ex(bio, cert, flags, ~X509_FLAG_NO_SUBJECT))
        return 0;
    if (X509_check_issued((X509 *)cert, cert) == X509_V_OK) {
        if (BIO_printf(bio, "        self-issued\n") <= 0)
            return 0;
    } else {
        if (BIO_printf(bio, " ") <= 0
            || !X509_print_ex(bio, cert, flags, ~X509_FLAG_NO_ISSUER))
            return 0;
    }
    if (!X509_print_ex(bio, cert, flags,
                       ~(X509_FLAG_NO_SERIAL | X509_FLAG_NO_VALIDITY)))
        return 0;
    if (X509_cmp_current_time(X509_get0_notBefore(cert)) > 0)
        if (BIO_printf(bio, "        not yet valid\n") <= 0)
            return 0;
    if (X509_cmp_current_time(X509_get0_notAfter(cert)) < 0)
        if (BIO_printf(bio, "        no more valid\n") <= 0)
            return 0;
    return X509_print_ex(bio, cert, flags,
                         ~neg_cflags & ~X509_FLAG_EXTENSIONS_ONLY_KID);
}

#if 0
/*IMPLEMENT_ASN1_DUP_FUNCTION(X509_PUBKEY)*/
/*
 * X509_PUBKEY_dup() must be implemented manually, because there is no
 * support for it in ASN1_EXTERN_FUNCS.
 */
X509_PUBKEY *X509_PUBKEY_dup(/*const */X509_PUBKEY *a)
{
    X509_PUBKEY *pubkey = NULL;

    if (!x509_pubkey_ex_new(NULL, ASN1_ITEM_rptr(X509_PUBKEY_INTERNAL))
        || !x509_pubkey_set0_libctx(pubkey, a->libctx, a->propq)
        || (pubkey->algor = X509_ALGOR_dup(a->algor)) == NULL
        || (pubkey->public_key = ASN1_BIT_STRING_new()) == NULL
        || !ASN1_BIT_STRING_set(pubkey->public_key,
                                a->public_key->data, a->public_key->length)
        || (a->pkey != NULL && !EVP_PKEY_up_ref(a->pkey))) {
        x509_pubkey_ex_free((ASN1_VALUE **)&pubkey,
                            ASN1_ITEM_rptr(X509_PUBKEY_INTERNAL));
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    pubkey->pkey = a->pkey;
    return pubkey;
}
#endif

int x509_set0_libctx(ossl_unused X509 *x, ossl_unused OSSL_LIB_CTX *libctx, ossl_unused const char *propq)
{
    return 1;
}

int ossl_x509v3_cache_extensions(X509 *x)
{
    X509_check_ca(x);

    return 1;
}


int X509_self_signed(X509 *cert, ossl_unused int verify_signature)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return X509_check_issued(cert, cert) == X509_V_OK;
#else
    return (X509_get_extension_flags(cert) & EXFLAG_SS) != 0;
#endif
}

int ossl_x509_add_cert_new(STACK_OF(X509) **p_sk, X509 *cert, int flags)
{
    if (*p_sk == NULL && (*p_sk = sk_X509_new_null()) == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return X509_add_cert(*p_sk, cert, flags);
}

int X509_add_cert(STACK_OF(X509) *sk, X509 *cert, int flags)
{
    if (sk == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((flags & X509_ADD_FLAG_NO_DUP) != 0) {
        /*
         * not using sk_X509_set_cmp_func() and sk_X509_find()
         * because this re-orders the certs on the stack
         */
        int i;

        for (i = 0; i < sk_X509_num(sk); i++) {
            if (X509_cmp(sk_X509_value(sk, i), cert) == 0)
                return 1;
        }
    }
    if ((flags & X509_ADD_FLAG_NO_SS) != 0 && X509_self_signed(cert, 0))
        return 1;
    if (!sk_X509_insert(sk, cert,
                        (flags & X509_ADD_FLAG_PREPEND) != 0 ? 0 : -1)) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if ((flags & X509_ADD_FLAG_UP_REF) != 0)
        (void)X509_up_ref(cert);
    return 1;
}

int X509_add_certs(STACK_OF(X509) *sk, STACK_OF(X509) *certs, int flags)
/* compiler would allow 'const' for the certs, yet they may get up-ref'ed */
{
    if (sk == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    return ossl_x509_add_certs_new(&sk, certs, flags);
}

int ossl_x509_add_certs_new(STACK_OF(X509) **p_sk, STACK_OF(X509) *certs,
                            int flags)
/* compiler would allow 'const' for the certs, yet they may get up-ref'ed */
{
    int n = sk_X509_num(certs /* may be NULL */);
    int i;

    for (i = 0; i < n; i++) {
        int j = (flags & X509_ADD_FLAG_PREPEND) == 0 ? i : n - 1 - i;
        /* if prepend, add certs in reverse order to keep original order */

        if (!ossl_x509_add_cert_new(p_sk, sk_X509_value(certs, j), flags))
            return 0;
    }
    return 1;
}

/* calculate cert digest using the same hash algorithm as in its signature */
ASN1_OCTET_STRING *X509_digest_sig(const X509 *cert,
                                   EVP_MD **md_used, int *md_is_fallback)
{
    unsigned int len;
    unsigned char hash[EVP_MAX_MD_SIZE];
    int mdnid, pknid;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    const
#endif
    EVP_MD *md = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    const char *md_name;
#endif
    ASN1_OCTET_STRING *new;

    if (md_used != NULL)
        *md_used = NULL;
    if (md_is_fallback != NULL)
        *md_is_fallback = 0;

    if (cert == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!OBJ_find_sigid_algs(X509_get_signature_nid(cert), &mdnid, &pknid)) {
        ERR_raise(ERR_LIB_X509, X509_R_UNKNOWN_SIGID_ALGS);
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (mdnid == NID_undef) {
        if (pknid == EVP_PKEY_RSA_PSS) {
            RSA_PSS_PARAMS *pss = ossl_rsa_pss_decode(&cert->sig_alg);
            const EVP_MD *mgf1md, *mmd = NULL;
            int saltlen, trailerfield;

            if (pss == NULL
                || !ossl_rsa_pss_get_param_unverified(pss, &mmd, &mgf1md,
                                                      &saltlen,
                                                      &trailerfield)
                ||  mmd == NULL) {
                RSA_PSS_PARAMS_free(pss);
                ERR_raise(ERR_LIB_X509, X509_R_UNSUPPORTED_ALGORITHM);
                return NULL;
            }
            RSA_PSS_PARAMS_free(pss);
            /* Fetch explicitly and do not fallback */
            if ((md = EVP_MD_fetch(cert->libctx, EVP_MD_get0_name(mmd),
                                   cert->propq)) == NULL)
                /* Error code from fetch is sufficient */
                return NULL;
        } else
        if (pknid != NID_undef) {
            /* A known algorithm, but without a digest */
            switch (pknid) {
            case NID_ED25519: /* Follow CMS default given in RFC8419 */
                md_name = "SHA512";
                break;
            case NID_ED448: /* Follow CMS default given in RFC8419 */
                md_name = "SHAKE256";
                break;
            default: /* Fall back to SHA-256 */
                md_name = "SHA256";
                break;
            }
            if ((md = EVP_MD_fetch(cert->libctx, md_name,
                                   cert->propq)) == NULL)
                return NULL;
            if (md_is_fallback != NULL)
                *md_is_fallback = 1;
        } else {
            /* A completely unknown algorithm */
            ERR_raise(ERR_LIB_X509, X509_R_UNSUPPORTED_ALGORITHM);
            return NULL;
        }
    } else if ((md = EVP_MD_fetch(cert->libctx, OBJ_nid2sn(mdnid),
                                  cert->propq)) == NULL
               && (md = (EVP_MD *)EVP_get_digestbynid(mdnid)) == NULL) {
        ERR_raise(ERR_LIB_X509, X509_R_UNSUPPORTED_ALGORITHM);
        return NULL;
    }
#else
    if ((md = EVP_get_digestbynid(mdnid)) == NULL) {
        ERR_raise(ERR_LIB_CMP, X509_R_UNSUPPORTED_ALGORITHM);
        return NULL;
    }
#endif
    if (!X509_digest(cert, md, hash, &len)
            || (new = ASN1_OCTET_STRING_new()) == NULL)
        goto err;
    if ((ASN1_OCTET_STRING_set(new, hash, len))) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (md_used != NULL)
            *md_used = md;
        else
            EVP_MD_free(md);
#endif
        return new;
    }
    ASN1_OCTET_STRING_free(new);
 err:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_free(md);
#endif
    return NULL;
}

static const char *_file_;
static int _line_;
static const char *_func_;
void ERR_set_debug(const char *file, int line, const char *func)
{
    _file_ = file;
    _line_ = line;
    _func_ = func;
}
void ERR_raise_data_(ossl_unused int lib, int reason, const char *fmt, ...)
{
    va_list ap;
    char buf[200] = "";

    if (_func_ != NULL) /* workaround for missing function name */
        snprintf(buf, sizeof(buf), "%s():", _func_);
    ERR_PUT_error(lib, 0, reason, _file_, _line_);
    va_start(ap, fmt);
    vsnprintf(buf + strlen(buf), sizeof(buf) -  strlen(buf), fmt, ap);
    va_end(ap);
    ERR_add_error_txt("", buf);
    /* sorry, does not support any further calls to ERR_add_error_txt() */
}

char *ossl_sk_ASN1_UTF8STRING2text(STACK_OF(ASN1_UTF8STRING) *text,
                                   const char *sep,
                                   size_t max_len /* excl. NUL terminator */)
{
    int i;
    ASN1_UTF8STRING *current;
    size_t length = 0, sep_len;
    char *result = NULL;
    char *p;

    if (!ossl_assert(sep != NULL))
        return NULL;
    sep_len = strlen(sep);

    for (i = 0; i < sk_ASN1_UTF8STRING_num(text); ++i) {
        current = sk_ASN1_UTF8STRING_value(text, i);
        if (i > 0)
            length += sep_len;
        length += ASN1_STRING_length(current);
        if (length > max_len)
            return NULL;
    }
    if ((result = OPENSSL_malloc(length + 1)) == NULL)
        return NULL;

    for (i = 0, p = result; i < sk_ASN1_UTF8STRING_num(text); ++i) {
        current = sk_ASN1_UTF8STRING_value(text, i);
        length = ASN1_STRING_length(current);
        if (i > 0 && sep_len > 0) {
            strncpy(p, sep, sep_len + 1);
            p += sep_len;
        }
        strncpy(p, (const char *)ASN1_STRING_get0_data(current), length);
        p += length;
    }
    *p = '\0';

    return result;
}

void ERR_add_error_mem_bio(const char *separator, BIO *bio)
{
    if (bio != NULL) {
        char *str;
        long len = BIO_get_mem_data(bio, &str);

        if (len > 0) {
            if (str[len - 1] != '\0') {
                if (BIO_write(bio, "", 1) <= 0)
                    return;

                len = BIO_get_mem_data(bio, &str);
            }
            if (len > 1)
                ERR_add_error_txt(separator, str);
        }
    }
}

/*
 * Return 0 if time should not be checked or reference time is in range,
 * or else 1 if it is past the end, or -1 if it is before the start
 */
int X509_cmp_timeframe(const X509_VERIFY_PARAM *vpm,
                       const ASN1_TIME *start, const ASN1_TIME *end)
{
    time_t ref_time;
    time_t *time = NULL;
    unsigned long flags = vpm == NULL ? 0 : X509_VERIFY_PARAM_get_flags((X509_VERIFY_PARAM *)vpm);

    if ((flags & X509_V_FLAG_USE_CHECK_TIME) != 0) {
        ref_time = X509_VERIFY_PARAM_get_time(vpm);
        time = &ref_time;
    } else if ((flags & X509_V_FLAG_NO_CHECK_TIME) != 0) {
        return 0; /* this means ok */
    } /* else reference time is the current time */

    if (end != NULL && X509_cmp_time(end, time) < 0)
        return 1;
    if (start != NULL && X509_cmp_time(start, time) > 0)
        return -1;
    return 0;
}

/* TODO param type could be constified as change to lock is intermittent */
STACK_OF(X509) *X509_STORE_get1_all_certs(X509_STORE *store)
{
    STACK_OF(X509) *sk;
    STACK_OF(X509_OBJECT) *objs;
    int i;

    if (store == NULL) {
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if ((sk = sk_X509_new_null()) == NULL)
        return NULL;
    X509_STORE_lock(store);
    objs = X509_STORE_get0_objects(store);
    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        X509 *cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));

        if (cert != NULL
            && !X509_add_cert(sk, cert, X509_ADD_FLAG_UP_REF))
            goto err;
    }
    X509_STORE_unlock(store);
    return sk;

 err:
    X509_STORE_unlock(store);
    sk_X509_pop_free(sk, X509_free);
    return NULL;
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#if !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)

/* from apps.h */
# ifndef openssl_fdset
#  if defined(OPENSSL_SYSNAME_WIN32) \
   || defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WINCE)
#   define openssl_fdset(a,b) FD_SET((unsigned int)a, b)
#  else
#   define openssl_fdset(a,b) FD_SET(a, b)
#  endif
# endif

/* from bio_sock.c */
/*
 * Wait on fd at most until max_time; succeed immediately if max_time == 0.
 * If for_read == 0 then assume to wait for writing, else wait for reading.
 * Returns -1 on error, 0 on timeout, and 1 on success.
 */
static int BIO_socket_wait(int fd, int for_read, time_t max_time)
{
    fd_set confds;
    struct timeval tv;
    time_t now;

    if (fd < 0 || fd >= FD_SETSIZE)
        return -1;
    if (max_time == 0)
        return 1;

    now = time(NULL);
    if (max_time <= now)
        return 0;

    FD_ZERO(&confds);
    openssl_fdset(fd, &confds);
    tv.tv_usec = 0;
    tv.tv_sec = (long)(max_time - now); /* might overflow */
    return select(fd + 1, for_read ? &confds : NULL,
                  for_read ? NULL : &confds, NULL, &tv);
}

/* from bio_lib.c */
/* Internal variant of the below BIO_wait() not calling BIOerr() */
static int bio_wait(BIO *bio, time_t max_time, unsigned int nap_milliseconds)
{
#ifndef OPENSSL_NO_SOCK
    int fd;
#endif
    long sec_diff;

    if (max_time == 0) /* no timeout */
        return 1;

#ifndef OPENSSL_NO_SOCK
    if (BIO_get_fd(bio, &fd) > 0 && fd < FD_SETSIZE)
        return BIO_socket_wait(fd, BIO_should_read(bio), max_time);
#endif
    /* fall back to polling since no sockets are available */

    sec_diff = (long)(max_time - time(NULL)); /* might overflow */
    if (sec_diff < 0)
        return 0; /* clearly timeout */

    /* now take a nap at most the given number of milliseconds */
    if (sec_diff == 0) { /* we are below the 1 seconds resolution of max_time */
        if (nap_milliseconds > 1000)
            nap_milliseconds = 1000;
    } else { /* for sec_diff > 0, take min(sec_diff * 1000, nap_milliseconds) */
        if ((unsigned long)sec_diff * 1000 < nap_milliseconds)
            nap_milliseconds = (unsigned int)sec_diff * 1000;
    }
    ossl_sleep(nap_milliseconds);
    return 1;
}

/* from bio_lib.c */
/*-
 * Wait on (typically socket-based) BIO at most until max_time.
 * Succeed immediately if max_time == 0.
 * If sockets are not available support polling: succeed after waiting at most
 * the number of nap_milliseconds in order to avoid a tight busy loop.
 * Call BIOerr(...) on timeout or error.
 * Returns -1 on error, 0 on timeout, and 1 on success.
 */
int BIO_wait(BIO *bio, time_t max_time, unsigned int nap_milliseconds)
{
    int rv = bio_wait(bio, max_time, nap_milliseconds);

    if (rv <= 0)
        ERR_raise(ERR_LIB_BIO,
                  rv == 0 ? BIO_R_TRANSFER_TIMEOUT : BIO_R_TRANSFER_ERROR);
    return rv;
}

/* from bio_lib.c */
/*
 * Connect via given BIO using BIO_do_connect() until success/timeout/error.
 * Parameter timeout == 0 means no timeout, < 0 means exactly one try.
 * For non-blocking and potentially even non-socket BIOs perform polling with
 * the given density: between polls sleep nap_milliseconds using BIO_wait()
 * in order to avoid a tight busy loop.
 * Returns -1 on error, 0 on timeout, and 1 on success.
 */
int BIO_do_connect_retry(BIO *bio, int timeout, int nap_milliseconds)
{
    int blocking = timeout <= 0;
    time_t max_time = timeout > 0 ? time(NULL) + timeout : 0;
    int rv;

    if (bio == NULL) {
        ERR_raise(ERR_LIB_BIO, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    if (nap_milliseconds < 0)
        nap_milliseconds = 100;
    BIO_set_nbio(bio, !blocking);

 retry:
    ERR_set_mark();
    rv = BIO_do_connect(bio);

    if (rv <= 0) { /* could be timeout or retryable error or fatal error */
        int err = ERR_peek_last_error();
        int reason = ERR_GET_REASON(err);
        int do_retry = BIO_should_retry(bio); /* may be 1 only if !blocking */

        if (ERR_GET_LIB(err) == ERR_LIB_BIO) {
            switch (reason) {
            case ERR_R_SYS_LIB:
                /*
                 * likely retryable system error occurred, which may be
                 * EAGAIN (resource temporarily unavailable) some 40 secs after
                 * calling getaddrinfo(): Temporary failure in name resolution
                 * or a premature ETIMEDOUT, some 30 seconds after connect()
                 */
            case BIO_R_CONNECT_ERROR:
            case BIO_R_NBIO_CONNECT_ERROR:
                /* some likely retryable connection error occurred */
                (void)BIO_reset(bio); /* often needed to avoid retry failure */
                do_retry = 1;
                break;
            default:
                break;
            }
        }
        if (timeout >= 0 && do_retry) {
            ERR_pop_to_mark();
            /* will not actually wait if timeout == 0 (i.e., blocking BIO): */
            rv = bio_wait(bio, max_time, nap_milliseconds);
            if (rv > 0)
                goto retry;
            ERR_raise(ERR_LIB_BIO,
                      rv == 0 ? BIO_R_CONNECT_TIMEOUT : BIO_R_CONNECT_ERROR);
        } else {
            ERR_clear_last_mark();
            rv = -1;
            if (err == 0) /* missing error queue entry */
                /* workaround: general error */
                ERR_raise(ERR_LIB_BIO, BIO_R_CONNECT_ERROR);
        }
    } else {
        ERR_clear_last_mark();
    }

    return rv;
}
#  endif /* !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK) */

BIO *ASN1_item_i2d_mem_bio(const ASN1_ITEM *it, const ASN1_VALUE *val)
{
    BIO *res;

    if (it == NULL || val == NULL) {
        ERR_raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if ((res = BIO_new(BIO_s_mem())) == NULL)
        return NULL;
    if (ASN1_item_i2d_bio(it, res, val) <= 0) {
        BIO_free(res);
        res = NULL;
    }
    return res;
}

STACK_OF(X509) *X509_build_chain(X509 *cert, STACK_OF(X509) *certs,
                                 X509_STORE *store, int with_self_signed,
                                 OSSL_LIB_CTX *libctx, const char *propq)
{
    STACK_OF(X509) *chain = NULL, *result = NULL;
    X509_STORE *ts = store == NULL ? X509_STORE_new() : store;
    X509_STORE_CTX *csc = NULL;
    int flags = X509_ADD_FLAG_UP_REF;

    if (ts == NULL || cert == NULL) {
        ERR_raise(ERR_LIB_CMP, CMP_R_NULL_ARGUMENT);
        goto err;
    }

    if ((csc = X509_STORE_CTX_new_ex(libctx, propq)) == NULL)
        goto err;
    if (store == NULL && certs != NULL
            && !ossl_cmp_X509_STORE_add1_certs(ts, certs, 0))
        goto err;
    if (!X509_STORE_CTX_init(csc, ts, cert,
                             store == NULL ? NULL : certs))
        goto err;
    /* disable any cert status/revocation checking etc. */
    X509_VERIFY_PARAM_clear_flags(X509_STORE_CTX_get0_param(csc),
                                  ~(X509_V_FLAG_USE_CHECK_TIME
                                    | X509_V_FLAG_NO_CHECK_TIME));

    if (X509_verify_cert(csc) <= 0 && store != NULL)
        goto err;
    chain = X509_STORE_CTX_get0_chain(csc);
    if (sk_X509_num(chain) > 1 && !with_self_signed)
        flags |= X509_ADD_FLAG_NO_SS;

    if (!ossl_x509_add_certs_new(&result, chain, flags)) {
        sk_X509_free(result);
        result = NULL;
    }

 err:
    if (store == NULL)
        X509_STORE_free(ts);
    X509_STORE_CTX_free(csc);
    return result;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100005L
/*
 * Given a buffer of length 'len' return a OPENSSL_malloc'ed string with its
 * hex representation @@@ (Contents of buffer are always kept in ASCII, also
 * on EBCDIC machines)
 */
char *OPENSSL_buf2hexstr(const unsigned char *buffer, long len)
{
    static const char hexdig[] = "0123456789ABCDEF";
    char *tmp, *q;
    const unsigned char *p;
    int i;

    if ((tmp = OPENSSL_malloc(len * 3 + 1)) == NULL) {
        CRYPTOerr(0 /* CRYPTO_F_OPENSSL_BUF2HEXSTR */, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    q = tmp;
    for (i = 0, p = buffer; i < len; i++, p++) {
        *q++ = hexdig[(*p >> 4) & 0xf];
        *q++ = hexdig[*p & 0xf];
        *q++ = ':';
    }
    q[-1] = 0;
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(tmp, tmp, q - tmp - 1);
#endif

    return tmp;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100002L
size_t OPENSSL_strlcpy(char *dst, const char *src, size_t size)
{
    size_t l = 0;
    for (; size > 1 && *src; size--) {
        *dst++ = *src++;
        l++;
    }
    if (size)
        *dst = '\0';
    return l + strlen(src);
}
#endif
