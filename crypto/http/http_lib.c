/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/http.h>
#include <openssl/httperr.h>
#include <openssl/err.h>
#include <string.h>

/*
 * Parse a URL and split it up into host, port and path components and
 * whether it indicates SSL/TLS. Return 1 on success, 0 on error.
 */

int OSSL_HTTP_parse_url(const char *url, char **phost, char **pport,
                        char **ppath, int *pssl)
{
    char *p, *buf;
    char *host, *port;

    if (url == NULL
        || phost == NULL || pport == NULL || ppath == NULL || pssl == NULL) {
        HTTPerr(0, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    *phost = NULL;
    *pport = NULL;
    *ppath = NULL;

    /* dup the buffer since we are going to mess with it */
    if ((buf = OPENSSL_strdup(url)) == NULL)
        goto err;

    /* Check for initial colon */
    p = strchr(buf, ':');
    if (p == NULL)
        goto parse_err;
    *(p++) = '\0';

    if (strcmp(buf, "http") == 0) {
        *pssl = 0;
        port = "80";
    } else if (strcmp(buf, "https") == 0) {
        *pssl = 1;
        port = "443";
    } else
        goto parse_err;

    /* Check for double slash */
    if ((p[0] != '/') || (p[1] != '/'))
        goto parse_err;
    p += 2;
    host = p;

    /* Check for trailing part of path */
    p = strchr(p, '/');
    if (p == NULL)
        *ppath = OPENSSL_strdup("/");
    else {
        *ppath = OPENSSL_strdup(p);
        /* Set start of path to 0 so hostname is valid */
        *p = '\0';
    }
    if (*ppath == NULL)
        goto err;

    p = host;
    if (host[0] == '[') {
        /* ipv6 literal */
        host++;
        p = strchr(host, ']');
        if (p == NULL)
            goto parse_err;
        *p = '\0';
        p++;
    }
    if ((*phost = OPENSSL_strdup(host)) == NULL)
        goto err;

    /* Look for optional ':' for port number */
    if ((p = strchr(p, ':'))) {
        *p = 0;
        port = p + 1;
    }
    if ((*pport = OPENSSL_strdup(port)) == NULL)
        goto err;

    OPENSSL_free(buf);
    return 1;

 parse_err:
    HTTPerr(0, HTTP_R_ERROR_PARSING_URL);

 err:
    OPENSSL_free(*ppath);
    *ppath = NULL;
    OPENSSL_free(*pport);
    *pport = NULL;
    OPENSSL_free(*phost);
    *phost = NULL;
    OPENSSL_free(buf);
    return 0;
}
