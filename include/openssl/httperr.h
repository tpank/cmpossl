/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HTTPERR_H
# define OPENSSL_HTTPERR_H
# pragma once

# include <openssl/macros.h>
# if !OPENSSL_API_3
#  define HEADER_HTTPERR_H
# endif

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>


# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C"
# endif
int ERR_load_HTTP_strings(void);

/*
 * HTTP function codes.
 */
# if !OPENSSL_API_3
#   define HTTP_F_HTTP_PARSE_URL                            0
#   define HTTP_F_PARSE_HTTP_LINE1                          0
# endif

/*
 * HTTP reason codes.
 */
# define HTTP_R_ERROR_PARSING_URL                         101
# define HTTP_R_SERVER_RESPONSE_ERROR                     102
# define HTTP_R_SERVER_RESPONSE_PARSE_ERROR               103

#endif
