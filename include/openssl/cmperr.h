/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_CMPERR_H
# define OPENSSL_CMPERR_H

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>


# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_CMP

#  ifdef  __cplusplus
extern "C"
#  endif
int ERR_load_CMP_strings(void);

/*
 * CMP function codes.
 */
# ifndef OPENSSL_NO_DEPRECATED_3_0
# endif

/*
 * CMP reason codes.
 */
#  define CMP_R_ALGORITHM_NOT_SUPPORTED                    114
#  define CMP_R_BAD_CHECKAFTER_IN_POLLREP                  115
#  define CMP_R_BAD_REQUEST_ID                             101
#  define CMP_R_CERTID_NOT_FOUND                           104
#  define CMP_R_CERTIFICATE_NOT_ACCEPTED                   116
#  define CMP_R_CERTIFICATE_NOT_FOUND                      105
#  define CMP_R_CERTREQMSG_NOT_FOUND                       117
#  define CMP_R_CERTRESPONSE_NOT_FOUND                     106
#  define CMP_R_CERT_AND_KEY_DO_NOT_MATCH                  118
#  define CMP_R_CONNECT_TIMEOUT                            119
#  define CMP_R_CP_NOT_RECEIVED                            120
#  define CMP_R_ENCOUNTERED_KEYUPDATEWARNING               121
#  define CMP_R_ENCOUNTERED_UNSUPPORTED_PKISTATUS          122
#  define CMP_R_ENCOUNTERED_WAITING                        123
#  define CMP_R_ERROR_CALCULATING_PROTECTION               124
#  define CMP_R_ERROR_CONNECTING                           125
#  define CMP_R_ERROR_CREATING_CERTCONF                    126
#  define CMP_R_ERROR_CREATING_CERTREP                     127
#  define CMP_R_ERROR_CREATING_CR                          128
#  define CMP_R_ERROR_CREATING_ERROR                       129
#  define CMP_R_ERROR_CREATING_GENM                        130
#  define CMP_R_ERROR_CREATING_GENP                        131
#  define CMP_R_ERROR_CREATING_IR                          132
#  define CMP_R_ERROR_CREATING_KUR                         133
#  define CMP_R_ERROR_CREATING_P10CR                       134
#  define CMP_R_ERROR_CREATING_PKICONF                     135
#  define CMP_R_ERROR_CREATING_POLLREP                     136
#  define CMP_R_ERROR_CREATING_POLLREQ                     137
#  define CMP_R_ERROR_CREATING_RP                          138
#  define CMP_R_ERROR_CREATING_RR                          139
#  define CMP_R_ERROR_DECODING_MESSAGE                     140
#  define CMP_R_ERROR_PARSING_PKISTATUS                    107
#  define CMP_R_ERROR_PROCESSING_CERTREQ                   141
#  define CMP_R_ERROR_PROCESSING_MSG                       142
#  define CMP_R_ERROR_PROTECTING_MESSAGE                   143
#  define CMP_R_ERROR_PUSHING_GENERALINFO_ITEM             108
#  define CMP_R_ERROR_PUSHING_GENERALINFO_ITEMS            109
#  define CMP_R_ERROR_SENDING_REQUEST                      144
#  define CMP_R_ERROR_SETTING_CERTHASH                     145
#  define CMP_R_ERROR_TRANSFERRING_IN                      146
#  define CMP_R_ERROR_TRANSFERRING_OUT                     147
#  define CMP_R_ERROR_UNEXPECTED_CERTCONF                  196
#  define CMP_R_ERROR_VALIDATING_PROTECTION                148
#  define CMP_R_FAILED_EXTRACTING_PUBKEY                   149
#  define CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE               150
#  define CMP_R_FAILED_TO_SEND_REQUEST                     151
#  define CMP_R_FAILURE_OBTAINING_RANDOM                   110
#  define CMP_R_FAIL_INFO_OUT_OF_RANGE                     152
#  define CMP_R_GENP_NOT_RECEIVED                          153
#  define CMP_R_INVALID_ARGS                               100
#  define CMP_R_IP_NOT_RECEIVED                            155
#  define CMP_R_KUP_NOT_RECEIVED                           156
#  define CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION  157
#  define CMP_R_MISSING_KEY_USAGE_DIGITALSIGNATURE         158
#  define CMP_R_MISSING_PRIVATE_KEY                        193
#  define CMP_R_MISSING_PROTECTION                         159
#  define CMP_R_MISSING_SENDER_IDENTIFICATION              111
#  define CMP_R_MISSING_TRUST_STORE                        154
#  define CMP_R_MULTIPLE_REQUESTS_NOT_SUPPORTED            195
#  define CMP_R_MULTIPLE_RESPONSES_NOT_SUPPORTED           160
#  define CMP_R_MULTIPLE_SAN_SOURCES                       102
#  define CMP_R_NO_STDIO                                   194
#  define CMP_R_NO_SUITABLE_SENDER_CERT                    161
#  define CMP_R_NULL_ARGUMENT                              103
#  define CMP_R_PKIBODY_ERROR                              163
#  define CMP_R_PKICONF_NOT_RECEIVED                       164
#  define CMP_R_PKISTATUSINFO_NOT_FOUND                    112
#  define CMP_R_POLLREP_NOT_RECEIVED                       165
#  define CMP_R_POTENTIALLY_INVALID_CERTIFICATE            166
#  define CMP_R_READ_TIMEOUT                               167
#  define CMP_R_RECEIVED_ERROR                             168
#  define CMP_R_RECEIVED_NEGATIVE_CHECKAFTER_IN_POLLREP    169
#  define CMP_R_RECIPNONCE_UNMATCHED                       170
#  define CMP_R_REQUEST_NOT_ACCEPTED                       171
#  define CMP_R_REQUEST_REJECTED_BY_CA                     172
#  define CMP_R_RP_NOT_RECEIVED                            173
#  define CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED      174
#  define CMP_R_SRVCERT_DOES_NOT_VALIDATE_MSG              162
#  define CMP_R_TLS_ERROR                                  175
#  define CMP_R_TOTAL_TIMEOUT                              176
#  define CMP_R_TRANSACTIONID_UNMATCHED                    177
#  define CMP_R_UNEXPECTED_PKIBODY                         178
#  define CMP_R_UNEXPECTED_PKISTATUS                       179
#  define CMP_R_UNEXPECTED_PVNO                            180
#  define CMP_R_UNEXPECTED_REQUEST_ID                      181
#  define CMP_R_UNEXPECTED_SENDER                          182
#  define CMP_R_UNKNOWN_ALGORITHM_ID                       183
#  define CMP_R_UNKNOWN_CERT_TYPE                          113
#  define CMP_R_UNKNOWN_PKISTATUS                          184
#  define CMP_R_UNSUPPORTED_ALGORITHM                      185
#  define CMP_R_UNSUPPORTED_KEY_TYPE                       186
#  define CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC      187
#  define CMP_R_WRONG_ALGORITHM_OID                        188
#  define CMP_R_WRONG_CERTID_IN_RP                         189
#  define CMP_R_WRONG_CERT_HASH                            190
#  define CMP_R_WRONG_PBM_VALUE                            191
#  define CMP_R_WRONG_RP_COMPONENT_COUNT                   192

# endif
#endif
