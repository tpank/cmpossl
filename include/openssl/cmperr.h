/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_CMPERR_H
# define HEADER_CMPERR_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_CMP

#  ifdef  __cplusplus
extern "C"
#  endif
int ERR_load_CMP_strings(void);

/*
 * CMP function codes.
 */
#  define CMP_F_ADD_EXTENSION                              100
#  define CMP_F_CMP_CALC_PROTECTION                        101
#  define CMP_F_CMP_CERTCONF_NEW                           202
#  define CMP_F_CMP_CERTREPMESSAGE_CERTRESPONSE_GET0       102
#  define CMP_F_CMP_CERTREQ_NEW                            203
#  define CMP_F_CMP_CERTRESPONSE_GET_CERTIFICATE           103
#  define CMP_F_CMP_CERTSTATUS_SET_CERTHASH                104
#  define CMP_F_CMP_ERROR_NEW                              204
#  define CMP_F_CMP_GENM_NEW                               205
#  define CMP_F_CMP_GEN_NEW                                105
#  define CMP_F_CMP_PKIFREETEXT_PUSH_STR                   106
#  define CMP_F_CMP_PKISI_PKISTATUS_GET_STRING             107
#  define CMP_F_CMP_POLLREPCONTENT_POLLREP_GET0            108
#  define CMP_F_CMP_POLLREQ_NEW                            206
#  define CMP_F_CMP_PROCESS_CERT_REQUEST                   109
#  define CMP_F_CMP_REVREPCONTENT_CERTID_GET               208
#  define CMP_F_CMP_REVREPCONTENT_PKISTATUSINFO_GET        110
#  define CMP_F_CMP_RR_NEW                                 207
#  define CMP_F_CMP_VERIFY_PBMAC                           111
#  define CMP_F_CMP_VERIFY_POPO                            112
#  define CMP_F_CMP_VERIFY_SIGNATURE                       113
#  define CMP_F_CRM_NEW                                    114
#  define CMP_F_FIND_VALIDATE_SRVCERT_AND_MSG              115
#  define CMP_F_GET_CERT_STATUS                            116
#  define CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1            117
#  define CMP_F_OSSL_CMP_ASN1_OCTET_STRING_SET1_BYTES      118
#  define CMP_F_OSSL_CMP_CERTCONF_NEW                      119
#  define CMP_F_OSSL_CMP_CERTREP_NEW                       120
#  define CMP_F_OSSL_CMP_CERTREQ_NEW                       121
#  define CMP_F_OSSL_CMP_CTX_CAPUBS_GET1                   122
#  define CMP_F_OSSL_CMP_CTX_CREATE                        123
#  define CMP_F_OSSL_CMP_CTX_EXTRACERTSIN_GET1             124
#  define CMP_F_OSSL_CMP_CTX_EXTRACERTSOUT_PUSH1           125
#  define CMP_F_OSSL_CMP_CTX_INIT                          126
#  define CMP_F_OSSL_CMP_CTX_PUSH_FREETEXT                 127
#  define CMP_F_OSSL_CMP_CTX_SET0_NEWPKEY                  128
#  define CMP_F_OSSL_CMP_CTX_SET0_PKEY                     129
#  define CMP_F_OSSL_CMP_CTX_SET0_REQEXTENSIONS            130
#  define CMP_F_OSSL_CMP_CTX_SET1_CAPUBS                   131
#  define CMP_F_OSSL_CMP_CTX_SET1_CLCERT                   132
#  define CMP_F_OSSL_CMP_CTX_SET1_EXPECTED_SENDER          133
#  define CMP_F_OSSL_CMP_CTX_SET1_EXTRACERTSIN             134
#  define CMP_F_OSSL_CMP_CTX_SET1_EXTRACERTSOUT            135
#  define CMP_F_OSSL_CMP_CTX_SET1_ISSUER                   136
#  define CMP_F_OSSL_CMP_CTX_SET1_LAST_SENDERNONCE         137
#  define CMP_F_OSSL_CMP_CTX_SET1_NEWCLCERT                138
#  define CMP_F_OSSL_CMP_CTX_SET1_NEWPKEY                  139
#  define CMP_F_OSSL_CMP_CTX_SET1_OLDCLCERT                140
#  define CMP_F_OSSL_CMP_CTX_SET1_P10CSR                   141
#  define CMP_F_OSSL_CMP_CTX_SET1_PKEY                     142
#  define CMP_F_OSSL_CMP_CTX_SET1_PROXYNAME                143
#  define CMP_F_OSSL_CMP_CTX_SET1_RECIPIENT                144
#  define CMP_F_OSSL_CMP_CTX_SET1_RECIPNONCE               145
#  define CMP_F_OSSL_CMP_CTX_SET1_REFERENCEVALUE           146
#  define CMP_F_OSSL_CMP_CTX_SET1_SECRETVALUE              147
#  define CMP_F_OSSL_CMP_CTX_SET1_SERVERNAME               148
#  define CMP_F_OSSL_CMP_CTX_SET1_SERVERPATH               149
#  define CMP_F_OSSL_CMP_CTX_SET1_SRVCERT                  150
#  define CMP_F_OSSL_CMP_CTX_SET1_SUBJECTNAME              151
#  define CMP_F_OSSL_CMP_CTX_SET1_TRANSACTIONID            152
#  define CMP_F_OSSL_CMP_CTX_SET_PROXYPORT                 153
#  define CMP_F_OSSL_CMP_CTX_SET_SERVERPORT                154
#  define CMP_F_OSSL_CMP_CTX_SUBJECTALTNAME_PUSH1          155
#  define CMP_F_OSSL_CMP_ERROR_NEW                         156
#  define CMP_F_OSSL_CMP_EXCHANGE_CERTCONF                 157
#  define CMP_F_OSSL_CMP_EXCHANGE_ERROR                    158
#  define CMP_F_OSSL_CMP_EXEC_CR_SES                       159
#  define CMP_F_OSSL_CMP_EXEC_GENM_SES                     160
#  define CMP_F_OSSL_CMP_EXEC_IR_SES                       161
#  define CMP_F_OSSL_CMP_EXEC_KUR_SES                      162
#  define CMP_F_OSSL_CMP_EXEC_P10CR_SES                    163
#  define CMP_F_OSSL_CMP_EXEC_RR_SES                       164
#  define CMP_F_OSSL_CMP_HDR_GENERALINFO_ITEM_PUSH0        165
#  define CMP_F_OSSL_CMP_HDR_GET_PVNO                      166
#  define CMP_F_OSSL_CMP_HDR_INIT                          167
#  define CMP_F_OSSL_CMP_HDR_PUSH0_FREETEXT                168
#  define CMP_F_OSSL_CMP_HDR_PUSH1_FREETEXT                169
#  define CMP_F_OSSL_CMP_HDR_SET_MESSAGETIME               170
#  define CMP_F_OSSL_CMP_HDR_SET_PVNO                      171
#  define CMP_F_OSSL_CMP_MSG_CHECK_RECEIVED                172
#  define CMP_F_OSSL_CMP_MSG_CREATE                        173
#  define CMP_F_OSSL_CMP_MSG_GENERALINFO_ITEMS_PUSH1       174
#  define CMP_F_OSSL_CMP_MSG_GENM_ITEMS_PUSH1              175
#  define CMP_F_OSSL_CMP_MSG_GENM_ITEM_PUSH0               176
#  define CMP_F_OSSL_CMP_MSG_HTTP_PERFORM                  177
#  define CMP_F_OSSL_CMP_MSG_PROTECT                       178
#  define CMP_F_OSSL_CMP_PKICONF_NEW                       179
#  define CMP_F_OSSL_CMP_PKISI_PKIFAILUREINFO_GET          180
#  define CMP_F_OSSL_CMP_PKISI_PKISTATUS_GET               181
#  define CMP_F_OSSL_CMP_POLLREP_NEW                       182
#  define CMP_F_OSSL_CMP_POLLREQ_NEW                       183
#  define CMP_F_OSSL_CMP_PRINT_CERT_VERIFY_CB              184
#  define CMP_F_OSSL_CMP_RP_NEW                            185
#  define CMP_F_OSSL_CMP_RR_NEW                            186
#  define CMP_F_OSSL_CMP_SRV_CTX_CREATE                    187
#  define CMP_F_OSSL_CMP_STATUSINFO_NEW                    188
#  define CMP_F_OSSL_CMP_VALIDATE_CERT_PATH                189
#  define CMP_F_OSSL_CMP_VALIDATE_MSG                      190
#  define CMP_F_POLLFORRESPONSE                            191
#  define CMP_F_PROCESS_CERTCONF                           192
#  define CMP_F_PROCESS_ERROR                              193
#  define CMP_F_PROCESS_GENM                               194
#  define CMP_F_PROCESS_POLLREQ                            195
#  define CMP_F_PROCESS_REQUEST                            196
#  define CMP_F_PROCESS_RR                                 197
#  define CMP_F_SAVE_STATUSINFO                            198
#  define CMP_F_SEND_RECEIVE_CHECK                         199
#  define CMP_F_SET1_AOSTR_ELSE_RANDOM                     200
#  define CMP_F_SET1_GENERAL_NAME                          201

/*
 * CMP reason codes.
 */
#  define CMP_R_ALGORITHM_NOT_SUPPORTED                    100
#  define CMP_R_BAD_CHECKAFTER_IN_POLLREP                  101
#  define CMP_R_BAD_PVNO                                   102
#  define CMP_R_BAD_REQUEST_ID                             103
#  define CMP_R_BAD_STATUS                                 104
#  define CMP_R_CERTID_NOT_FOUND                           194
#  define CMP_R_CERTIFICATE_NOT_ACCEPTED                   105
#  define CMP_R_CERTIFICATE_NOT_FOUND                      106
#  define CMP_R_CERTREQMSG_NOT_FOUND                       107
#  define CMP_R_CERTRESPONSE_NOT_FOUND                     108
#  define CMP_R_CERT_AND_KEY_DO_NOT_MATCH                  109
#  define CMP_R_CONNECT_TIMEOUT                            110
#  define CMP_R_CP_NOT_RECEIVED                            111
#  define CMP_R_ENCOUNTERED_KEYUPDATEWARNING               112
#  define CMP_R_ENCOUNTERED_UNSUPPORTED_PKISTATUS          113
#  define CMP_R_ENCOUNTERED_WAITING                        114
#  define CMP_R_ERROR_CALCULATING_PROTECTION               115
#  define CMP_R_ERROR_CONNECTING                           116
#  define CMP_R_ERROR_CREATING_CERTCONF                    117
#  define CMP_R_ERROR_CREATING_CERTREP                     118
#  define CMP_R_ERROR_CREATING_CR                          119
#  define CMP_R_ERROR_CREATING_ERROR                       120
#  define CMP_R_ERROR_CREATING_GENM                        121
#  define CMP_R_ERROR_CREATING_GENP                        122
#  define CMP_R_ERROR_CREATING_IR                          123
#  define CMP_R_ERROR_CREATING_KUR                         124
#  define CMP_R_ERROR_CREATING_P10CR                       125
#  define CMP_R_ERROR_CREATING_PKICONF                     126
#  define CMP_R_ERROR_CREATING_POLLREP                     127
#  define CMP_R_ERROR_CREATING_POLLREQ                     128
#  define CMP_R_ERROR_CREATING_RP                          129
#  define CMP_R_ERROR_CREATING_RR                          130
#  define CMP_R_ERROR_DECODING_MESSAGE                     131
#  define CMP_R_ERROR_PARSING_PKISTATUS                    132
#  define CMP_R_ERROR_PROCESSING_CERTREQ                   133
#  define CMP_R_ERROR_PROCESSING_MSG                       134
#  define CMP_R_ERROR_PROTECTING_MESSAGE                   135
#  define CMP_R_ERROR_PUSHING_GENERALINFO_ITEM             136
#  define CMP_R_ERROR_PUSHING_GENERALINFO_ITEMS            137
#  define CMP_R_ERROR_PUSHING_GENM_ITEMS                   138
#  define CMP_R_ERROR_SENDING_REQUEST                      139
#  define CMP_R_ERROR_SETTING_CERTHASH                     140
#  define CMP_R_ERROR_TRANSFERRING_IN                      141
#  define CMP_R_ERROR_TRANSFERRING_OUT                     142
#  define CMP_R_ERROR_VALIDATING_PROTECTION                143
#  define CMP_R_FAILED_EXTRACTING_PUBKEY                   144
#  define CMP_R_FAILED_TO_RECEIVE_PKIMESSAGE               145
#  define CMP_R_FAILED_TO_SEND_REQUEST                     146
#  define CMP_R_FAILURE_OBTAINING_RANDOM                   147
#  define CMP_R_FAIL_INFO_OUT_OF_RANGE                     192
#  define CMP_R_GENP_NOT_RECEIVED                          148
#  define CMP_R_INVALID_ARGS                               149
#  define CMP_R_INVALID_CONTEXT                            150
#  define CMP_R_INVALID_PARAMETERS                         151
#  define CMP_R_IP_NOT_RECEIVED                            152
#  define CMP_R_KUP_NOT_RECEIVED                           153
#  define CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION  154
#  define CMP_R_MISSING_KEY_USAGE_DIGITALSIGNATURE         155
#  define CMP_R_MISSING_PROTECTION                         156
#  define CMP_R_MULTIPLE_RESPONSES_NOT_SUPPORTED           157
#  define CMP_R_MULTIPLE_SAN_SOURCES                       158
#  define CMP_R_NO_SENDER_NO_REFERENCE                     159
#  define CMP_R_NO_SUITABLE_SERVER_CERT                    160
#  define CMP_R_NO_VALID_SERVER_CERT_FOUND                 161
#  define CMP_R_NULL_ARGUMENT                              162
#  define CMP_R_PKIBODY_ERROR                              163
#  define CMP_R_PKICONF_NOT_RECEIVED                       164
#  define CMP_R_PKISTATUSINFO_NOT_FOUND                    165
#  define CMP_R_POLLREP_NOT_RECEIVED                       166
#  define CMP_R_POTENTIALLY_INVALID_CERTIFICATE            167
#  define CMP_R_READ_TIMEOUT                               168
#  define CMP_R_RECEIVED_ERROR                             169
#  define CMP_R_RECEIVED_NEGATIVE_CHECKAFTER_IN_POLLREP    170
#  define CMP_R_RECIPNONCE_UNMATCHED                       171
#  define CMP_R_REQUEST_NOT_ACCEPTED                       172
#  define CMP_R_REQUEST_REJECTED_BY_CA                     173
#  define CMP_R_RP_NOT_RECEIVED                            174
#  define CMP_R_SENDER_GENERALNAME_TYPE_NOT_SUPPORTED      175
#  define CMP_R_TLS_ERROR                                  176
#  define CMP_R_TOTAL_TIMEOUT                              177
#  define CMP_R_TRANSACTIONID_UNMATCHED                    178
#  define CMP_R_UNEXPECTED_PKIBODY                         179
#  define CMP_R_UNEXPECTED_PKISTATUS                       180
#  define CMP_R_UNEXPECTED_PVNO                            193
#  define CMP_R_UNEXPECTED_REQUEST_ID                      181
#  define CMP_R_UNEXPECTED_SENDER                          182
#  define CMP_R_UNKNOWN_ALGORITHM_ID                       183
#  define CMP_R_UNKNOWN_CERT_TYPE                          184
#  define CMP_R_UNKNOWN_PKISTATUS                          185
#  define CMP_R_UNSUPPORTED_ALGORITHM                      186
#  define CMP_R_UNSUPPORTED_KEY_TYPE                       187
#  define CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC      188
#  define CMP_R_WRONG_ALGORITHM_OID                        189
#  define CMP_R_WRONG_CERTID_IN_RP                         196
#  define CMP_R_WRONG_CERT_HASH                            190
#  define CMP_R_WRONG_PBM_VALUE                            191
#  define CMP_R_WRONG_RP_COMPONENT_COUNT                   195

# endif
#endif
