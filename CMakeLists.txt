cmake_minimum_required(VERSION 3.7)

project(cmp)

find_package(OpenSSL REQUIRED)

set(LIBCMP_INC ${PROJECT_SOURCE_DIR}/include_cmp)
set(LIBCMP_INTERNAL_INC ${PROJECT_SOURCE_DIR}/crypto/cmp)

if(NOT DEFINED CMP_VERSION )
    set(CMP_VERSION 0.9.1)
endif()

message(STATUS ${CMP_VERSION})

file(MAKE_DIRECTORY ${LIBCMP_INC}/openssl)

set(CMP_SSL_INC_DIR ${PROJECT_SOURCE_DIR}/include/openssl)

set(CMP_SSL_INC ${CMP_SSL_INC_DIR}/cmp.h
    ${CMP_SSL_INC_DIR}/cmperr.h
    ${CMP_SSL_INC_DIR}/crmf.h
    ${CMP_SSL_INC_DIR}/crmferr.h
    ${CMP_SSL_INC_DIR}/safestack_backport.h
    ${LIBCMP_INTERNAL_INC}/cmp_int.h
)

file (COPY ${CMP_SSL_INC} DESTINATION ${LIBCMP_INC}/openssl)
file (READ ${CMP_SSL_INC_DIR}/crmf.h CMPH_CONTENTS)
file (WRITE ${LIBCMP_INC}/openssl/crmf.h "#undef CMP_STANDALONE\n")
file (APPEND ${LIBCMP_INC}/openssl/crmf.h "#define CMP_STANDALONE\n")
file (APPEND ${LIBCMP_INC}/openssl/crmf.h "${CMPH_CONTENTS}")

include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${LIBCMP_INC}
)

add_definitions(-include ${LIBCMP_INC}/openssl/crmf.h)

set(CMP_SRCDIR ${PROJECT_SOURCE_DIR}/crypto/cmp)
set(CRMF_SRCDIR ${PROJECT_SOURCE_DIR}/crypto/crmf)

set(CMP_SRC ${CMP_SRCDIR}/cmp_asn.c
    ${CMP_SRCDIR}/cmp_ctx.c
    ${CMP_SRCDIR}/cmp_err.c
    ${CMP_SRCDIR}/cmp_http.c
    ${CMP_SRCDIR}/cmp_lib.c
    ${CMP_SRCDIR}/cmp_msg.c
    ${CMP_SRCDIR}/cmp_ses.c
    ${CMP_SRCDIR}/cmp_srv.c
    ${CMP_SRCDIR}/cmp_vfy.c
)

set(CRMF_SRC ${CRMF_SRCDIR}/crmf_asn.c
    ${CRMF_SRCDIR}/crmf_err.c
    ${CRMF_SRCDIR}/crmf_lib.c
    ${CRMF_SRCDIR}/crmf_pbm.c
)

add_library(cmp SHARED
    ${CMP_SRC}
    ${CRMF_SRC}
)

set_target_properties(cmp PROPERTIES
    VERSION ${CMP_VERSION}
    PUBLIC_HEADER "${CMP_SSL_INC}"
)

target_link_libraries(cmp ${OPENSSL_LIBRARIES})
set_property(TARGET cmp PROPERTY C_STANDARD 90)

install(TARGETS cmp
    LIBRARY
        DESTINATION lib
        COMPONENT Library
    PUBLIC_HEADER
        DESTINATION include/openssl
        COMPONENT Development
)
