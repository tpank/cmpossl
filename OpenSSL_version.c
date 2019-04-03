#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>

#if OPENSSL_VERSION_NUMBER < 0x10002000L
#error Better not use OpenSSL versions older than 1.0.2. They are unsupported and insecure.
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OpenSSL_version_num SSLeay
#elif OPENSSL_VERSION_NUMBER >= 0x30000000L
#define OpenSSL_version_num() ((unsigned long) \
                               ((OPENSSL_version_major()<<28) \
                               |(OPENSSL_version_minor()<<20) \
                               |(OPENSSL_version_patch()<< 4) \
                               |_OPENSSL_VERSION_PRE_RELEASE ))
#endif

int main(int argc, char *argv[])
{
    unsigned long runtime_version = OpenSSL_version_num();
    #define MAJOR_MINOR_MASK 0xfff00000L
    if ((MAJOR_MINOR_MASK & runtime_version ) !=
        (MAJOR_MINOR_MASK & OPENSSL_VERSION_NUMBER)) {
        fprintf(stderr, "OpenSSL runtime version 0x%lx does not match version 0x%lx used by compiler\n",
                runtime_version, (unsigned long)OPENSSL_VERSION_NUMBER);
        return EXIT_FAILURE;
    }
    fprintf(stdout, "%s (0x%lx)\n", OPENSSL_VERSION_TEXT, runtime_version);
    return EXIT_SUCCESS;
}
