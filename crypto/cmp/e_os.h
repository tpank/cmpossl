/* system-specific variants defining ossl_sleep() */
#  ifdef OPENSSL_SYS_UNIX
#   include <unistd.h>
static ossl_inline void ossl_sleep(unsigned long millis)
{
#   ifdef OPENSSL_SYS_VXWORKS
    struct timespec ts;
    ts.tv_sec = (long int) (millis / 1000);
    ts.tv_nsec = (long int) (millis % 1000) * 1000000ul;
    nanosleep(&ts, NULL);
#   elif defined(__TANDEM) && !defined(_REENTRANT)
#    include <cextdecs.h(PROCESS_DELAY_)>
    /* HPNS does not support usleep for non threaded apps */
    PROCESS_DELAY_(millis * 1000);
#   else
    usleep((unsigned int)(millis * 1000));
#   endif
}
#  elif defined(_WIN32)
#   include <windows.h>
static ossl_inline void ossl_sleep(unsigned long millis)
{
    Sleep(millis);
}
#  else
/* Fallback to a busy wait */
static ossl_inline void ossl_sleep(unsigned long millis)
{
    struct timeval start, now;
    unsigned long elapsedms;

    gettimeofday(&start, NULL);
    do {
        gettimeofday(&now, NULL);
        elapsedms = (((now.tv_sec - start.tv_sec) * 1000000)
                     + now.tv_usec - start.tv_usec) / 1000;
    } while (elapsedms < millis);
}
#  endif /* defined OPENSSL_SYS_UNIX */
