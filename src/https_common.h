
/* (c)  Oblong Industries */

#ifndef COMMON_MAN
#define COMMON_MAN

void die_most_horribly_from_openssl_error (const char *func);

#define error_report printf
#define info_report printf

/**
 * Calls some OpenSSL setup functions, which both the client and
 * server need to do.
 */
void openssl_init (void);

#endif  /* COMMON_MAN */
