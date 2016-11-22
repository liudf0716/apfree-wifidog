
/* (c)  Oblong Industries */

#ifndef COMMON_MAN
#define COMMON_MAN

/**
 * This is the string the client tells the server in the POST request.
 */
#define COMMON_PASSCODE "R23"

/**
 * If an OpenSSL function returns a return value indicating failure
 * (for non-pointery functions, generally 1 means success, and non-1
 * means failure), then usually it ought to have left one or more
 * entries in the OpenSSL "error stack", which is a bit of thread-local
 * state containing error information.
 *
 * This function is a simple way to handle OpenSSL errors (something
 * better may be needed in a real application), which prints the
 * name of the function which failed (which you must supply as an
 * argument), prints the OpenSSL error stack (which hopefully says
 * something meaningful) and exits.
 */
void die_most_horribly_from_openssl_error (const char *func);

void error_exit (const char *fmt, ...);

#define error_report printf
#define info_report printf

/**
 * Calls some OpenSSL setup functions, which both the client and
 * server need to do.
 */
void common_setup (void);

#endif  /* COMMON_MAN */
