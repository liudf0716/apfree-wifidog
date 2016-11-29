
/* (c)  Oblong Industries */

#include <signal.h>

#include "https_common.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <event2/event.h>

#include <syslog.h>
#include "debug.h"

void die_most_horribly_from_openssl_error (const char *func) { 
	debug (LOG_ERR,  "%s failed:\n", func);
	exit (EXIT_FAILURE);
}

void error_exit (const char *fmt, ...) { 
	va_list ap;

	va_start (ap, fmt);
	vfprintf (stderr, fmt, ap);
	va_end (ap);

	exit (EXIT_FAILURE);
}

/* OpenSSL has a habit of using uninitialized memory.  (They turn up their
 * nose at tools like valgrind.)  To avoid spurious valgrind errors (as well
 * as to allay any concerns that the uninitialized memory is actually
 * affecting behavior), let's install a custom malloc function which is
 * actually calloc.
 */
static void *my_zeroing_malloc (size_t howmuch) { 
	return calloc (1, howmuch); 
}

void common_setup (void)
{ 
	CRYPTO_set_mem_functions (my_zeroing_malloc, realloc, free);
	SSL_library_init ();
	SSL_load_error_strings ();
	OpenSSL_add_all_algorithms ();

	debug (LOG_DEBUG, "Using OpenSSL version \"%s\"\nand libevent version \"%s\"\n",
		  SSLeay_version (SSLEAY_VERSION),
		  event_get_version ());
}
