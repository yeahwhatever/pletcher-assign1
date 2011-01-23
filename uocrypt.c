#include <stdio.h>

#include "uocrypt.h"

void usage(char *name) {
    printf("Usage: %s <input file> [<output file>]\n", name);
}


/* Ripped from the manual
 * http://www.gnupg.org/documentation/manuals/gcrypt/Error-Strings.html#Error-Strings */
void uocrypt_error(gcry_error_t err) {
    if (err)
    {
        fprintf (stderr, "Failure: %s/%s\n",
                gcry_strsource (err),
                gcry_strerror (err));
        abort();
    }

}

/* Ripped from the manual 
 * http://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html#Initializing-the-library */
void uocrypt_init() {
    /* Version check should be the very first call because it
     *           makes sure that important subsystems are intialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        fputs ("libgcrypt version mismatch\n", stderr);
        exit (2);
    }

    /* Disable secure memory.  */
    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        fputs ("libgcrypt has not been initialized\n", stderr);
        abort ();
    }
}

void uocrypt_hash_md5(char *pass) {
    gcry_error_t err = NULL;
    

}
