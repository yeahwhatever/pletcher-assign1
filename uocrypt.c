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

void uocrypt_print(char *str, int len) {
    int i;
    for(i = 0; i < len; i++)
        printf("%02x", (unsigned char)str[i]);

    printf("\n");
}

void uocrypt_hash_md5(char *input) {
    char digest[16], pass[16];
    int i;

    /* Right pad the pass with 0's */
    for (i = strlen(input) - 1; i < 16; i++)
        input[i] = '0';

    memcpy(pass, input, sizeof(pass));

    uocrypt_print(pass, 16);

    gcry_md_hash_buffer(GCRY_MD_MD5, digest, pass, 16);

    uocrypt_print(digest, 16);
}
