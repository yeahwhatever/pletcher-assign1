#include <stdio.h>

#include "uocrypt.h"

void usage(char *name) {
    printf("Usage: %s <input file> [<output file>]\n", name);
}

void* xmalloc(size_t i) {
    void *ptr;

    ptr = malloc(i);

    if (!ptr)
        exit(255);

    return ptr;
}

/* Close file handles and free alloc'd memory, if alloc'd */
void clean(FILE *in, FILE *out, char *outfile, int argc) {
    fclose(in);
    fclose(out);
    if (argc == 3)
        free(outfile);
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

/* Print data in hex mostly for debugging */
void uocrypt_print(char *str, size_t len) {
    unsigned int i;
    for(i = 0; i < len; i++)
        printf("%02x", (unsigned char)str[i]);

    printf("\n");
}

/* Zero pad and strip new line and null terminator */
void uocrypt_zero_pad(char *input, char *pass, size_t len) {
    unsigned int i;
    /* Right pad the pass with 0's */
    for (i = strlen(input) - 1; i < len; i++)
        input[i] = '0';

    memcpy(pass, input, len);

#if DEBUG
    printf("DEBUG: Zero padded password=");
    uocrypt_print(pass, len);
#endif 
}

void uocrypt_hash_md5(char *pass, size_t len) {
    char digest[16];

    gcry_md_hash_buffer(GCRY_MD_MD5, digest, pass, len);

    /* Copy back into pass */
    memcpy(pass, digest, len);

#if DEBUG
    printf("DEBUG: Hashed password=");
    uocrypt_print(pass, len);
#endif

}
