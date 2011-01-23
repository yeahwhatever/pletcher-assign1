#include "uocrypt.h"
#include "uoenc.h"

int main(int argc, char** argv) {
    char *infile, *outfile = NULL;
    /* 16 byes, plus two for newline and null */
    char input[18];

    /* Parse argv */
    if (argc < 2 || argc > 3) {
        usage(argv[0]);
        return 1;
    } else {
        infile = argv[1];
        if (argc == 2)
            outfile = argv[2];
    }

    /* Init gcrypt */
    uocrypt_init();

    /* Get password */
    printf("Password: ");
    fgets(input, sizeof input, stdin);
    /* Get the first 16 bytes */

    /* Hash it */
    uocrypt_hash_md5(input);

    return 0;
}

