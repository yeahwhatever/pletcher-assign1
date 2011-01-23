#include "uocrypt.h"
#include "uoenc.h"

int main(int argc, char** argv) {
    char *infile, *outfile = NULL;
    char pass[129];

    /* Parse argv */
    if (argc < 2 || argc > 3) {
        usage(argv[0]);
        return 1;
    } else {
        infile = argv[1];
        if (argc == 3)
            outfile = argv[2];
    }

    /* Init gcrypt */
    uocrypt_init();

    /* Get password */
    printf("Password: ");
    fgets(pass, sizeof pass, stdin);

    /* Hash it */
    uocrypt_hash_md5(pass);

    return 0;
}

