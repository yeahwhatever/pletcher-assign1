#include "uocrypt.h"
#include "uoenc.h"

int main(int argc, char** argv) {
    char *infile, *outfile = NULL;
    /* 16 byes, plus two for newline and null */
    char input[18], pass[16];

    /* Parse argv */
    if (argc < 3 || argc > 4) {
        usage(argv[0]);
        return 1;
    } else {
        infile = argv[2];
        if (argc == 4)
            outfile = argv[3];
        else {
            outfile = xmalloc(sizeof(argv[2]) + 3);
            strcpy(outfile, infile);
            strcat(outfile, ".uo");
        }
    }

#if DEBUG
    printf("DEBUG: infile=%s\n", infile);
    printf("DEBUG: outfile=%s\n", outfile);
#endif

    /* Init gcrypt */
    uocrypt_init();

    /* Get password */
    printf("Password: ");
    fgets(input, sizeof input, stdin);

    /* Hash it */
    uocrypt_zero_pad(input, pass, sizeof(pass));
    uocrypt_hash_md5(pass, sizeof(pass));

    return 0;
}

