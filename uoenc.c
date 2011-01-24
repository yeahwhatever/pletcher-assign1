#include "uocrypt.h"
#include "uoenc.h"

int main(int argc, char** argv) {
    char *infile, *outfile = NULL;
    FILE *in, *out;
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

        in = fopen(infile, "rb");
        out = fopen(outfile, "wb");
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

void uoenc(char *pass, size_t len, FILE *in, FILE *out) {
    gcry_cipher_hd_t h;
    gcry_error_t err;

    char buffer[1024];
    size_t b, pad;

    /* Open a cipher handle.. */
    err = gcry_cipher_open(&h, GCRY_CIPHER_RIJNDAEL128, GCRY_CIPHER_MODE_CBC, 0);

    /* Check for errors */
    uocrypt_error(err);

    /* Set the key */
    err = gcry_cipher_setkey(h, pass, len);
    uocrypt_error(err);

    /* Set the initialization vector */
    err = gcry_cipher_setiv(h, IV, IV_SIZE);

    while (b = read(*in, buffer, sizeof(buffer))) {
        if (b < sizeof(buffer)) {
            pad = b % sizeof(buffer);
        }
    }
    /* Clean Up */
    gcry_cipher_close(h);
}
