#include "uocrypt.h"
#include "uoenc.h"

int main(int argc, char** argv) {
    char *infile, *outfile = NULL;
    FILE *in, *out;
    /* 16 byes, plus two for newline and null */
    char input[18], pass[16];

    /* Parse argv */
    if (argc < 2 || argc > 3) {
        usage(argv[0]);
        return 1;
    } else {
        infile = argv[1];
        if (argc == 4)
            outfile = argv[2];
        else {
            outfile = xmalloc(sizeof(argv[1]) + 3);
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

    uoenc(pass, sizeof(pass), in, out);

    return 0;
}

void uoenc(char *pass, size_t len, FILE *in, FILE *out) {
    gcry_cipher_hd_t h;
    gcry_error_t err;

    char buffer[1024], encrypt[1024];
    size_t rbytes = 0, wbytes = 0;

    out = NULL;

    /* Open a cipher handle.. */
    err = gcry_cipher_open(&h, GCRY_CIPHER_RIJNDAEL128, GCRY_CIPHER_MODE_CBC, 0);

    /* Check for errors */
    uocrypt_error(err);

#if DEBUG
    printf("DEBUG: gcrypt handle opened\n");
    printf("DEBUG: cipher keylen=%u\n", gcry_cipher_get_algo_keylen(GCRY_CIPHER_RIJNDAEL128));
    printf("DEBUG: cipher blklen=%u\n", gcry_cipher_get_algo_blklen(GCRY_CIPHER_RIJNDAEL128));
#endif

    /* Set the key */
    err = gcry_cipher_setkey(h, pass, len);
    uocrypt_error(err);

#if DEBUG
    printf("DEBUG: gcrypt handle key set\n");
#endif

    /* Set the initialization vector */
    err = gcry_cipher_setiv(h, IV, IV_SIZE);
    uocrypt_error(err);

#if DEBUG
    printf("DEBUG: gcrypt handle init vector set\n");
#endif

    do {
        rbytes = fread(buffer, sizeof(buffer), 1, in);
        err = gcry_cipher_encrypt(h, encrypt, sizeof(encrypt), buffer, sizeof(buffer));
        uocrypt_error(err);

#if DEBUG
        printf("DEBUG: encrypt=\n");
        uocrypt_print(buffer, sizeof(buffer));
        uocrypt_print(encrypt, sizeof(encrypt));
#endif
        printf("Read %u bytes, wrote %u bytes\n", rbytes, wbytes);
        /* wbytes = fwrite(encrypt, sizeof(encrypt), 1, out); */
    } while (rbytes);

    /* Clean Up */
    gcry_cipher_close(h);
}
