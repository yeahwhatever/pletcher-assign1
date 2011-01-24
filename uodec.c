#include "uocrypt.h"
#include "uodec.h"

int main(int argc, char** argv) {
    char *infile, *outfile = NULL;
    FILE *in, *out;
    /* 16 byes, plus two for newline and null */
    char input[18], pass[16];
    unsigned int total;

    /* Parse argv */
    if (argc < 2 || argc > 3) {
        usage(argv[0]);
        return 1;
    } else {
        infile = argv[1];
        if (argc == 3)
            outfile = argv[2];
        else {
            outfile = xmalloc(strlen(argv[1]) + 4);
            strcpy(outfile, infile);
            strcat(outfile, ".uo");
        }

        /* Open files */
        in = fopen(infile, "rb");
        out = fopen(outfile, "rb");
        /* File exists, clean up and bail */
        if (out) {
            printf("Output file [%s] already exists.\nAborting operation.\n", outfile);
            clean(in, out, outfile, argc);
            return 2;
        /* We're good */
        } 
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
    uocrypt_zero_pad(input, pass, sizeof pass);
    uocrypt_hash_md5(pass, sizeof pass);

    total = uodec(pass, sizeof pass, in, out);

    printf("Successfully decrypted %s to %s (%u bytes written).\n", infile, outfile, total);
    clean(in, out, outfile, argc);

    return 0;
}

unsigned int uodec(char *pass, size_t len, FILE *in, FILE *out) {
    gcry_cipher_hd_t h;
    gcry_error_t err;

    char buffer[1024], decrypt[1024];
    unsigned short rbytes = 0, wbytes = 0;
    unsigned int total, i;

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

    while (!feof(in)) {
        rbytes = fread(buffer, sizeof buffer[0], sizeof buffer, in);
        if (!rbytes)
            continue;
        err = gcry_cipher_decrypt(h, decrypt, sizeof decrypt, buffer, sizeof buffer);
        uocrypt_error(err);

#if DEBUG > 1
        printf("DEBUG: decrypt=\n");
        uocrypt_print(buffer, sizeof buffer);
        uocrypt_print(decrypt, sizeof decrypt);
#endif

        for (i = 0; i < sizeof decrypt; i++) {
            if (decrypt[i] == EOF)
                break;
        }

        wbytes = fwrite(decrypt, sizeof decrypt[0], i, out);
        total += wbytes;

        printf("read %u bytes, wrote bytes %u\n", rbytes, wbytes);
    }

    /* Clean Up */
    gcry_cipher_close(h);

    return total;
}
