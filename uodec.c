#include "uocrypt.h"
#include "uodec.h"

int main(int argc, char** argv) {
    char *infile, *outfile = NULL;
    FILE *in, *out;
    /* 16 byes, plus two for newline and null */
    char input[18], pass[16];
    unsigned int total, sub;

    /* Parse argv */
    if (argc < 2 || argc > 3) {
        usage(argv[0]);
        return 1;
    } else {
        infile = argv[1];
        if (argc == 3)
            outfile = argv[2];
        else {
            outfile = strstr(infile, ".uo");
            if (!outfile) {
                printf("Output file required when input file does not end in .uo\n");
                return 4;
            }
            /* strlen doesnt count the null */
            sub = strlen(argv[1]) - 2;
            outfile = xmalloc(sub);
            strncpy(outfile, infile, sub - 1);
            outfile[sub - 1] = '\0';
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

    /* Do Work */
    total = uodec(pass, sizeof pass, in, out);

    printf("Successfully decrypted %s to %s (%u bytes written).\n", infile, outfile, total);

    /* Clean up and bail */
    clean(in, out, outfile, argc);

    return 0;
}

unsigned int uodec(char *pass, size_t len, FILE *in, FILE *out) {
    gcry_cipher_hd_t h;
    gcry_error_t err;

    unsigned char buffer[1024], decrypt[1024], iv[16];
    unsigned short rbytes = 0, wbytes = 0;
    unsigned int total = 0, pad = 0;
    long size;


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
    /* Get the filesize so we know when to remove padding */
    fseek(in, 0L, SEEK_END);
    size = ftell(in);
    fseek(in, 0L, SEEK_SET);

    /* When pad is non-zero we're done, prevents another run through */
    while (!feof(in) && !pad) {
        /* Set the initialization vector */
        rbytes = fread(iv, sizeof iv[0], sizeof iv, in);
        if (rbytes != sizeof iv) {
            printf("Could not read initialization vector\n");
            abort();   
        }
        err = gcry_cipher_setiv(h, iv, sizeof iv);
        uocrypt_error(err);

#if DEBUG
        printf("DEBUG: gcrypt handle init vector set\n");
#endif

        rbytes += fread(buffer, sizeof buffer[0], sizeof buffer, in);
        /* Perform decryption */
        err = gcry_cipher_decrypt(h, decrypt, rbytes - sizeof iv, buffer, rbytes - sizeof iv); 
        uocrypt_error(err);

#if DEBUG > 1
        printf("DEBUG: decrypt=\n");
        uocrypt_print(buffer, sizeof buffer);
        uocrypt_print(decrypt, sizeof decrypt);
#endif
        /* Remove padding */
        if ((rbytes - sizeof iv) < sizeof buffer || ftell(in) == size)
            pad = decrypt[rbytes - sizeof iv - 1];

        /* Write decryted data */
        wbytes = fwrite(decrypt, sizeof decrypt[0], rbytes - sizeof iv - pad, out);

        total += wbytes;

        printf("read %u bytes, wrote bytes %u\n", rbytes, wbytes);
    }

    /* Clean Up */
    gcry_cipher_close(h);

    return total;
}
