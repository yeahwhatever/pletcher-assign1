#include "uocrypt.h"
#include "uoenc.h"

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

        in = fopen(infile, "rb");
        out = fopen(outfile, "rb");
        if (out) {
            printf("Output file [%s] already exists.\nAborting operation.\n", outfile);
            clean(in, out, outfile, argc);
            return 2;
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

    total = uoenc(pass, sizeof pass, in, out);

    printf("Successfully encrypted %s to %s (%u bytes written).\n", infile, outfile, total);
    clean(in, out, outfile, argc);

    return 0;
}

unsigned int uoenc(char *pass, size_t len, FILE *in, FILE *out) {
    gcry_cipher_hd_t h;
    gcry_error_t err;

    unsigned char buffer[1024], encrypt[1024], iv[16];
    unsigned short rbytes = 0, wbytes = 0, first = 0;
    unsigned int total = 0, pad = 0; 

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
    gcry_create_nonce(iv, sizeof iv);
    err = gcry_cipher_setiv(h, iv, sizeof iv);
    uocrypt_error(err);
    first = fwrite(iv, sizeof iv[0], sizeof iv, out);

#if DEBUG
    printf("DEBUG: gcrypt handle init vector set\n");
#endif

    while (!feof(in)) {
        rbytes = fread(buffer, sizeof buffer[0], sizeof buffer, in);
        /* Last run through the loop */
        if (rbytes < sizeof buffer) {
            /* AES has a 16byte blocksize... */
            pad = BLOCK_SIZE - rbytes % BLOCK_SIZE;
            /* Lets use PKCS7
             * http://tools.ietf.org/html/rfc5652#section-6.3 */
            if (!pad)
                pad = BLOCK_SIZE;
            memset(&buffer[rbytes], pad, pad);
        /* This is the case where input is exactly 1024 bytes, and we need
         * a padding block on the next run through */
        } else if (!rbytes) {
            rbytes = BLOCK_SIZE;
            memset(buffer, rbytes, rbytes);
        }
#if DEBUG
        printf("DEBUG: Read/write bytes=%u\n", rbytes + pad);
#endif
        err = gcry_cipher_encrypt(h, encrypt, rbytes + pad, buffer, rbytes + pad);
        uocrypt_error(err);

#if DEBUG > 1
        printf("DEBUG: encrypt=\n");
        uocrypt_print(buffer, rbytes + pad);
        uocrypt_print(encrypt, rbytes + pad);
#endif
        wbytes = fwrite(encrypt, sizeof encrypt[0], rbytes + pad, out);

        if (first) {
            wbytes += first;
            first = 0;
        }

        total += wbytes;

        printf("Read %u bytes, wrote %u bytes\n", rbytes, wbytes);
    }

    /* Clean Up */
    gcry_cipher_close(h);
    
    return total;
}
