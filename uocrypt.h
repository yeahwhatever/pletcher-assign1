#ifndef _UOCRYPT
#define _UOCRYPT 1

#include <gcrypt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define DEBUG 1
#define IV "ae6a8419985e8c5b9f890d983bf230e9"
#define IV_SIZE 16

void usage(char *name);
void* xmalloc(size_t i);
void uocrypt_init();
void uocrypt_error(gcry_error_t err);
void uocrypt_print(char * str, size_t len);
void uocrypt_zero_pad(char *input, char *pass, size_t len);
void uocrypt_hash_md5(char *pass, size_t len);

#endif
