#ifndef _UOCRYPT
#define _UOCRYPT 1

#include <gcrypt.h>

#define DEBUG 1
#define IV "ae6a8419985e8c5b9f890d983bf230e9"
#define IV_SIZE sizeof(IV) - 1

void usage(char *name);
void* xmalloc(size_t i);
void uocrypt_init();
void uocrypt_print(char * str, size_t len);
void uocrypt_zero_pad(char *input, char *pass, size_t len);
void uocrypt_hash_md5(char *pass, size_t len);

#endif
