#ifndef _UOCRYPT
#define _UOCRYPT 1

#include <gcrypt.h>

void usage(char *name);
void uocrypt_init();
void uocrypt_hash_md5(char *pass);

#endif
