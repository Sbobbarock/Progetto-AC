#include <openssl/evp.h>

bool encrypt_gcm(unsigned char *, int ,unsigned char *, int ,unsigned char *,unsigned char *,unsigned char *,uint32_t*,unsigned char *);
bool decrypt_gcm(unsigned char *, uint32_t ,unsigned char *, int ,unsigned char *,unsigned char *,unsigned char *,unsigned char *,uint32_t*);
