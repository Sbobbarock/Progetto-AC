#include <openssl/evp.h>

unsigned char* compute_signature(const EVP_MD* , unsigned char* , int , EVP_PKEY* ,uint32_t* );
bool verify_signature(const EVP_MD* , unsigned char* , int , EVP_PKEY* ,unsigned char* ,uint32_t );
