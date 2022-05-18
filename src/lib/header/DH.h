#include <stdio.h>
#include <string.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>

EVP_PKEY* DH_privkey();
unsigned char* DH_pubkey(std::string ,EVP_PKEY* ,EVP_PKEY* ,uint32_t* );
EVP_PKEY* DH_derive_pubkey(std::string ,unsigned char* ,uint32_t );
unsigned char* DH_derive_session_secret(EVP_PKEY* , EVP_PKEY* ,size_t* );
unsigned char* session_key(const EVP_MD* ,const EVP_CIPHER* , unsigned char* ,size_t ,unsigned int*);
