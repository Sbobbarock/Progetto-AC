#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <iostream>

EVP_PKEY* DH_privkey();
unsigned char* DH_pubkey(std::string , EVP_PKEY*, uint32_t*);
EVP_PKEY* DH_derive_pubkey(std::string,unsigned char*, uint32_t);
unsigned char* DH_derive_session_secret(EVP_PKEY*,EVP_PKEY*,size_t*);
