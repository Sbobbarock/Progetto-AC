#include <openssl/x509.h>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

X509_STORE* build_store(std::string ,std::string );
X509* read_certificate(std::string,unsigned char* ,uint32_t);
EVP_PKEY* validate_certificate(X509_STORE* , X509* ); 
