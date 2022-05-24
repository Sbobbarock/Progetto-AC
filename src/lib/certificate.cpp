#include "header/certificate.h"

X509_STORE* build_store(std::string file_crl,std::string root_cert){
    X509_STORE* store = X509_STORE_new();
    FILE* f_crl = fopen(file_crl.c_str(),"r");
    if(!f_crl) return NULL;
    X509_CRL* crl = PEM_read_X509_CRL(f_crl,NULL,NULL,NULL);
    fclose(f_crl);
    FILE* f_root = fopen(root_cert.c_str(),"r");
    if(!f_root) return NULL;
    X509* root = PEM_read_X509(f_root,NULL,NULL,NULL);

    X509_STORE_add_cert(store,root);
    X509_STORE_add_crl(store,crl);
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    fclose(f_root);
    return store;
}

X509* read_certificate(std::string file,unsigned char* buffer,uint32_t len){
    FILE* f_cert = fopen(file.c_str(),"w+");
    if(!f_cert) return NULL;
    fwrite(buffer,1,len,f_cert);
    rewind(f_cert);
    X509* cert = PEM_read_X509(f_cert,NULL,NULL,NULL);
    fclose(f_cert);
    return cert;
}

EVP_PKEY* validate_certificate(X509_STORE* store, X509* cert){

    X509_STORE_add_cert(store,cert);
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);
    if(X509_verify_cert(ctx) == 1){
        X509_STORE_CTX_free(ctx);
        if(std::string(X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0)).find("O=Server") == std::string::npos){
            std::cout<<"Il certificato non appertiene al server\n";
            return NULL;
        }                                                                              
        return X509_get_pubkey(cert);
    }
    else
        std::cerr<<X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
    X509_STORE_CTX_free(ctx);
    return NULL;
} 
