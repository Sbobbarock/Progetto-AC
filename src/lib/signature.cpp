#include "header/signature.h"

//metodo che firma il messaggio 
unsigned char* compute_signature(const EVP_MD* Hash_type, unsigned char* msg, int msg_len, EVP_PKEY* key,uint32_t* signature_len){

    unsigned char* signature = (unsigned char*)malloc(EVP_PKEY_size(key));
    if(!signature)
        return NULL;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx,Hash_type);
    EVP_SignUpdate(ctx,msg,size_t(msg_len));
    EVP_SignFinal(ctx,signature,signature_len,key);
    EVP_MD_CTX_free(ctx);

    return signature;
}


//metodo per verificare la firma del messaggio 
bool verify_signature(const EVP_MD* Hash_type, unsigned char* signature, int sign_len, EVP_PKEY* key,unsigned char* msg,uint32_t msg_len){

    int ret;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(ctx,Hash_type);
    EVP_VerifyUpdate(ctx,msg,size_t(msg_len));
    ret = EVP_VerifyFinal(ctx,signature,sign_len,key);
    if(ret != 1){
        EVP_MD_CTX_free(ctx);
        return false;
    }
    EVP_MD_CTX_free(ctx);
    return true;
}