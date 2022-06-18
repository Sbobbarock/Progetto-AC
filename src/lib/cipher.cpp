#include "header/cipher.h"
#include <openssl/err.h>
#include <iostream>

//funzione per crittografare un blocco di dati. 
bool encrypt_gcm(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                uint32_t* ciphertext_len,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len=0;
    *ciphertext_len=0;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return false;

    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return false;

    
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        return false;

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return false;
    *ciphertext_len = len;

    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
        return false;
    *ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        return false;

    EVP_CIPHER_CTX_cleanup(ctx);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}



//funzione per decriptare il ciphertext. 
bool decrypt_gcm(unsigned char *ciphertext, uint32_t ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *plaintext,
                uint32_t* plaintext_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ret;

    if(!(ctx = EVP_CIPHER_CTX_new())){
        std::cout<<ERR_error_string(ERR_get_error(),NULL);
        return false;
    }
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv)){
        std::cout<<ERR_error_string(ERR_get_error(),NULL);
        return false;
    }

    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
        std::cout<<ERR_error_string(ERR_get_error(),NULL);
        return false;
    }

    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
        std::cout<<ERR_error_string(ERR_get_error(),NULL);
        return false;
    }
    *plaintext_len = len;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)){
        std::cout<<ERR_error_string(ERR_get_error(),NULL);
        return false;
    }

    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_cleanup(ctx);

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        *plaintext_len += len;
        return true;
    } else {
        std::cout<<ERR_error_string(ERR_get_error(),NULL)<<std::endl;
        perror("Decrypt error");
        return false;
    }
}
