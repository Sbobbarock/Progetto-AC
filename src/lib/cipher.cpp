#include "openssl/evp.h"
#include "header/cipher.h"

int encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len=0;
    int ciphertext_len=0;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return 0;

    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return 0;

    
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        return 0;

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return 0;
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
        return 0;
    ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        return 0;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}