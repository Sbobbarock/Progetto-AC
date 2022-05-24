#include "header/cipher.h"

bool encrypt_gcm(unsigned char *plaintext, int plaintext_len,
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
        return false;

    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return false;

    
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        return false;

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return false;
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
        return false;
    ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        return false;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool decrypt_gcm(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return false;
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return false;

    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        return false;

    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return false;
    plaintext_len = len;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        return false;

    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_cleanup(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return true;
    } else {
        /* Verify failed */
        return false;
    }
}
