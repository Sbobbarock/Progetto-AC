#include "header/DH.h"



//Metodo per creare la chiave privata
EVP_PKEY* DH_privkey(){
    EVP_PKEY* dh_params = EVP_PKEY_new();
    if(!dh_params) {
        return NULL;
    }
    DH* low_params = DH_get_2048_224();
    if(!EVP_PKEY_set1_DH(dh_params, low_params)) {
        DH_free(low_params);
        EVP_PKEY_free(dh_params);
        return NULL;
    }
    DH_free(low_params);
    EVP_PKEY_CTX* dh_ctx = EVP_PKEY_CTX_new(dh_params,NULL);
    if(!dh_ctx){
        EVP_PKEY_free(dh_params);
        return NULL;
    }

    EVP_PKEY* my_privkey = NULL;
    if(!EVP_PKEY_keygen_init(dh_ctx)){
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(dh_ctx);
        return NULL;
    }
    if(!EVP_PKEY_keygen(dh_ctx,&my_privkey)){
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(dh_ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(dh_ctx);
    EVP_PKEY_free(dh_params);
    return my_privkey;
}

//ritorna il buffer contenente il file PEM della chiave pubblica 
unsigned char* DH_pubkey(std::string filename,EVP_PKEY* my_privkey,EVP_PKEY* pub_key,uint32_t* file_len){
    FILE* pubkey_PEM = fopen(filename.c_str(),"w+");
    if(!pubkey_PEM){
        std::cout<<"Errore nella creazione del file PEM per la chiave pubblica\n";
        return NULL;
    }

    //ricavo la chiave pubblica dalla chiave privata DH
    uint32_t ret = PEM_write_PUBKEY(pubkey_PEM,my_privkey);
    if(ret != 1){
        std::cout<<"Errore nella generazione della chiave pubblica\n";
        fclose(pubkey_PEM);
        return NULL;
    }

    //leggo la dimensione del file PEM contenente la chiave pubblica
    fseek(pubkey_PEM,0,SEEK_END);
    *file_len = (uint32_t)ftell(pubkey_PEM);
    rewind(pubkey_PEM);
    unsigned char* buffer = (unsigned char*)malloc((size_t)*file_len);
    if(!buffer){
        std::cout<<"Errore malloc()\n";
        fclose(pubkey_PEM);
        return NULL;
    }

    //leggo il file PEM con la chiave pubblica
    ret = fread(buffer,1,(size_t)*file_len,pubkey_PEM);
    if (ret < *file_len){
        std::cout<<"Errore nella lettura del file PEM\n";
        fclose(pubkey_PEM);
        free(buffer);
        return NULL;
    }
    fclose(pubkey_PEM);
    return buffer;
}


//deriva la chiave pubblica dal file PEM 
EVP_PKEY* DH_derive_pubkey(std::string filename,unsigned char* buffer,uint32_t file_len){

    FILE* pubkey_PEM = fopen(filename.c_str(),"w+");
    if(!pubkey_PEM){
        std::cout<<"Errore nell'apertura del file PEM\n";
        return NULL;
    }
    
    //scrivo la chiave pubblica ricevuta nel file PEM
    uint32_t ret = fwrite(buffer,1,file_len,pubkey_PEM);
    if(ret < file_len){
        std::cout<<"Errore scrittura del file PEM\n";
        fclose(pubkey_PEM);
        return NULL;
    }

    fseek(pubkey_PEM,0,SEEK_SET);
    EVP_PKEY* received_pubkey = PEM_read_PUBKEY(pubkey_PEM,NULL,NULL,NULL);
    if(!received_pubkey){
        std::cout<<"Errore nella lettura della chiave pubblica ricevuta\n";
        fclose(pubkey_PEM);
        return NULL;
    }
    fclose(pubkey_PEM);
    return received_pubkey;
}


//deriva il segreto di sessione 
unsigned char* DH_derive_session_secret(EVP_PKEY* my_privkey, EVP_PKEY* received_pubkey,size_t* secret_len){

    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(my_privkey,NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv,received_pubkey);
    unsigned char* secret;
    EVP_PKEY_derive(ctx_drv,NULL,secret_len);

    secret = (unsigned char*)malloc(*secret_len);
    if(!secret){
        EVP_PKEY_CTX_free(ctx_drv);
        std::cout<<"Errore nella malloc()\n";
        return NULL;
    }
    if(!EVP_PKEY_derive(ctx_drv,secret,secret_len)){
        EVP_PKEY_CTX_free(ctx_drv);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx_drv);
    return secret;
}


//deriva la chiave di sessione 
unsigned char* session_key(const EVP_MD* Hash_type,const EVP_CIPHER* Cipher_type, unsigned char* msg,size_t msg_len,unsigned int* digest_len){
    
    unsigned char* full_digest = (unsigned char*)malloc(EVP_MD_size(Hash_type));
    if(!full_digest)
        return NULL;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx) return NULL;
    if(!EVP_DigestInit(ctx,Hash_type)){
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    if(!EVP_DigestUpdate(ctx,msg,msg_len)){
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    if(!EVP_DigestFinal(ctx,full_digest,digest_len)){
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);
    if(*digest_len > (unsigned int)EVP_CIPHER_key_length(Cipher_type)){
        unsigned char* digest = (unsigned char*)malloc(EVP_CIPHER_key_length(Cipher_type));
        if(!digest){
            free(full_digest);
            return NULL;
        }
        memcpy(digest,full_digest,EVP_CIPHER_key_length(Cipher_type));
        free(full_digest);
        *digest_len = EVP_CIPHER_key_length(Cipher_type);
        return digest;
    }
    return full_digest;
}