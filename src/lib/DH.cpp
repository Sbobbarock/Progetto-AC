#include "DH.h"

EVP_PKEY* DH_privkey(){
    
    EVP_PKEY* dh_params = EVP_PKEY_new();
    EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());
    EVP_PKEY_CTX* dh_ctx = EVP_PKEY_CTX_new(dh_params,NULL);
    EVP_PKEY* my_privkey = NULL;
    EVP_PKEY_keygen_init(dh_ctx);
    EVP_PKEY_keygen(dh_ctx,&my_privkey);
    EVP_PKEY_CTX_free(dh_ctx);
    return my_privkey;
}

//ritorna il buffer contenente il file PEM della chiave pubblica
unsigned char* DH_pubkey(std::string filename,EVP_PKEY* my_privkey,uint32_t* file_len){
    FILE* pubkey_PEM = fopen(filename.c_str(),"w+");
    if(!pubkey_PEM){
        std::cout<<"Errore nella creazione del file PEM per la chiave pubblica\n";
        return NULL;
    }
    //ricavo la chiave pubblica dalla chiave privata DH
    int ret = PEM_write_PUBKEY(pubkey_PEM,my_privkey);
    if(ret != 1){
        std::cout<<"Errore nella generazione della chiave pubblica\n";
        fclose(pubkey_PEM);
        return NULL;
    }
    //leggo la dimensione del file PEM contenente la chiave pubblica
    fseek(pubkey_PEM,0,SEEK_END);
    *file_len = (uint32_t)ftell(pubkey_PEM); //CHECK OVERFLOW!
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
        return NULL;
    }
    
    fclose(pubkey_PEM);
    return buffer;
}

EVP_PKEY* DH_derive_pubkey(std::string filename,unsigned char* buffer,uint32_t file_len){

    FILE* pubkey_PEM = fopen(filename.c_str(),"w+");
    if(!pubkey_PEM){
        std::cout<<"Errore nell'apertura del file PEM\n";
        return NULL;
    }
    //scrivo la chiave pubblica ricevuta nel file PEM
    int ret = fwrite(buffer,1,file_len,pubkey_PEM);
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

unsigned char* DH_derive_session_secret(EVP_PKEY* my_privkey, EVP_PKEY* received_pubkey,size_t* key_len){

    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(my_privkey,NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv,received_pubkey);
    unsigned char* K_ab;
    EVP_PKEY_derive(ctx_drv,NULL,key_len);

    K_ab = (unsigned char*)malloc(*key_len);
    if(!K_ab){
        std::cout<<"Errore nella malloc()\n";
        return NULL;
    }
    EVP_PKEY_derive(ctx_drv,K_ab,key_len);
    return  K_ab;
}
