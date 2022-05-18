#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define IP "127.0.0.1"
#define MAX_USER_INPUT 10
#define NONCE_LEN 16
#define MAX_USERNAME 20
#define MAX_CONNECTED 5

template<class T> 
bool send_packet(int sd, T* msg, int len){
    int ret = 0;
    do{
        ret += send(sd,msg,len,0);
        if(!ret)
            return false;
    }while(ret < len); 
    return true;
}

template <class T>
T* recv_packet(int sd,int len){
    int ret;
    T* buffer;
    int dim_msg;

    buffer = (T*)malloc(len);
    if(!buffer){
        std::cerr<<"Buffer allocation for received packet failed\n";
        return NULL;
    }
    ret = recv(sd,buffer,len,0);
    if(!ret){
        free(buffer);
        return NULL;
    }
    while(ret < len)
        ret += recv(sd,buffer,len,0);
    
    return buffer;
}

unsigned char* nonce(unsigned char* buffer){
    RAND_poll();
    RAND_bytes(buffer,NONCE_LEN);
    return buffer;
}

EVP_PKEY* read_RSA_privkey(std::string filename){
    FILE* file = fopen(filename.c_str(),"r");
    EVP_PKEY* key = PEM_read_PrivateKey(file,NULL,NULL,NULL);
    fclose(file);
    return key;
}

EVP_PKEY* read_RSA_pubkey(std::string username){
    username = "PubKeyList/" + username + ".pem";
    FILE* file = fopen(username.c_str(),"r");
    EVP_PKEY* key = PEM_read_PUBKEY(file,NULL,NULL,NULL);
    fclose(file);
    return key;
}

bool send_file(int sd,std::string file){

    FILE* f = fopen(file.c_str(),"r");
    if(!f)
        return false;
    uint32_t file_len;
    fseek(f,0,SEEK_END);
    file_len = ftell(f);
    rewind(f);

    unsigned char* buffer = (unsigned char*)malloc(file_len);
    if(!buffer)
        return false;
    fread(buffer,1,file_len,f);
    fclose(f);
    file_len = htonl(file_len);
    if(!send_packet<uint32_t>(sd,&file_len,sizeof(uint32_t)))
        return false;
    if(!send_packet<unsigned char>(sd,buffer,ntohl(file_len)))
        return false;
    return true;
}
