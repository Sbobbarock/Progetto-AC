#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cmath>
#include "cipher.h"

#define IP "127.0.0.1"
#define NONCE_LEN 16
#define MAX_USERNAME 20
#define MAX_CONNECTED 5
#define SIZE_FILENAME 255
#define REQ_LEN 296
#define STD_AAD_LEN 25
#define AAD_LEN 20
#define MAX_PAYLOAD_SIZE (uint64_t)pow(2,10)

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

unsigned char* nonce(unsigned char* buffer, unsigned int nonce_len){
    RAND_poll();
    RAND_bytes(buffer,nonce_len);
    return buffer;
}

EVP_PKEY* read_RSA_privkey(std::string filename){
    FILE* file = fopen(filename.c_str(),"r");
    if(!file) {
        return NULL;
    }
    EVP_PKEY* key = PEM_read_PrivateKey(file,NULL,NULL,NULL);
    fclose(file);
    return key;
}

EVP_PKEY* read_RSA_pubkey(std::string username){
    std::string file_name;
    file_name = "PubKeyList/" + username + ".pem";
    FILE* file = fopen(file_name.c_str(),"r");
    if(!file) {
        return NULL;
    }
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

/*Funzione che controlla la validita' di una stringa: 
  - la stringa non e' vuota? 
  - i caratteri che ne fanno parte sono consentiti? */
bool check_string(std::string s){
    static char ok_chars[] = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "1234567890."; 
    if(s.find_first_not_of(ok_chars) != std::string::npos){
        std::cout<<"Stringa non valida\n";
        return false;
    }
    return true;
}

unsigned char* build_aad_std(uint64_t counter, uint32_t num_packets, uint8_t id, unsigned char* iv){

    //aad = counter || id || num_packets || iv
    unsigned char* aad = (unsigned char*)malloc(STD_AAD_LEN);
    if(!aad){
        return NULL;
    }
    memcpy(aad,&counter,sizeof(uint64_t));
    memcpy(aad + sizeof(uint64_t),&id,sizeof(uint8_t));
    memcpy(aad + sizeof(uint64_t) + sizeof(uint8_t), &num_packets, sizeof(uint32_t));
    memcpy(aad + sizeof(uint64_t) + sizeof(uint8_t) + sizeof(uint32_t), iv, 12);

    return aad;
}

unsigned char* build_request(unsigned char* aad, unsigned char* ciphertext, unsigned char* tag,uint32_t aad_len, uint32_t cipher_len){

    unsigned char* request = (unsigned char*)malloc(cipher_len + aad_len + 16);
        if(!request){
            std::cout<<"Errore nella malloc\n";
            return NULL;
        }

        memcpy(request,aad,aad_len);
        memcpy(request + aad_len, ciphertext, cipher_len);
        memcpy(request + aad_len + cipher_len, tag, 16);
        return request;
}


void send_std_packet(std::string filename, unsigned char* key,int sd, uint64_t* counter, uint8_t id, uint32_t num_packets){


    unsigned char* iv = (unsigned char*)malloc(12);
    if(!iv){
        std::cout<<"Errore nella malloc\n";
        return;
    }
    iv = nonce(iv,12);

    unsigned char* aad = build_aad_std(*counter,num_packets,id,iv);
    if(!aad){
        std::cout<<"Errore nella generazione dell' aad del pacchetto\n";
        free(iv);
        return;
    }
    unsigned char* ciphertext = (unsigned char*)malloc(SIZE_FILENAME);
    if(!ciphertext){
        std::cout<<"Errore nella malloc\n";
        free(iv);
        free(aad);
        return;
    }
    unsigned char* tag = (unsigned char*)malloc(16);
    if(!tag){
        std::cout<<"Errore nella malloc\n";
        free(iv);
        free(aad);
        free(ciphertext);
        return;
    }
    uint32_t* ciphertext_len = (uint32_t*)malloc(sizeof(uint32_t));

    if( !encrypt_gcm((unsigned char*)filename.c_str(),SIZE_FILENAME,aad,STD_AAD_LEN,key,iv,ciphertext,ciphertext_len, tag) ){
        std::cout<<"Errore nella encrypt della richiesta\n";
        free(iv);
        free(aad);
        free(ciphertext);
        free(tag);
        return;
    }
    unsigned char* request = build_request(aad,ciphertext,tag,STD_AAD_LEN,*ciphertext_len);
    if(!request){
        std::cout<<"Errore nella malloc\n";
        free(iv);
        free(aad);
        free(ciphertext);
        free(tag);
        return;
    }
    if(!send_packet<unsigned char>(sd, request, REQ_LEN)){
        std::cout<<"Errore nell'invio della richiesta\n";
        free(iv);
        free(aad);
        free(ciphertext);
        free(tag);
        return;
    }
    std::cout<<"COUNTER: "<<*counter<<std::endl;
    (*counter)++;
    free(iv);
    free(aad);
    free(ciphertext);
    free(tag);
    std::cout<<"INVIATO\n";
    return;
}

bool read_request_param(unsigned char* request,uint64_t* counter,uint32_t* num_packets, uint8_t* id, unsigned char* plaintext,unsigned char* key){

    uint64_t received_count;
    memcpy(&received_count,request,sizeof(uint64_t));

    //controllo id
    memcpy(id,request + sizeof(uint64_t),sizeof(uint8_t));

    //controllo num_packets
    memcpy(num_packets,request + sizeof(uint64_t) +  sizeof(uint8_t), sizeof(uint32_t));

    //ricavo il ciphertext
    unsigned char* ciphertext = (unsigned char*)malloc(SIZE_FILENAME);
    if(!ciphertext){
        std::cout<<"Errore nella malloc\n";
        return false;
    }
    memcpy(ciphertext,request+ STD_AAD_LEN, SIZE_FILENAME);

    unsigned char* aad = (unsigned char*)malloc(STD_AAD_LEN);
    if(!aad){
        std::cout<<"Errore nella malloc\n";
        return false;
    }
    unsigned char* tag = (unsigned char*)malloc(16);
    if(!tag){
        std::cout<<"Errore nella malloc\n";
        free(aad);
        return false;
    }
    unsigned char* iv = (unsigned char*)malloc(12);
    if(!iv){
        std::cout<<"Errore nella malloc\n";
        free(tag);
        free(aad);
        return false;
    }

    memcpy(iv,request + sizeof(uint64_t) + sizeof(uint8_t) + sizeof(uint32_t), 12 );
    memcpy(tag,request + SIZE_FILENAME + STD_AAD_LEN, 16);
    memcpy(aad, request, STD_AAD_LEN);
    uint32_t* plaintext_len = (uint32_t*)malloc(sizeof(uint32_t));
    if(!decrypt_gcm(ciphertext, SIZE_FILENAME, aad, STD_AAD_LEN, tag, key, iv , plaintext,plaintext_len)){
        std::cout<<"Errore nella decfiratura della richiesta\n";
        free(aad);
        free(tag);
        free(iv);
        free(ciphertext);
        return false;
    }   
    if(received_count != *counter){
        std::cout<<"Counter errato\n";
        return false;
    }
    std::cout<<"COUNTER: "<<*counter<<std::endl;
    (*counter)++;
    free(aad);
    free(tag);
    free(iv);
    free(ciphertext); 
    return true;
}

unsigned char* build_aad_data(uint64_t counter, unsigned char* iv){

    //aad = counter || iv
    unsigned char* aad = (unsigned char*)malloc(AAD_LEN);
    if(!aad){
        return NULL;
    }
    memcpy(aad,&counter,sizeof(uint64_t));
    memcpy(aad + sizeof(uint64_t), iv, 12);

    return aad;
}

void send_data_packet(unsigned char* data, unsigned char* key,int sd, uint64_t* counter,uint32_t data_len){

    unsigned char* iv = (unsigned char*)malloc(12);
    if(!iv){
        std::cout<<"Errore nella malloc\n";
        return;
    }
    iv = nonce(iv,12);

    unsigned char* aad = build_aad_data(*counter,iv);
    if(!aad){
        std::cout<<"Errore nella generazione dell' aad del pacchetto\n";
        free(iv);
        return ;
    }
    unsigned char* ciphertext = (unsigned char*)malloc(data_len + 16);
    if(!ciphertext){
        std::cout<<"Errore nella malloc\n";
        free(iv);
        free(aad);
        return ;
    }
    unsigned char* tag = (unsigned char*)malloc(16);
    if(!tag){
        std::cout<<"Errore nella malloc\n";
        free(iv);
        free(aad);
        free(ciphertext);
        return ;
    }

    uint32_t* ciphertext_len = (uint32_t*)malloc(sizeof(uint32_t));
    
    if( !encrypt_gcm(data,data_len,aad,AAD_LEN,key,iv,ciphertext,ciphertext_len,tag) ){
        std::cout<<"Errore nella encrypt della richiesta\n";
        free(iv);
        free(aad);
        free(ciphertext);
        free(tag);
        return ;
    }

    unsigned char* extended_aad = (unsigned char*)malloc(AAD_LEN + sizeof(uint32_t));
    memcpy(extended_aad, ciphertext_len, sizeof(uint32_t));
    memcpy(extended_aad + sizeof(uint32_t), aad, AAD_LEN);
    unsigned char* request = build_request(extended_aad,ciphertext,tag,AAD_LEN + sizeof(uint32_t),*ciphertext_len);
    if(!request){
        std::cout<<"Errore nella malloc\n";
        free(iv);
        free(aad);
        free(ciphertext);
        free(tag);
        free(extended_aad);
        return ;
    }
    if(!send_packet<unsigned char>(sd, request, sizeof(uint32_t) + AAD_LEN + *ciphertext_len + 16)){
        std::cout<<"Errore nell'invio della richiesta\n";
        free(iv);
        free(aad);
        free(ciphertext);
        free(tag);
        free(extended_aad);
        return ;
    }
    std::cout<<"COUNTER: "<<*counter<<std::endl;
    (*counter)++;
    free(iv);
    free(aad);
    free(ciphertext);
    free(tag);
    free(extended_aad);
    std::cout<<"INVIATO\n";
    return;
}

unsigned char* receive_data_packet(int sd,uint64_t* counter,unsigned char* key,uint32_t* plaintext_len){

    uint32_t* data_len = recv_packet<uint32_t>(sd,sizeof(uint32_t));
    unsigned char* aad = recv_packet<unsigned char>(sd,AAD_LEN);
    unsigned char* payload = recv_packet<unsigned char>(sd,*data_len);
    unsigned char* tag = recv_packet<unsigned char>(sd,16);

    uint64_t received_count;
    unsigned char* iv = (unsigned char*)malloc(12);
    memcpy(&received_count,aad,sizeof(uint64_t));
    memcpy(iv,aad + sizeof(uint64_t), 12);

    if(received_count != *counter){
        std::cout<<"Errore: counter errato\n";
        return NULL;
    }
    (*counter)++;
    unsigned char* plaintext = (unsigned char*)malloc(*data_len);
    if(!decrypt_gcm(payload, *data_len, aad, AAD_LEN, tag, key, iv , plaintext,plaintext_len)){
        return NULL;
    }
    free(data_len);
    free(aad);
    free(payload);
    free(tag);
    free(iv);
    return plaintext;
}

uint32_t how_many_fragments(uint64_t size){
    return size/MAX_PAYLOAD_SIZE + (size % MAX_PAYLOAD_SIZE != 0);
}
