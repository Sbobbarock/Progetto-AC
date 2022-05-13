#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define MAX_USER_INPUT 10
#define MAX_CONNECTED 5
#define MAX_USERNAME 20
#define NONCE_LEN 16

/////////////////////////////////////
//// COMPILE WITH FLAG -lpthread ///
///////////////////////////////////

bool send_packet(int sd,unsigned char* msg,int len){
    int ret = 0;

    do{
        ret += send(sd,msg,len,0);
        if(!ret)
            return false;
    }while(ret < len);
    return true;
}

unsigned char* recv_packet(int sd,int len){
    int ret;
    unsigned char* buffer;
    int dim_msg;

    buffer = (unsigned char*)malloc(len);
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

void disconnect(int sd){
    close(sd);
    std::cout<<"Client disconnected\n";
    pthread_exit(NULL);
}

// routine eseguita dal thread
void* manageConnection(void* s){
    int ret = 0;
    uint32_t* len;
    char* username;
    unsigned char* buffer;
    std::string client_check;
    unsigned char* nonce_c;
    int soc = *((int*)s);
    int dim_msg;
 
    while(1){
        username = (char*)recv_packet(soc,MAX_USERNAME);
        if(!username)
            disconnect(soc);
        //ricevo username e nonce
        username[MAX_USERNAME-1] = '\0';
        nonce_c = recv_packet(soc,NONCE_LEN);
        if(!nonce_c)
            disconnect(soc);

        //check del nome utente dal file client_list.txt
        std::ifstream user_file;
        user_file.open("client_list.txt");
        while(std::getline(user_file,client_check)){
            if(!client_check.compare(username)){
               std::cout<<"NOME VALIDO\n";
                break;     
            }
        }
        //nome utente non trovato
        if(user_file.eof()){
            user_file.close();
            std::cout<<"Nome utente non valido\n";
            disconnect(soc);
        }
        user_file.close();

        EVP_PKEY* dh_params;
        dh_params = EVP_PKEY_new();
        EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());
        EVP_PKEY_CTX* dh_ctx = EVP_PKEY_CTX_new(dh_params,NULL);
        EVP_PKEY* my_privkey = NULL;
        EVP_PKEY_keygen_init(dh_ctx);
        EVP_PKEY_keygen(dh_ctx,&my_privkey);

        FILE* pubkey_PEM = fopen("dh_pubkey.pem","w+");
        ret = PEM_write_PUBKEY(pubkey_PEM,my_privkey);
        if(ret != 1){
            std::cout<<"Errore nella generazione della chiave pubblica\n";
            EVP_PKEY_free(my_privkey);
            fclose(pubkey_PEM);
            EVP_PKEY_CTX_free(dh_ctx);
            disconnect(soc);
        }
        fseek(pubkey_PEM,0,SEEK_SET);
        EVP_PKEY* my_pubkey = PEM_read_PUBKEY(pubkey_PEM,NULL,NULL,NULL);
        if(!my_pubkey){
            std::cout<<"Errore nella generazione della chiave pubblica\n";
            EVP_PKEY_free(my_privkey);
            fclose(pubkey_PEM);
            EVP_PKEY_CTX_free(dh_ctx);
            disconnect(soc);
        }
        fseek(pubkey_PEM,0,SEEK_END);
        *len = ftell(pubkey_PEM);
        ///////////////////
        //CHECK OVERFLOW//
        /////////////////
        rewind(pubkey_PEM);

        unsigned char* pub_key_msg = (unsigned char*)malloc(*len);
        fread(pub_key_msg,1,*len,pubkey_PEM);
        if(!pub_key_msg){
            std::cout<<"Errore malloc()\n";
            EVP_PKEY_free(my_privkey);
            fclose(pubkey_PEM);
            EVP_PKEY_CTX_free(dh_ctx);
            disconnect(soc);
        }
        *len = htonl(*len);
        if(!send_packet(soc,(unsigned char*)len,sizeof(uint32_t))){
            disconnect(soc);
        }
        *len = ntohl(*len);
        if(!send_packet(soc,pub_key_msg,*len)){
            disconnect(soc);
        }
        fclose(pubkey_PEM);

        len = (uint32_t*)recv_packet(soc,sizeof(uint32_t));
        *len = ntohl(*len);
        ///////////////////
        //CHECK OVERFLOW//
        /////////////////
        buffer = (unsigned char*)malloc((size_t)*len);
        if(!buffer){
            std::cout<<"Errore malloc()\n";
            EVP_PKEY_free(my_privkey);
            fclose(pubkey_PEM);
            EVP_PKEY_CTX_free(dh_ctx);
            disconnect(soc);////da rivedere!!!!
        }
        buffer = recv_packet(soc,*len);

        FILE* pem = fopen("client_pubkey.pem","w+");// GENERARE NOME FILE DINAMICAMENTE
        ret = fwrite(buffer,1,*len,pem);
        if(ret < *len){
            std::cout<<"Errore scrittura del server_pubkey.pem\n";
            fclose(pem);
            disconnect(soc);
            ////////////
            // check della deallocazione!!!!
            ///////////////////
        }
        fseek(pem,0,SEEK_SET);
        EVP_PKEY* client_pubkey = PEM_read_PUBKEY(pem,NULL,NULL,NULL);
        if(!client_pubkey){
            std::cout<<"Errore nella lettura della chiave pubblica del client\n";
            EVP_PKEY_free(my_privkey);
            fclose(pem);
            EVP_PKEY_CTX_free(dh_ctx);
            close(soc);
            exit(1);//da riguardare!!!!!
        }
        fclose(pem);

        EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(my_privkey,NULL);
        EVP_PKEY_derive_init(ctx_drv);
        EVP_PKEY_derive_set_peer(ctx_drv,client_pubkey);
        unsigned char* K_ab;
        size_t secret_len;
        EVP_PKEY_derive(ctx_drv,NULL,&secret_len);

        K_ab = (unsigned char*)malloc(secret_len);
        if(!K_ab){
            std::cout<<"Errore nella malloc()\n";
            exit(1); //da riguardare!!!!!
        }
        EVP_PKEY_derive(ctx_drv,K_ab,&secret_len);
        /////////////////////////
        // COMPUTE DIGEST OF K_ab
        //////////////////////// 
    }
}

int main(int n_args, char** args){
    int i;
    int porta; /*porta del server */
    int listener; /* socket listener TCP */
    int* client_sd;
    socklen_t len;
    struct sockaddr_in server, client;
    int ret; /*controllo errori */
    char user_input[MAX_USER_INPUT];

    /* variabili multiplexing I/O */
    int max_fd;
    fd_set MASTER,READY;

    /* multithreading */
    pthread_t thread_id;

    if(n_args != 2){
        std::cout<<"Errore: numero di porta non inserito\n";
        exit(1);
    }
    ret = sscanf(args[1],"%d",&porta);
    if(!ret){
        std::cout<<"Numero di porta non valido\n";
        exit(1);
    }
    
    /* inizializzo socket listener */
    listener = socket(AF_INET,SOCK_STREAM,0);
    if(listener == -1){
        perror("Error: ");
        exit(1);
    }
    memset(&server,0,sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(porta);

    if(bind(listener,(struct sockaddr*)&server,sizeof(server)) == -1){
        perror("Error: ");
        exit(1);
    }
    if(listen(listener,MAX_CONNECTED) == -1){
        perror("Error: ");
        exit(1);
    }

    FD_ZERO(&MASTER);
    FD_ZERO(&READY);
    FD_SET(STDIN_FILENO,&MASTER);
    FD_SET(listener,&MASTER);

    max_fd = listener;
    while(1){
        READY = MASTER;
        select(max_fd+1, &READY, NULL, NULL, NULL);
        for(i = 0; i <= max_fd; i++){
            if(!FD_ISSET(i,&READY))
                continue;
            else if(i == STDIN_FILENO){   
                if(!fgets(user_input,MAX_USER_INPUT,stdin)){
                    std::cerr<<"Error in reading user input\n";
                    exit(1);
                }
                char* p = strchr(user_input,'\n');
                if(p)
                    *p = '\0';
                else{
                    scanf("%*[^\n]");
                    scanf("%*c");
                }
                std::cout<<"Letto da stdin: "<<user_input<<std::endl;
            }
            else if(i == listener){ /* richiesta di connessione al server */
                socklen_t addrlen = sizeof(client);
                client_sd = (int *)malloc(sizeof(int));

                if(!client_sd){
                    close(listener);
                    std::cerr<<"Error in allocating client struct\n";
                    exit(1);
                }

                *client_sd = accept(listener,(struct sockaddr*)&client,&addrlen);
                if(*client_sd == -1){
                    perror("Error: ");
                    close(listener);
                    free(client_sd);
                    exit(1);
                }
                if(pthread_create(&thread_id,NULL,manageConnection,(void*)client_sd)){ //crea un nuovo thread che gestisce il socket client-server
                    std::cout<<"Errore creazione del thread\n";
                    close(*client_sd);
                    close(listener);
                    free(client_sd);
                }
            }
        }
    }
    close(listener);
}
