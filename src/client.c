#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>


#define IP "127.0.0.1"
#define MAX_USER_INPUT 10
#define NONCE_LEN 16
#define MAX_USERNAME 20

bool check_string(std::string s){
    static char ok_chars[] = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "1234567890-.:"; 
    if(s.find_first_not_of(ok_chars) != std::string::npos || s[0] == '-'){
        std::cout<<"Stringa non valida\n";
        return false;
    }
    return true;
}

bool send_packet(int sd,unsigned char* msg, int len){
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

void handshake(int sd){
    int ret;
    uint32_t* len;
    unsigned char* buffer;
    unsigned char nonce_c[NONCE_LEN];
    std::string username;
    RAND_poll();
    RAND_bytes(nonce_c,NONCE_LEN);
    do{
        std::cout<<"Inserisci nome utente: ";
        std::cin>>username;
    }while(!check_string(username) || username.length() > MAX_USERNAME);

    username.resize(MAX_USERNAME);
    send_packet(sd,(unsigned char*)username.c_str(),username.length()+1);
    send_packet(sd,nonce_c,NONCE_LEN);

    len = (uint32_t*)recv_packet(sd,sizeof(uint32_t));
    *len = ntohl(*len);
    ///////////////////
    //CHECK OVERFLOW//
    /////////////////
    buffer = (unsigned char*)malloc((size_t)*len);
    buffer = recv_packet(sd,*len);

    FILE* pem = fopen("server_pubkey.pem","w+");
    ret = fwrite(buffer,1,*len,pem);
    if(ret < *len){
        std::cout<<"Errore scrittura del server_pubkey.pem\n";
        fclose(pem);
        close(sd);
        exit(1);
        ////////////
        // check della deallocazione!!!!
        ///////////////////
    }
    fseek(pem,0,SEEK_SET);
    EVP_PKEY* server_pubkey = PEM_read_PUBKEY(pem,NULL,NULL,NULL);
    if(!server_pubkey){
        std::cout<<"Errore nella lettura della chiave pubblica del server\n";
        fclose(pem);
        close(sd);
        exit(1);//da riguardare!!!!!
    }
    fclose(pem);

    EVP_PKEY* dh_params;
    dh_params = EVP_PKEY_new();
    EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());
    EVP_PKEY_CTX* dh_ctx = EVP_PKEY_CTX_new(dh_params,NULL);
    EVP_PKEY* my_privkey = NULL;
    EVP_PKEY_keygen_init(dh_ctx);
    EVP_PKEY_keygen(dh_ctx,&my_privkey);
    //inviare la chiave pubblica al server firmata insieme al nonce del server!

    FILE* pubkey_PEM = fopen("dh_pubkey.pem","w+");
    ret = PEM_write_PUBKEY(pubkey_PEM,my_privkey);
    if(ret != 1){
        std::cout<<"Errore nella generazione della chiave pubblica\n";
        EVP_PKEY_free(my_privkey);
        fclose(pubkey_PEM);
        EVP_PKEY_CTX_free(dh_ctx);
        close(sd);
        exit(1);//da riguardare!!!!!
    }
    fseek(pubkey_PEM,0,SEEK_SET);
    EVP_PKEY* my_pubkey = PEM_read_PUBKEY(pubkey_PEM,NULL,NULL,NULL);
    if(!my_pubkey){
        std::cout<<"Errore nella generazione della chiave pubblica\n";
        EVP_PKEY_free(my_privkey);
        fclose(pubkey_PEM);
        EVP_PKEY_CTX_free(dh_ctx);
        close(sd);
        exit(1);//da riguardare!!!!!
    }

    fseek(pubkey_PEM,0,SEEK_END);
    *len = ftell(pubkey_PEM);
    ///////////////////
    //CHECK OVERFLOW//
    /////////////////
    fseek(pubkey_PEM,0,SEEK_SET);

    unsigned char* pub_key_msg = (unsigned char*)malloc(*len);
    if(!pub_key_msg){
        std::cout<<"Errore nella malloc()\n";
        exit(1); //da riguardare!!!!!
    }
    ret = fread(pub_key_msg,1,*len,pubkey_PEM);
    if(ret < *len){
        std::cout<<"Errore nella lettura della chiave pubblica del client\n";
        EVP_PKEY_free(my_privkey);
        fclose(pem);
        EVP_PKEY_CTX_free(dh_ctx);
        close(sd);
        exit(1); //da riguardare!!!!!
    }
    
    *len = htonl(*len);
    if(!send_packet(sd,(unsigned char*)&len,sizeof(uint32_t))){
        exit(1);//da riguardare!!!!!
    }
    *len = ntohl(*len);
    if(!send_packet(sd,pub_key_msg,*len)){
        exit(1);//da riguardare!!!!!
    }
    fclose(pubkey_PEM);
    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(my_privkey,NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv,server_pubkey);
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

int main(int n_args, char** args){
    int porta;
    int ret;
    int sd; //sdket id
    char user_input[MAX_USER_INPUT];
    socklen_t len;
    struct sockaddr_in server;
    fd_set MASTER, READY;
    int max_fd;
    int dim_msg;
    char* buffer;

    if(n_args != 2){
        std::cout<<"Numero di porta non inserito\n";
        exit(1);
    }
    ret = sscanf(args[1],"%d",&porta);
    if(!ret){
        std::cout<<"Numero di porta non valido\n";;
        exit(1);
    }

    sd = socket(AF_INET,SOCK_STREAM,0);
    if(sd == -1){
        perror("Error:");
        exit(1);
    }
    memset(&server,0,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(porta);
    if(inet_pton(AF_INET,IP,&server.sin_addr) != 1){
        perror("Error:");
        exit(1);
    }
    ret = connect(sd,(struct sockaddr*)&server,sizeof(server));
    if(ret == -1){
        perror("Error:");
        exit(1);
    }
    FD_ZERO(&MASTER);
    FD_ZERO(&READY);
    FD_SET(STDIN_FILENO,&MASTER);
    FD_SET(sd,&MASTER);

    max_fd = sd;
    handshake(sd);
    while(1){
        READY = MASTER;
        select(max_fd+1, &READY, NULL,NULL,NULL);
        for(int i=0; i <=max_fd; i++){
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
                std::cout<<"INVIO: "<<user_input<<std::endl;
                
                //esempio di come inviare un intero sul network
                dim_msg = strlen(user_input)+1;
                dim_msg = htonl(dim_msg); //standardizza la endianess 
                ret = send(sd,&dim_msg,sizeof(uint32_t),0); 
                while(ret < sizeof(uint32_t)) //gestione errore se non invia tutti i byte
                    ret += send(sd,&dim_msg,sizeof(uint32_t),0);

                //dopo aver inviato la dimensione del pacchetto, invio il pacchetto vero e propio
                dim_msg = ntohl(dim_msg); //ripristina la endianess usata del sistema
                ret = send(sd,user_input,dim_msg,0);
                while(ret < dim_msg)
                    ret += send(sd,user_input,dim_msg,0);
            }

            else if(i == sd){
                //ricevo prima la dimensione del pacchetto
                ret = recv(i,&dim_msg,sizeof(uint32_t),0);
                if(!ret){
                    close(i);
                    FD_CLR(i,&MASTER);
                    std::cout<<"Server disconnected\n";
                    exit(0); 
                }
                while(ret < sizeof(uint32_t))
                    ret += recv(i,&dim_msg,sizeof(uint32_t),0);

                dim_msg = ntohl(dim_msg);
                buffer = (char*) malloc(dim_msg);
                if(!buffer){
                    std::cerr<<"Error in allocation of buffer for received packet\n";
                    close(i);
                    exit(1);
                }

                ret = recv(i,buffer,dim_msg,0);
                if(!ret){
                    close(i);
                    FD_CLR(i,&MASTER);
                    free(buffer);
                    std::cout<<"Server disconnected\n";
                    exit(0); 
                }
                while(ret < dim_msg)
                    ret += recv(i,buffer,dim_msg,0);

                buffer[dim_msg-1] = '\0';
                std::cout<<"Ricevuto: "<<buffer<<std::endl; 
                free(buffer); 
            }
        }
    }
    free(buffer);
    close(sd);
}
