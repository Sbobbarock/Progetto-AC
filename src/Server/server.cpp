#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <string.h>
#include <pthread.h>
#include <fstream>
#include "../lib/DH.h"
#include "../lib/packet.h"

#define MAX_USER_INPUT 10
#define MAX_CONNECTED 5
#define MAX_USERNAME 20
#define NONCE_LEN 16

/////////////////////////////////////
//// COMPILE WITH FLAG -lpthread ///
///////////////////////////////////

void disconnect(int sd){
    close(sd);
    std::cout<<"Client disconnected\n";
    pthread_exit(NULL);
}

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

// routine eseguita dal thread
void* manageConnection(void* s){
    int ret = 0;
    char* username;
    std::string client_check;
    unsigned char* nonce_c;
    int sd = *((int*)s);
    uint32_t* len;
 
    username = recv_packet<char>(sd,MAX_USERNAME);
    if(!username)
        disconnect(sd);
    //ricevo username e nonce
    username[MAX_USERNAME-1] = '\0';
    if(!check_string(std::string(username))){
        std::cout<<"Formato nome utente non valido\n";
        disconnect(sd);
    }
    nonce_c = recv_packet<unsigned char>(sd,NONCE_LEN);
    if(!nonce_c){
        std::cout<<"Errore nella ricezione del nonce\n";
        disconnect(sd);
    }
    //check del nome utente dal file client_list.txt
    std::ifstream user_file;
    user_file.open("client_list.txt");
    while(std::getline(user_file,client_check)){
        if(!client_check.compare(username)){
            std::cout<<"Connessione con: "<<username<<std::endl;
            break;     
        }
    }
    //nome utente non trovato
    if(user_file.eof()){
        user_file.close();
        std::cout<<"Nome utente non valido\n";
        free(username);
        disconnect(sd);
    }
    user_file.close();
    //inizializzazione parametri DH e chiave privata
    EVP_PKEY* my_privkey = DH_privkey();
    //ricavo e leggo file PEM con la mia chiave pubblica
    //genera dinamicamente il nome del file!
    
    len = (uint32_t*)malloc(sizeof(uint32_t));
    if(!len){
        std::cout<<"Errore nella malloc()\n";
        EVP_PKEY_free(my_privkey);
        free(username);
        disconnect(sd);
    }
    unsigned char* buffer = DH_pubkey(std::string("dh_myPUBKEY.pem"),my_privkey,len);
    if(!buffer){
        EVP_PKEY_free(my_privkey);
        free(username);
        free(len);
        disconnect(sd);
    }

    //invio la dimensione del file PEM al client
    *len = htonl(*len);
    if(!send_packet<uint32_t>(sd,len,sizeof(uint32_t))){
        EVP_PKEY_free(my_privkey);
        free(buffer);
        free(len);
        free(username);
        disconnect(sd);
    }
    *len = ntohl(*len);
    //invio il file PEM con la chiave pubblica al client
    if(!send_packet<unsigned char>(sd,buffer,*len)){
        EVP_PKEY_free(my_privkey);
        free(buffer);
        free(len);
        free(username);
        disconnect(sd);
    }
    free(len);
    //ricevo la chiave pubblica del client
    len = recv_packet<uint32_t>(sd,sizeof(uint32_t));
    if(!len){
        std::cout<<"Errore nella ricezione della dimensione del file PEM\n";
        EVP_PKEY_free(my_privkey);
        free(buffer);
        free(username);
        disconnect(sd);
    }
    *len = ntohl(*len);
    ///////////////////
    //CHECK OVERFLOW//
    /////////////////
    free(buffer);
    buffer = recv_packet<unsigned char>(sd,*len);
    if(!buffer){
        std::cout<<"Chiave pubblica non ricevuta correttamente\n";
        EVP_PKEY_free(my_privkey);
        free(username);
        free(len);
        disconnect(sd);
    }
    //genera dinamicamente il nome del file!
    EVP_PKEY* client_pubkey = DH_derive_pubkey(std::string("dh_clientpubkey.pem"),buffer,*len);
    if(!client_pubkey){
        std::cout<<"Errore nella derivazione della chiave pubblica ricevuta dal client\n";
        EVP_PKEY_free(my_privkey);
        free(username);
        free(len);
        free(buffer);
        disconnect(sd);
    }
    
    size_t secret_len;
    unsigned char* K_ab = DH_derive_session_secret(my_privkey,client_pubkey,&secret_len);
    if(!K_ab){
        std::cout<<"Errore nella derivazione del segreto di sessione\n";
        EVP_PKEY_free(my_privkey);
        free(username);
        free(len);
        free(buffer);
        EVP_PKEY_free(client_pubkey);
        disconnect(sd);
    }
    disconnect(sd);
    /////////////////////////
    // COMPUTE DIGEST OF K_ab
    //////////////////////// 
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
