#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <string.h>
#include <openssl/rand.h>
#include "../lib/packet.h"
#include "../lib/DH.h"

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

void handshake(int sd){
    int ret;
    uint32_t* len;
    unsigned char* buffer;
    unsigned char nonce_c[NONCE_LEN];
    std::string username;

    //genero il nonce(C)
    RAND_poll();
    RAND_bytes(nonce_c,NONCE_LEN);
    do{
        std::cout<<"Inserisci nome utente: ";
        std::cin>>username;
    }while(!check_string(username) || username.length() > MAX_USERNAME);

    //standardizzo la lunghezza del nome utente
    username.resize(MAX_USERNAME);

    //invio nonce e nome utente
    if(!send_packet<const char>(sd,username.c_str(),MAX_USERNAME)){
        std::cout<<"Errore nell'invio del nome utente\n";
        close(sd);
        exit(1);
    }
    if(!send_packet<unsigned char>(sd,nonce_c, NONCE_LEN)){
        std::cout<<"Errore nell'invio del nonce\n";
        close(sd);
        exit(1);
    }
    
    //inizializzazione parametri DH e chiave privata
    EVP_PKEY* my_privkey = DH_privkey();
    //ricavo e leggo file PEM con la mia chiave pubblica
    //genera dinamicamente il nome del file!
    len = (uint32_t*)malloc(sizeof(uint32_t));
    if(!len){
        std::cout<<"Errore nella malloc()\n";
        EVP_PKEY_free(my_privkey);
        close(sd);
        exit(1);
    }
    buffer = DH_pubkey(std::string("dh_myPUBKEY.pem"),my_privkey,len);
    if(!buffer){
        std::cout<<"Errore nella generazione della chiave pubblica\n";
        EVP_PKEY_free(my_privkey);
        close(sd);
        free(len);
        exit(1);
    } 
    //invio la dimensione del file PEM al server
    *len = htonl(*len);
    if(!send_packet<uint32_t>(sd,len,sizeof(uint32_t))){
        std::cout<<"Errore nell'invio della dimensione del file PEM\n";
        EVP_PKEY_free(my_privkey);
        free(buffer);
        free(len);
        close(sd);
        exit(1);
    }
    *len = ntohl(*len);
    //invio il file PEM con la chiave pubblica al server
    if(!send_packet<unsigned char>(sd,buffer,*len)){
        std::cout<<"Errore nell'invio del file PEM con la chiave pubblica\n";
        EVP_PKEY_free(my_privkey);
        free(buffer);
        free(len);
        close(sd);
        exit(1);
    }
    free(len);
    //ricevo la chiave pubblica del server
    len = recv_packet<uint32_t>(sd,sizeof(uint32_t));
    if(!len){
        std::cout<<"Errore nella ricezione della dimensione del file PEM\n";
        EVP_PKEY_free(my_privkey);
        free(buffer);
        close(sd);
        exit(1);
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
        close(sd);
        free(len);
        exit(1);
    }
    //genera dinamicamente il nome del file!
    EVP_PKEY* server_pubkey = DH_derive_pubkey(std::string("dh_serverpubkey.pem"),buffer,*len);
    if(!server_pubkey){
        std::cout<<"Errore nella derivazione della chiave pubblica ricevuta dal server\n";
        EVP_PKEY_free(my_privkey);
        free(len);
        free(buffer);
        close(sd);
        exit(1);
    }
    
    size_t secret_len;
    unsigned char* K_ab = DH_derive_session_secret(my_privkey,server_pubkey,&secret_len);
    if(!K_ab){
        std::cout<<"Errore nella derivazione del segreto di sessione\n";
        EVP_PKEY_free(my_privkey);
        free(len);
        free(buffer);
        EVP_PKEY_free(server_pubkey);
        close(sd);
        exit(1);
    }
    exit(0);
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
