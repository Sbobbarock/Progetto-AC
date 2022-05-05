#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>

#define BUF_SIZE 10

int main(int n_args, char** args){
    int i;
    int porta; /*porta del server */
    int listener; /* socket listener TCP */
    int client_sd;
    socklen_t len;
    struct sockaddr_in server, client;
    int ret; /*controllo errori */
    char buffer[BUF_SIZE];
    char input[BUF_SIZE];

    /* variabili multiplexing I/O */
    int max_fd;
    fd_set MASTER;
    fd_set READY;

    if(n_args != 2){
        printf("Errore: numero di porta non inserito\n");
        exit(0);
    }
    ret = sscanf(args[1],"%d",&porta); // OVERFLOW?
    if(!ret){
        printf("Numero di porta non valido\n");
        exit(0);
    }
    
    /* inizializzo socket listener */
    listener = socket(AF_INET,SOCK_STREAM,0);
    memset(&server,0,sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(porta);

    if(bind(listener,(struct sockaddr*)&server,sizeof(server)) == -1){
        perror("Errore: ");
        exit(0);
    }
    if(listen(listener,10) == -1){
        perror("Errore: ");
        exit(0);
    }

    FD_ZERO(&MASTER);
    FD_ZERO(&READY);
    FD_SET(STDIN_FILENO,&MASTER);
    FD_SET(listener,&MASTER);

    max_fd = listener;
    while(1){
        READY = MASTER;
        /* Bloccante. Si sblocca quando almeno uno dei socket (o stdin) e' pronto in
            lettura o scrittura. Attenzione: in READY rimangono solo i socket pronti */
        select(max_fd+1, &READY, NULL, NULL, NULL); 
        for(i = 0; i <= max_fd; i++){
            if(!FD_ISSET(i,&READY))
                continue;
            else if(i == STDIN_FILENO){   
                /*
                fgets(buffer,BUF_SIZE,stdin); //NON SICURO: SOLO PER PROVA 
                printf("Letto: %s",buffer);
                */
            }
            else if(i == listener){ /* richiesta di connessione al server */
                int addrlen = sizeof(client);
                client_sd = accept(listener,(struct sockaddr*)&client,&addrlen); //nuovo socket connesso con il client
                FD_SET(client_sd, &MASTER);
                if(client_sd > max_fd) max_fd = client_sd;
            }
            else{
                /* ret = 0;
                while(ret += recv(i,buffer,BUF_SIZE,0) < BUF_SIZE)  //controlla di averli ricevuti tutti i byte 
                    if(!ret){
                        close(i);
                        FD_CLR(i,&MASTER);
                    }
                
                    else{
                        printf("Ricevuto: %s",buffer);
                        printf("INVIO: %s",buffer);
                        send(i,buffer,BUF_SIZE,0);
                    }
                 */
            }
        }
    }

}