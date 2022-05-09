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

#define BUF_SIZE 10
#define MAX_CONNECTED 5

////////////////////////////////////
// COMPILARE CON FLAG -lpthread !//
//////////////////////////////////

//invia la dimensione del pacchetto e successivamente il pacchetto stesso
void send_packet(int sd,char* msg){
    int ret;
    int dim_msg = htonl(strlen(msg)+1);

    ret = send(sd,&dim_msg,sizeof(uint32_t),0);
    if(!ret){
            perror("Errore:");
            return;
    }

    dim_msg = ntohl(dim_msg);
    ret = send(sd,msg,dim_msg,0);
    if(!ret){
        perror("Errore:");
        return;
    }
}

//riceve la dimensione del pacchetto e successivamente il pacchetto stesso
char* recv_packet(int sd){
    int ret;
    char * buffer;
    int dim_msg;

    ret = recv(sd,&dim_msg,sizeof(uint32_t),0);
    if(!ret){
        close(sd);
        pthread_exit(NULL);
        return NULL;
    }

    dim_msg = ntohl(dim_msg);
    buffer = (char*)malloc(dim_msg);
    if(!buffer){
        close(sd);
        pthread_exit(NULL);
        return NULL;
    }
    ret = recv(sd,buffer,dim_msg,0);
   if(!ret){
        close(sd);
        pthread_exit(NULL);
        return NULL;
    }
    return buffer;
}

// routine eseguita dal thread
void* manageConnection(void* s){
    int ret = 0;
    char* buffer;
    int soc = *((int*)s);
    int dim_msg;
    // il client manda sempre il primo messaggio
    while(1){
        buffer = recv_packet(soc);
        if(!buffer){
            close(soc);
            pthread_exit(NULL);
        }
        printf("Ricevuto: %s",buffer);
        printf("INVIO: %s",buffer);

        send_packet(soc,buffer);
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
    char buffer[BUF_SIZE];
    char input[BUF_SIZE];

    /* variabili multiplexing I/O */
    int max_fd;
    fd_set MASTER,READY;

    /* multithreading */
    pthread_t thread_id;

    if(n_args != 2){
        printf("Errore: numero di porta non inserito\n");
        exit(0);
    }
    ret = sscanf(args[1],"%d",&porta); /* OVERFLOW? */
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
    if(listen(listener,MAX_CONNECTED) == -1){
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
        select(max_fd+1, &READY, NULL, NULL, NULL);
        for(i = 0; i <= max_fd; i++){
            if(!FD_ISSET(i,&READY))
                continue;
            else if(i == STDIN_FILENO){   
                
                fgets(buffer,BUF_SIZE,stdin); // NON SICURO: SOLO PER PROVA 
                printf("Letto: %s",buffer);
                
            }
            else if(i == listener){ /* richiesta di connessione al server */
                socklen_t addrlen = sizeof(client);
                client_sd = (int *)malloc(sizeof(int));
                if(!client_sd){
                    printf("Errore\n");
                    exit(0);
                }
                *client_sd = accept(listener,(struct sockaddr*)&client,&addrlen);
                if(pthread_create(&thread_id,NULL,manageConnection,(void*)client_sd)){ //crea un nuovo thread che gestisce il socket client-server
                    printf("Errore creazione del thread\n");
                    close(*client_sd);
                }
            }
        }
    }

}
