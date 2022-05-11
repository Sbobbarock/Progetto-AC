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
#include <iostream>

#define MAX_USER_INPUT 10
#define MAX_CONNECTED 5

/////////////////////////////////////
//// COMPILE WITH FLAG -lpthread ///
///////////////////////////////////

//invia la dimensione del pacchetto e successivamente il pacchetto stesso
void send_packet(int sd,char* msg){
    int ret;
    int dim_msg = htonl(strlen(msg)+1);

    ret = send(sd,&dim_msg,sizeof(uint32_t),0);
    if(!ret){
        free(msg);
        close(sd);
        std::cout<<"Client disconnected\n";
        pthread_exit(NULL);
    }
    while(ret < sizeof(uint32_t))
        ret += send(sd,&dim_msg,sizeof(uint32_t),0);

    dim_msg = ntohl(dim_msg);

    ret = send(sd,msg,dim_msg,0);
    if(!ret){
        free(msg);
        close(sd);
        std::cout<<"Client disconnected\n";
        pthread_exit(NULL);
    }
    while(ret < dim_msg)
        ret += send(sd,msg,dim_msg,0);

    free(msg);
}

//riceve la dimensione del pacchetto e successivamente il pacchetto stesso
char* recv_packet(int sd){
    int ret;
    char* buffer;
    int dim_msg;

    ret = recv(sd,&dim_msg,sizeof(uint32_t),0);
    if(!ret)
        return NULL;

    dim_msg = ntohl(dim_msg);

    buffer = (char*)malloc(dim_msg);
    if(!buffer){
        std::cerr<<"Buffer allocation for received packet failed\n";
        return NULL;
    }
    ret = recv(sd,buffer,dim_msg,0);
    if(!ret){
        free(buffer);
        return NULL;
    }
    while(ret < dim_msg)
        ret += recv(sd,buffer,dim_msg,0);
    //sanitize buffer
    buffer[dim_msg-1] = '\0';
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
            std::cout<<"Client disconnected\n";
            pthread_exit(NULL);
        }
        std::cout<<"Ricevuto: "<<buffer<<std::endl;
        std::cout<<"Invio: "<<buffer<<std::endl;

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
