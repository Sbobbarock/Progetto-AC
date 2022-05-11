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


#define IP "127.0.0.1"
#define MAX_USER_INPUT 10

int main(int n_args, char** args){
    int porta;
    int ret;
    int sd; //socket id
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
