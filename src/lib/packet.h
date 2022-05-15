#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <iostream>

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

