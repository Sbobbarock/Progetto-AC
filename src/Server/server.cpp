#include <unistd.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <pthread.h>
#include <fstream>
#include <dirent.h>
#include "../lib/header/DH.h"
#include "../lib/header/utility.h"
#include "../lib/header/certificate.h"
#include "../lib/header/signature.h"
#include "../lib/header/cipher.h"


/////////////////////////////////////
//// COMPILE WITH FLAG -lpthread ///
///////////////////////////////////


/*Funzione per effettuare la disconnessione del client dal server. */
void disconnect(int sd){
    close(sd);
    std::cout<<"Client disconnected\n";
    pthread_exit(NULL);
}


/*Funzione che gestisce le azioni svolte lato server nel protocollo di handshake. 
  1) Il server riceve username, di cui controlla la validita' e nonce_c
  2) Il server genera la sua chiave privata e pubblica di DH
  3) Il server riceve la chiave pubblica del client di DH e deriva la chiave di sessione Kab 
  4) Il server invia il messaggio firmato con la sua chiave privata RSA, nonce_s e il certificato al client
  5) Il server verifica la firma del client
*/
unsigned char* handshake(int sd,unsigned int* key_len,std::string* username){

    int ret = 0;
    std::string client_check;
    unsigned char* nonce_c;
    uint32_t* len;
 
    char* tmp = recv_packet<char>(sd,MAX_USERNAME);
    if(!tmp)
        disconnect(sd);
    
    /******************************************************************************
     1) Il server riceve nonce e username del client e ne controlla la validita'.
     ********************************************************************************/
    tmp[MAX_USERNAME-1] = '\0';
    *username = std::string(tmp);
    free(tmp);
    if(!check_string( *(username) ) ){
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
        if(!client_check.compare(*username)){
            std::cout<<"Connessione con: "<<*username<<std::endl;
            break;     
        }
    }
    bool login_status = true;

    //se il nome utente non e' trovato il server invia un pacchetto al client 
    if(user_file.eof()){
        user_file.close();
        login_status = false;
        std::cout<<"Nome utente non valido\n";
        send_packet<bool>(sd,&login_status,sizeof(bool));
        
        free(nonce_c);
        disconnect(sd);
    }
    user_file.close();
    
    if(!send_packet<bool>(sd,&login_status,sizeof(bool))){
        
        free(nonce_c);
        disconnect(sd);
    }
    /**************************************************************************************/






    /**************************************************************************
     2) Creazione della chiave privata e pubblica del server del protocollo DH. 
        - inizializzo DH param e chiave privata del server 
        - ricavo chiave pubblica server
        - invio la chiave pubblica del server al client in file PEM 
    ***************************************************************************/

    EVP_PKEY* my_DHprivkey = DH_privkey();
    EVP_PKEY* my_DHpubkey = EVP_PKEY_new();


    //ricavo e leggo file PEM con la mia chiave pubblica
    //genera dinamicamente il nome del file!
    len = (uint32_t*)malloc(sizeof(uint32_t));
    if(!len){
        std::cout<<"Errore nella malloc()\n";
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        EVP_PKEY_free(my_DHpubkey);
        
        disconnect(sd);
    }

    //leggo la chiave pubblica del server 
    unsigned char* my_DH_pubkeyPEM = DH_pubkey(std::string("dh_myPUBKEY")+(*username)+".pem",my_DHprivkey,my_DHpubkey,len);
    if(!my_DH_pubkeyPEM){
        EVP_PKEY_free(my_DHprivkey);
        
        free(len);
        EVP_PKEY_free(my_DHpubkey);
        free(nonce_c);
        disconnect(sd);
    }
    uint32_t my_DHpubkeyLEN = *len;
    EVP_PKEY_free(my_DHpubkey);


    //invio la dimensione del file PEM al client
    *len = htonl(*len);
    if(!send_packet<uint32_t>(sd,len,sizeof(uint32_t))){
        EVP_PKEY_free(my_DHprivkey);
        free(len);
        free(my_DH_pubkeyPEM);
        free(nonce_c);
        
        disconnect(sd);
    }


    //invio il file PEM con la chiave pubblica del server al client
    if(!send_packet<unsigned char>(sd,my_DH_pubkeyPEM,my_DHpubkeyLEN)){
        EVP_PKEY_free(my_DHprivkey);
        free(my_DH_pubkeyPEM);
        free(len);
        free(nonce_c);
        
        disconnect(sd);
    }
    free(len);
    /**************************************************************************************/












    /****************************************************************************
    3) Ricevo la chiave pubblica del client. 
       Derivo la chiave di sessione Kab. 
    ******************************************************************************/

    //ricevo la lunghezza della chiave pubblica del client
    uint32_t* client_DH_pubkeyLEN = recv_packet<uint32_t>(sd,sizeof(uint32_t));
    if(!client_DH_pubkeyLEN){
        std::cout<<"Errore nella ricezione della dimensione del file PEM\n";
        EVP_PKEY_free(my_DHprivkey);
        free(my_DH_pubkeyPEM);
        
        free(nonce_c);
        disconnect(sd);
    }
    *client_DH_pubkeyLEN = ntohl(*client_DH_pubkeyLEN);
    ///////////////////
    //CHECK OVERFLOW//
    /////////////////

    //ricevo la chiave pubblica del client 
    unsigned char* client_DH_pubkeyPEM = recv_packet<unsigned char>(sd,*client_DH_pubkeyLEN);
    if(!client_DH_pubkeyPEM){
        std::cout<<"Chiave pubblica non ricevuta correttamente\n";
        EVP_PKEY_free(my_DHprivkey);
        free(my_DH_pubkeyPEM);
        free(client_DH_pubkeyLEN);
        free(nonce_c);
        
        disconnect(sd);
    }

    //genera dinamicamente il nome del file!
    EVP_PKEY* client_pubkey = DH_derive_pubkey(std::string("dh_")+(*username)+"pubkey.pem",client_DH_pubkeyPEM,*client_DH_pubkeyLEN);
    if(!client_pubkey){
        std::cout<<"Errore nella derivazione della chiave pubblica ricevuta dal client\n";
        EVP_PKEY_free(my_DHprivkey);
        free(my_DH_pubkeyPEM);
        free(client_DH_pubkeyLEN);
        free(client_DH_pubkeyPEM);
        free(nonce_c);
        
        disconnect(sd);
    }
    

    //derivo il segreto di sessione 
    size_t secret_len;
    unsigned char* secret = DH_derive_session_secret(my_DHprivkey,client_pubkey,&secret_len);
    if(!secret){
        std::cout<<"Errore nella derivazione del segreto di sessione\n";
        EVP_PKEY_free(my_DHprivkey);
        EVP_PKEY_free(client_pubkey);
        free(my_DH_pubkeyPEM);
        free(client_DH_pubkeyLEN);
        free(client_DH_pubkeyPEM);
        free(nonce_c);
        
        disconnect(sd);
    }

    EVP_PKEY_free(client_pubkey);
    EVP_PKEY_free(my_DHprivkey);

    
    //derivo la chiave di sessione Kab
    unsigned char* K_ab = session_key(EVP_sha256(),EVP_aes_128_gcm(),secret,secret_len,key_len);
    if(!K_ab){
        std::cout<<"Errore nel calcolo di K_ab\n";
        free(my_DH_pubkeyPEM);
        free(client_DH_pubkeyLEN);
        free(client_DH_pubkeyPEM);
        free(nonce_c);
        free(secret);
        
        disconnect(sd);
    }
    free(secret);
    /*****************************************************************************************************/













    /*********************************************************
     5) Il server: 
     - legge la sua chiave privata RSA 
     - firma digitalmente il messaggio (nonce_c + server_DHpubkey) e lo invio al client 
     - invio il certificato del server al client 
     - invio il nonce_s al client 
    **********************************************************/

    //leggo la chiave privata RSA del server per la firma digitale
    EVP_PKEY* my_privkeyRSA = read_RSA_privkey(std::string("ServerRSA_priv.pem"));
    if(!my_privkeyRSA){
        std::cout<<"Errore nella lettura della chiave privata RSA\n";
        free(my_DH_pubkeyPEM);
        free(client_DH_pubkeyLEN);
        free(client_DH_pubkeyPEM);
        free(nonce_c);
        free(K_ab);
        
        disconnect(sd);
    }

    //valuto la lunghezza della firma digitale
    uint32_t* sign_len = (uint32_t*)malloc(sizeof(uint32_t));
    if(!sign_len){
        EVP_PKEY_free(my_privkeyRSA);
        free(my_DH_pubkeyPEM);
        free(client_DH_pubkeyLEN);
        free(client_DH_pubkeyPEM);
        free(nonce_c);
        free(K_ab);
        
        disconnect(sd);
    }
    
    //preparo il messaggio da firmare (nonce_c + server_DHpubkey)
    unsigned char* signed_msg = (unsigned char*)malloc(NONCE_LEN + my_DHpubkeyLEN);
    if(!signed_msg){
        EVP_PKEY_free(my_privkeyRSA);
        free(my_DH_pubkeyPEM);
        free(client_DH_pubkeyLEN);
        free(client_DH_pubkeyPEM);
        free(nonce_c);
        free(K_ab);
        
        free(sign_len);
        disconnect(sd);
    }
    memcpy(signed_msg, nonce_c, NONCE_LEN);
    memcpy(signed_msg+NONCE_LEN, my_DH_pubkeyPEM, my_DHpubkeyLEN);
    free(my_DH_pubkeyPEM); 
    free(nonce_c);

    //genero la firma digitale. Firmo con la chiave privata del server RSA! 
    unsigned char* signature = compute_signature(EVP_sha256(), signed_msg, NONCE_LEN+my_DHpubkeyLEN, my_privkeyRSA,sign_len);
    if(!signature){
        EVP_PKEY_free(my_privkeyRSA);
        free(client_DH_pubkeyLEN);
        free(signed_msg);
        
        free(K_ab);
        free(sign_len);
        disconnect(sd);
    }
    free(signed_msg);
    EVP_PKEY_free(my_privkeyRSA);


    //invio la dimensione della firma
    *sign_len = htonl(*sign_len);
    if(!send_packet<uint32_t>(sd,sign_len,sizeof(uint32_t))){
        free(client_DH_pubkeyLEN);
        free(signature);
        
        free(K_ab);
        free(sign_len);
        disconnect(sd);
    }
    *sign_len = ntohl(*sign_len);

    //invio il messaggio firmato 
    if(!send_packet<unsigned char>(sd,signature,*sign_len)){
        free(client_DH_pubkeyLEN);
        
        free(signature);
        free(K_ab);
        free(sign_len);
        disconnect(sd);
    }
    free(sign_len);
    free(signature);


    //invio il certificato del server 
    if(!send_file(sd,std::string("Server_certificate.pem"))){
        free(client_DH_pubkeyLEN);
        
        free(K_ab);
        disconnect(sd);
    }
    

    //genero e invio il nonce_s
    unsigned char* nonce_s = (unsigned char*)malloc(NONCE_LEN);
    if(!nonce_s){
        free(client_DH_pubkeyLEN);
        free(K_ab);
        
        disconnect(sd);
    }
    nonce_s = nonce(nonce_s, NONCE_LEN);
    if(!send_packet<unsigned char>(sd,nonce_s,NONCE_LEN)){
        free(client_DH_pubkeyLEN);
        free(K_ab);
        free(nonce_s);
        
        disconnect(sd);
    }
    /******************************************************************************************/










    /*********************************************************
     5) Il server riceve e verifica la firma del client 
    **********************************************************/

    //ricevo la firma dal client
    uint32_t* client_signature_len = recv_packet<uint32_t>(sd,sizeof(uint32_t));
    if(!client_signature_len){
        free(client_DH_pubkeyLEN);
        free(K_ab);
        free(nonce_s);
        
        disconnect(sd);
    }
    *client_signature_len = ntohl(*client_signature_len);
    unsigned char* client_signature = recv_packet<unsigned char>(sd,*client_signature_len);
    if(!client_signature){
        free(client_DH_pubkeyLEN);
        free(K_ab);
        free(nonce_s);
        
        free(client_signature_len);
        disconnect(sd);
    }


    //creo il messaggio con cui controllare la firma
    signed_msg = (unsigned char*)malloc(NONCE_LEN + *client_DH_pubkeyLEN);
    if(!signed_msg){
        free(client_DH_pubkeyLEN);
        free(nonce_s);
        free(K_ab);
        
        free(client_signature);
        free(client_signature_len);
        disconnect(sd);
    }
    memcpy(signed_msg,nonce_s,NONCE_LEN);
    memcpy(signed_msg + NONCE_LEN, client_DH_pubkeyPEM, *client_DH_pubkeyLEN);
    free(nonce_s);

    //controllo la firma del client
    if( !verify_signature( EVP_sha256(),client_signature, *client_signature_len, read_RSA_pubkey(*username),signed_msg, NONCE_LEN + *client_DH_pubkeyLEN) ){
        std::cout<<"FIRMA NON VALIDA\n";
        
        free(K_ab);
        free(signed_msg);
        free(client_signature);
        free(client_signature_len);
        disconnect(sd);
    }
    free(client_signature_len);
    free(signed_msg);
    free(client_signature);


    //rimuovo le chiavi effimere
    if(remove((std::string("dh_myPUBKEY")+(*username)+".pem").c_str())){
        std::cout<<"Impossibile eliminare i file DH\n";
        
        free(K_ab);
        disconnect(sd);
    }
    if(remove((std::string("dh_")+(*username)+"pubkey.pem").c_str())){
        std::cout<<"Impossibile eliminare i file DH\n";
        
        free(K_ab);
        disconnect(sd);
    }
    return K_ab;
}

void list(unsigned char* key, int sd,uint64_t* counter,std::string* username){
    uint8_t id;
    std::string plaintext;
    struct dirent *dirent;
    DIR *dir;
    dir = opendir((*username + "/").c_str());
    if (dir == NULL) {
        id = 8; //ID di errore 
        plaintext = std::string("Cartella non trovata");
        plaintext.resize(SIZE_FILENAME);
        send_std_packet(plaintext,key,sd,counter,id,1);
        return;
    }
    char* buffer;
    while ((dirent = readdir(dir)) != NULL) {
        /////////////////////////////////////////////////
        ///// controllare vulnerabilita' di sprintf /////
        /////////////////////////////////////////////////
        sprintf(buffer, "%s\n", dirent->d_name);
        plaintext = plaintext + "└── " + buffer;
    }
    if(!plaintext.empty()) {
        plaintext.erase(0,10);
    }
    if(!plaintext.empty()) {
        plaintext.resize(plaintext.size()-13);
    }
    closedir(dir);
    free(dirent);
    // considerare la possibilita' che la dimensione della lista maggiore sia di 255 byte?
    send_std_packet(plaintext,key,sd,counter,0,1);
    return;
}

void upload(unsigned char* plaintext,unsigned char* key, int sd,uint64_t* counter,std::string* username, uint32_t num_packets){
    uint8_t id;
    std::string msg;
    uint64_t file_len;

    id = 0; //ID ack
    msg = std::string("");
    msg.resize(SIZE_FILENAME);

    *(plaintext + SIZE_FILENAME -1 ) = '\0';
    if(!check_string(std::string((char*)plaintext))){
        id = 8; //ID di errore 
        msg = std::string("Filename non valido");
        msg.resize(SIZE_FILENAME);
        file_len = 0;
    }
    send_std_packet(msg,key,sd,counter,id,num_packets);
    std::string filename = (*username + "/" + (char*)plaintext).c_str();
    if(!write_transfer_op(filename,num_packets,sd, key, counter)) {
        std::cout<<"Uh oh..."<<std::endl;
        return;
    }

    std::cout<<std::endl;
    std::cout<<"Upload completato!\n";
    std::cout<<"-------------------\n";

    //invio messaggio DONE
    filename = std::string("");
    filename.resize(SIZE_FILENAME);
    id = 7; //ID di done
    num_packets = 0;
    send_std_packet(filename, key,sd,counter,id,num_packets);
}

void download(unsigned char* plaintext,unsigned char* key, int sd,uint64_t* counter,std::string* username){

    uint8_t id;
    std::string msg;
    uint64_t file_len;
    uint32_t num_packets;

    *(plaintext + SIZE_FILENAME -1 ) = '\0';
    if(!check_string(std::string((char*)plaintext))){
        id = 8; //ID di errore 
        msg = std::string("Filename non valido");
        msg.resize(SIZE_FILENAME);
        file_len = 0;
        send_std_packet(msg,key,sd,counter,id,num_packets);
        return;
    }
    else {
        FILE* file = fopen((*username + "/" + (char*)plaintext).c_str(),"r");
        if(!file){
            id = 8; //ID di errore 
            msg = std::string("File non esistente");
            msg.resize(SIZE_FILENAME);
            file_len = 0;
        }
        else{
            fseek(file,0,SEEK_END);
            file_len = (ftell(file) > UINT32_MAX)? 0: ftell(file);
            rewind(file);
        
            if(!file_len){
                id = 8;
                msg = std::string("File troppo grande");
                msg.resize(SIZE_FILENAME);
            }
            else{
                id = 0; //ID ack
                msg = std::string("");
                msg.resize(SIZE_FILENAME);
            }
            fclose(file);
        }
        num_packets = how_many_fragments(file_len);
        send_std_packet(msg,key,sd,counter,id,num_packets);
        if(id != 0) return;
        std::string filename;
        filename = std::string((char*)plaintext);
        if(!read_transfer_op(*username, num_packets, file_len, filename, sd, key, counter)) {
            std::cout<<":("<<std::endl;
            return;
        }
        std::cout<<std::endl;
        unsigned char* request = recv_packet<unsigned char>(sd,REQ_LEN);
        if(!request){
            std::cout<<"Errore nella ricezione della richiesta\n";
            disconnect(sd);
        }

        //dovrei ricevere pacchetto richiesta DONE
        //parametri da leggere nel pacchetto di richiesta
        uint32_t num_packets;
        uint8_t id;
        unsigned char* req_payload = (unsigned char*)malloc(SIZE_FILENAME);
        if(!req_payload){
            std::cout<<"Errore nella malloc\n";
            free(request);
            return;
        }
        if(!read_request_param(request,counter,&num_packets,&id,req_payload,key)){
            std::cout<<"Impossibile leggere correttamente la richiesta\n";
            free(request);
            free(plaintext);
            return;
        }
        free(request);
        if(id != 7){
            //Implementa invio errore da client
            std::cout<<"Errore: il client non ha ricevuto il file\n";
            return;
        }
        std::cout<<"Download completato!\n";
        std::cout<<"-------------------\n";
        return;
    }
}

void rename(unsigned char* plaintext,unsigned char* key, int sd,uint64_t* counter,std::string* username){

}

void delete_file(unsigned char* plaintext,unsigned char* key, int sd,uint64_t* counter,std::string* username){

}

void logout(unsigned char* key, int sd,uint64_t* counter){

}

void wait_request(int sd, uint64_t* counter, unsigned char* key,std::string* username){
    while(true) {
        unsigned char* request = recv_packet<unsigned char>(sd,REQ_LEN);
        if(!request){
            std::cout<<"Errore nella ricezione della richiesta\n";
            disconnect(sd);
        }

        //parametri da leggere nel pacchetto di richiesta
        uint32_t num_packets;
        uint8_t id;
        unsigned char* plaintext = (unsigned char*)malloc(SIZE_FILENAME);
        if(!plaintext){
            std::cout<<"Errore nella malloc\n";
            free(request);
            return;
        }
        if(!read_request_param(request,counter,&num_packets,&id,plaintext,key)){
            std::cout<<"Impossibile leggere correttamente la richiesta\n";
            free(request);
            free(plaintext);
            return;
        }
        free(request);

        switch(id){
            case 1: list(key,sd,counter,username);
                break;
            case 2: upload(plaintext,key,sd,counter,username,num_packets); 
                break;
            case 3: download(plaintext,key,sd,counter,username); 
                break;
            case 4: rename(plaintext,key,sd,counter,username); 
                break;
            case 5: delete_file(plaintext,key,sd,counter,username); 
                break;
            case 6: logout(key,sd,counter); 
                break;
            default: 
                break;
        }
    }
}

// routine eseguita dal thread
void* manageConnection(void* s){

    std::string* username = new std::string();
    int sd = *((int*)s);
    unsigned int key_len;
 
    unsigned char* K_ab = handshake(sd,&key_len,username);
    while(true){
        uint64_t* counter = (uint64_t*)malloc(sizeof(uint64_t));
        if(!counter){
            free(K_ab);
            disconnect(sd);
        }
        *counter = 0;
        wait_request(sd,counter,K_ab,username);
    }

    disconnect(sd); 
}

int main(int n_args, char** args){
    int i;
    int porta; /*porta del server */
    int listener; /* socket listener TCP */
    int* client_sd;
    socklen_t len;
    struct sockaddr_in server, client;
    int ret; /*controllo errori */

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
    FD_SET(listener,&MASTER);

    max_fd = listener;
    while(1){
        READY = MASTER;
        select(max_fd+1, &READY, NULL, NULL, NULL);
        for(i = 0; i <= max_fd; i++){
            if(!FD_ISSET(i,&READY))
                continue;
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
