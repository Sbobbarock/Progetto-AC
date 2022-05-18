#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "../lib/header/DH.h"
#include "../lib/header/utility.h"
#include "../lib/header/certificate.h"
#include "../lib/header/signature.h"


/*Funzione che controlla la validita' di una stringa. 
  Si controlla che la stringa non e' vuota e che i caratteri che ne fanno parte siano consentiti */
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

/*Funzione che gestisce le azioni svolte lato client nel protocollo di handshake. 
  1) Il client invia al server la nonce e il suo id 
  2) Genero la chiave privata e pubblica del client con DH
  3) Ricevo la chiave pubblica del server e derivo la chiave di sessione Kab*/
void handshake(int sd){
    int ret;
    uint32_t* len;
    unsigned char* buffer;
    unsigned char* nonce_c;
    std::string username;

/*********************************************************************
    1) Invio al server la nonce ed una stringa che identifichi il client
    *********************************************************************/
    //genero il nonce(C)
    nonce_c = (unsigned char*)malloc(NONCE_LEN);
    if(!nonce_c){
        close(sd);
        exit(1);
    }
    nonce_c = nonce(nonce_c);
    do{
        std::cout<<"Inserisci nome utente: ";
        std::cin>>username;
    }while(!check_string(username) || username.length() > MAX_USERNAME);

    //standardizzo la lunghezza del nome utente
    username.resize(MAX_USERNAME);

    //invio nonce e nome utente
    if(!send_packet<const char>(sd,username.c_str(),MAX_USERNAME)){
        std::cout<<"Errore nell'invio del nome utente\n";
        free(nonce_c);
        close(sd);
        exit(1);
    }
    if(!send_packet<unsigned char>(sd,nonce_c, NONCE_LEN)){
        std::cout<<"Errore nell'invio del nonce\n";
        free(nonce_c);
        close(sd);
        exit(1);
    }
    
    bool* login_status =recv_packet<bool>(sd,sizeof(bool));
    if(!login_status || *login_status == false){
        std::cout<<"Nome utente non registrato\n";
        free(nonce_c);
        close(sd);
        exit(1);
    }
    std::cout<<"BENVENUTO "<<username<<std::endl;
    /*************************************************************************************/



    /***********************************************
    2) Ricavo chiave privata e pubblica del client. 
      - inizializzo DH param e chiave privata del client 
      - invio la chiave pubblica del client al server 
    *************************************************/
    free(login_status);
    //inizializzazione parametri DH e chiave privata
    EVP_PKEY* my_DHprivkey = DH_privkey();
    EVP_PKEY* my_DHpubkey = EVP_PKEY_new();
    //ricavo e leggo file PEM con la mia chiave pubblica
    //genera dinamicamente il nome del file!
    len = (uint32_t*)malloc(sizeof(uint32_t));
    if(!len){
        std::cout<<"Errore nella malloc()\n";
        EVP_PKEY_free(my_DHprivkey);
        EVP_PKEY_free(my_DHpubkey);
        free(nonce_c);
        close(sd);
        exit(1);
    }
    unsigned char* my_DH_pubkeyPEM = DH_pubkey(std::string("dh_myPUBKEY.pem"),my_DHprivkey,my_DHpubkey,len);
    if(!my_DH_pubkeyPEM){
        std::cout<<"Errore nella generazione della chiave pubblica\n";
        EVP_PKEY_free(my_DHprivkey);
        EVP_PKEY_free(my_DHpubkey);
        free(nonce_c);
        free(len);
        close(sd);
        exit(1);
    } 
    EVP_PKEY_free(my_DHpubkey);
    uint32_t my_DHpubkeyLEN = *len;

    //invio la dimensione del file PEM al server
    *len = htonl(*len);
    if(!send_packet<uint32_t>(sd,len,sizeof(uint32_t))){
        std::cout<<"Errore nell'invio della dimensione del file PEM\n";
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        free(my_DH_pubkeyPEM);
        free(len);
        close(sd);
        exit(1);
    }

    //invio il file PEM con la chiave pubblica al server
    if(!send_packet<unsigned char>(sd,my_DH_pubkeyPEM,my_DHpubkeyLEN)){
        std::cout<<"Errore nell'invio del file PEM con la chiave pubblica\n";
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        free(my_DH_pubkeyPEM);
        free(len);
        close(sd);
        exit(1);
    }
    free(len);

    /*************************************************************************************/



    /*********************************************************
     3) Leggo la chiave pubblica del server e determino Kab
     *********************************************************/
    //ricevo la chiave pubblica del server
    uint32_t* server_DH_pubkeyLEN = recv_packet<uint32_t>(sd,sizeof(uint32_t));
    if(!server_DH_pubkeyLEN){
        std::cout<<"Errore nella ricezione della dimensione del file PEM\n";
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        free(my_DH_pubkeyPEM);
        close(sd);
        exit(1);
    }
    *server_DH_pubkeyLEN = ntohl(*server_DH_pubkeyLEN);
    ///////////////////
    //CHECK OVERFLOW//
    /////////////////
    unsigned char* server_DH_pubkeyPEM = recv_packet<unsigned char>(sd,*server_DH_pubkeyLEN);
    if(!server_DH_pubkeyPEM){
        std::cout<<"Chiave pubblica non ricevuta correttamente\n";
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        close(sd);
        exit(1);
    }
    
    EVP_PKEY* server_pubkey = DH_derive_pubkey(std::string("dh_serverpubkey.pem"),server_DH_pubkeyPEM,*server_DH_pubkeyLEN);
    if(!server_pubkey){
        std::cout<<"Errore nella derivazione della chiave pubblica ricevuta dal server\n";
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        close(sd);
        exit(1);
    }
    
    size_t secret_len;
    unsigned char* secret = DH_derive_session_secret(my_DHprivkey,server_pubkey,&secret_len);
    if(!secret){
        std::cout<<"Errore nella derivazione del segreto di sessione\n";
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        EVP_PKEY_free(server_pubkey);
        close(sd);
        exit(1);
    }
    EVP_PKEY_free(server_pubkey);
    EVP_PKEY_free(my_DHprivkey);

    unsigned int key_len;
    unsigned char* K_ab = session_key(EVP_sha256(),EVP_aes_128_gcm(),secret,secret_len,&key_len);
    if(!K_ab){
        std::cout<<"Errore nel calcolo di K_ab\n";
        free(nonce_c);
        free(secret);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        close(sd);
        exit(1);
    }
    free(secret);
    
    //ricevo la dimensione della firma del server e la firma
    uint32_t* sign_len = recv_packet<uint32_t>(sd,sizeof(uint32_t));
    if(!sign_len){
        free(nonce_c);
        free(K_ab);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        close(sd);
        exit(1);
    }
    *sign_len = ntohl(*sign_len);
    unsigned char* server_signature = recv_packet<unsigned char>(sd,*sign_len);
    if(!server_signature){
        free(nonce_c);
        free(K_ab);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        free(sign_len);
        close(sd);
        exit(1);
    }

    //ricevo il certificato del server
    uint32_t* cert_len = recv_packet<uint32_t>(sd,sizeof(uint32_t));
    if(!cert_len){
        free(nonce_c);
        free(K_ab);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        free(sign_len);
        free(server_signature);
        close(sd);
        exit(1);
    }
    *cert_len = ntohl(*cert_len);
    unsigned char* server_cert_msg = recv_packet<unsigned char>(sd,*cert_len);
    if(!server_cert_msg){
        free(nonce_c);
        free(K_ab);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        free(sign_len);
        free(cert_len);
        free(server_signature);
        close(sd);
        exit(1);
    }
    X509* server_certificate = read_certificate(std::string("Server_cert.pem"), server_cert_msg,*cert_len);
    if(!server_certificate){
        free(nonce_c);
        free(K_ab);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        free(sign_len);
        free(cert_len);
        free(server_cert_msg);
        free(server_signature);
        close(sd);
        exit(1);
    }
    free(server_cert_msg);
    free(cert_len);
    //costruisco lo store dei certificati e verifico il certificato
    X509_STORE* store = build_store(std::string("CA_crl.pem"),std::string("CA_root.pem"));
    if(!store){
        free(nonce_c);
        X509_free(server_certificate);
        free(K_ab);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        free(sign_len);
        free(server_signature);
        close(sd);
        exit(1);
    }
    EVP_PKEY* server_RSApubkey = validate_certificate(store,server_certificate);
    if(!server_RSApubkey){
        std::cout<<"Certificato non corretto\n";
        free(nonce_c);
        X509_free(server_certificate);
        free(K_ab);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        free(sign_len);
        free(server_signature);
        X509_STORE_free(store);
        close(sd);
        exit(1);

    }
    X509_free(server_certificate);
    X509_STORE_free(store);

    //preparo il msg per verificare la firma
    unsigned char* signed_msg = (unsigned char*)malloc(NONCE_LEN + * server_DH_pubkeyLEN);
    if(!signed_msg){
        EVP_PKEY_free(server_RSApubkey);
        free(nonce_c);
        free(K_ab);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        free(sign_len);
        free(server_signature);
        close(sd);
        exit(1);
    }
    memcpy(signed_msg,nonce_c,NONCE_LEN);
    memcpy(signed_msg + NONCE_LEN, server_DH_pubkeyPEM, *server_DH_pubkeyLEN);
    uint32_t signed_msg_len = *server_DH_pubkeyLEN + NONCE_LEN;
    free(server_DH_pubkeyLEN);
    free(server_DH_pubkeyPEM);
    free(nonce_c);

    if(!verify_signature(EVP_sha256(),server_signature, *sign_len, server_RSApubkey,signed_msg, signed_msg_len)){
        std::cout<<"FIRMA NON VALIDA\n";
        EVP_PKEY_free(server_RSApubkey);
        free(K_ab);
        free(my_DH_pubkeyPEM);
        free(sign_len);
        free(signed_msg);
        free(server_signature);
        close(sd);
        exit(1);
    }
    EVP_PKEY_free(server_RSApubkey);
    free(server_signature);
    //ricevo il nonce_s
    unsigned char* nonce_s = recv_packet<unsigned char>(sd,NONCE_LEN);
    if(!nonce_s){
        free(K_ab);
        free(my_DH_pubkeyPEM);
        free(sign_len);
        free(signed_msg);
        close(sd);
        exit(1);
    }

    //genero il messaggio da firmare (nonce_s + my_DHpubkey)
    free(signed_msg);
    signed_msg = (unsigned char*)malloc(NONCE_LEN + my_DHpubkeyLEN);
    if(!signed_msg){
        free(K_ab);
        free(my_DH_pubkeyPEM);
        free(sign_len);
        free(nonce_s);
        close(sd);
        exit(1);
    }
    memcpy(signed_msg,nonce_s,NONCE_LEN);
    memcpy(signed_msg + NONCE_LEN, my_DH_pubkeyPEM, my_DHpubkeyLEN);
    *sign_len = NONCE_LEN + my_DHpubkeyLEN;
    free(nonce_s);
    free(my_DH_pubkeyPEM);
    //leggo la chiave privata RSA
    EVP_PKEY* my_privkeyRSA = read_RSA_privkey(std::string("rsa_priv_client1.pem"));
    if(!my_privkeyRSA){
        free(K_ab);
        free(sign_len);
        free(signed_msg);
        close(sd);
        exit(1);
    }
    //firmo nonce_s e my_DHpubkey
    unsigned char* client_signature = compute_signature(EVP_sha256(), signed_msg, NONCE_LEN+my_DHpubkeyLEN, my_privkeyRSA,sign_len);
    if(!client_signature){
        EVP_PKEY_free(my_privkeyRSA);
        free(K_ab);
        free(sign_len);
        free(signed_msg);
        close(sd);
        exit(1);
    }
    EVP_PKEY_free(my_privkeyRSA);
    free(signed_msg);
    *sign_len = htonl(*sign_len);
    if(!send_packet<uint32_t>(sd,sign_len,sizeof(uint32_t))){
        free(K_ab);
        free(sign_len);
        free(client_signature);
        close(sd);
        exit(1);
    }
    *sign_len = ntohl(*sign_len);
    if(!send_packet<unsigned char>(sd,client_signature, *sign_len)){
        free(K_ab);
        free(sign_len);
        free(client_signature);
        close(sd);
        exit(1);
    }
    free(client_signature);
    free(sign_len);

    if(remove((std::string("dh_serverpubkey.pem")).c_str())){
        free(K_ab);
        close(sd);
        exit(1);
    }
    if(remove((std::string("dh_myPUBKEY.pem")).c_str())){
        free(K_ab);
        close(sd);
        exit(1);
    }
    if(remove((std::string("Server_cert.pem")).c_str())){
        free(K_ab);
        close(sd);
        exit(1);
    }

    std::cout<<"Connessione con il server completata\n";
    exit(0);

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
