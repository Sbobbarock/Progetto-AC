#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "../lib/header/DH.h"
#include "../lib/header/utility.h"
#include "../lib/header/certificate.h"
#include "../lib/header/signature.h"
#include "../lib/header/cipher.h"


/*Funzione che gestisce le azioni svolte lato client nel protocollo di handshake. 
  1) Il client invia al server la nonce e il suo id 
  2) Il client genera la sua chiave privata e pubblica di DH
  3) Il client riceve la chiave pubblica del server di DH 
  4) Il client deriva la chiave di sessione Kab 
  5) Il client verifica il messaggio firmato dal server che contiene la chiave pubblica del server 
  6) Il client invia al server il messaggio firmato (nonce_s + client_DHpubkey) 
  7) Sessione stabilita
*/
unsigned char* handshake(int sd){
    int ret;
    uint32_t* len;
    unsigned char* buffer;
    unsigned char* nonce_c;
    std::string* username = new std::string();

    /*********************************************************************
    1) Invio al server la nonce ed una stringa che identifichi il client
    *********************************************************************/
    //genero il nonce(C)
    nonce_c = (unsigned char*)malloc(NONCE_LEN);
    if(!nonce_c){
        std::cout<<"Errore nell'allocazione del buffer nonce_c\n";
        delete username;
        close(sd);
        exit(1);
    }
    nonce_c = nonce(nonce_c, NONCE_LEN);

    //chiedo username all'utente
    do{
        std::cout<<"Inserisci nome utente: ";
        std::cin>>*username;
    }while(!check_string(*username) || (*username).length() > MAX_USERNAME);

    //standardizzo la lunghezza del nome utente
    (*username).resize(MAX_USERNAME);

    //invio nonce e nome utente
    if(!send_packet<const char>(sd,(*username).c_str(),MAX_USERNAME)){
        std::cout<<"Errore nell'invio del nome utente al server\n";
        free(nonce_c);
        delete username;
        close(sd);
        exit(1);
    }
    if(!send_packet<unsigned char>(sd,nonce_c, NONCE_LEN)){
        std::cout<<"Errore nell'invio del nonce al server\n";
        free(nonce_c);
        delete username;
        close(sd);
        exit(1);
    }
    
    //controllo che lo username del client sia presente nella lista degli utenti registrati sul server
    bool* login_status = recv_packet<bool>(sd,sizeof(bool));
    if(!login_status || *login_status == false){
        std::cout<<"Nome utente non registrato\n";
        free(nonce_c);
        close(sd);
        delete username;
        exit(1);
    }
    std::cout<<"Welcome "<<*username<<std::endl;
    free(login_status);
    /*************************************************************************************/














    /***********************************************
    2) Ricavo la coppia di chiavi (privata, pubblica) di DH
       - calcolo la chiave privata effiemera di DH 
       - ricavo la chiave pubblica di DH 
       - invio la chiave pubbllica del client al server in un file PEM 
    *************************************************/

    //inizializzazione parametri DH e chiave privata
    EVP_PKEY* my_DHprivkey = DH_privkey();
    EVP_PKEY* my_DHpubkey = EVP_PKEY_new();

    //genera dinamicamente il nome del file!
    len = (uint32_t*)malloc(sizeof(uint32_t));
    if(!len){
        std::cout<<"Errore nell'allocazione di len\n";
        EVP_PKEY_free(my_DHprivkey);
        EVP_PKEY_free(my_DHpubkey);
        free(nonce_c);
        delete username;
        close(sd);
        exit(1);
    }

    //ricavo e leggo la lunghezza del file PEM con la mia chiave pubblica
    unsigned char* my_DH_pubkeyPEM = DH_pubkey(std::string("dh_myPUBKEY.pem"),my_DHprivkey,my_DHpubkey,len);
    if(!my_DH_pubkeyPEM){
        std::cout<<"Errore nella generazione della chiave pubblica\n";
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        EVP_PKEY_free(my_DHprivkey);
        EVP_PKEY_free(my_DHpubkey);
        free(nonce_c);
        free(len);
        close(sd);
        delete username;
        exit(1);
    } 
    EVP_PKEY_free(my_DHpubkey);
    uint32_t my_DHpubkeyLEN = *len;

    //invio la dimensione del file PEM al server
    *len = htonl(*len);
    if(!send_packet<uint32_t>(sd,len,sizeof(uint32_t))){
        std::cout<<"Errore nell'invio della dimensione del file PEM\n";
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        free(my_DH_pubkeyPEM);
        free(len);
        close(sd);
        delete username;
        exit(1);
    }

    //invio il file PEM con la chiave pubblica al server
    if(!send_packet<unsigned char>(sd,my_DH_pubkeyPEM,my_DHpubkeyLEN)){
        std::cout<<"Errore nell'invio del file PEM con la chiave pubblica\n";
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        free(my_DH_pubkeyPEM);
        free(len);
        close(sd);
        delete username;
        exit(1);
    }
    free(len);
    /*************************************************************************************/











    /*********************************************************
     3) Leggo la chiave pubblica del server
     *********************************************************/

    //ricevo la lunghezza della chiave pubblica del server
    uint32_t* server_DH_pubkeyLEN = recv_packet<uint32_t>(sd,sizeof(uint32_t));
    if(!server_DH_pubkeyLEN){
        std::cout<<"Errore nella ricezione della dimensione del file PEM\n";
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        free(my_DH_pubkeyPEM);
        close(sd);
        delete username;
        exit(1);
    }
    *server_DH_pubkeyLEN = ntohl(*server_DH_pubkeyLEN);

    //ricevo la chiave pubblica del server in un file PEM
    unsigned char* server_DH_pubkeyPEM = recv_packet<unsigned char>(sd,*server_DH_pubkeyLEN);
    if(!server_DH_pubkeyPEM){
        std::cout<<"Chiave pubblica non ricevuta correttamente\n";
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        close(sd);
        delete username;
        exit(1);
    }
    

    //Derivo la chiave pubblica del server
    EVP_PKEY* server_pubkey = DH_derive_pubkey(std::string("dh_serverpubkey.pem"),server_DH_pubkeyPEM,*server_DH_pubkeyLEN);
    if(!server_pubkey){
        std::cout<<"Errore nella derivazione della chiave pubblica ricevuta dal server\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        close(sd);
        delete username;
        exit(1);
    }
    /*************************************************************************************************************************/











    /*********************************************************
    4) Derivo la chiave di sessione Kab
    ***********************************************************/

    //derivo il segreto di sessione del protocollo DH 
    size_t secret_len;
    unsigned char* secret = DH_derive_session_secret(my_DHprivkey,server_pubkey,&secret_len);
    if(!secret){
        std::cout<<"Errore nella derivazione del segreto di sessione\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        EVP_PKEY_free(my_DHprivkey);
        free(nonce_c);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        EVP_PKEY_free(server_pubkey);
        close(sd);
        delete username;
        exit(1);
    }
    EVP_PKEY_free(server_pubkey);
    EVP_PKEY_free(my_DHprivkey);

    //trovo chiave di sessione Kab 
    unsigned int key_len;
    unsigned char* K_ab = session_key(EVP_sha256(),EVP_aes_128_gcm(),secret,secret_len,&key_len);
    if(!K_ab){
        std::cout<<"Errore nel calcolo di K_ab\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        free(nonce_c);
        free(secret);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        close(sd);
        delete username;
        exit(1);
    }
    free(secret);
    /*********************************************************************************************************/














    /*********************************************************
     5) Il client riceve: 
     - firma del server 
     - certificato del server di cui certifico la validita' 
     - chiave pubblica del server RSA
     - verifico la validita' della firma del server
    **********************************************************/

    //ricevo la dimensione della firma del server
    uint32_t* sign_len = recv_packet<uint32_t>(sd,sizeof(uint32_t));
    if(!sign_len){
        std::cout<<"Errore nella ricezione di sign_len\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        free(nonce_c);
        free(K_ab);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        close(sd);
        delete username;
        exit(1);
    }
    *sign_len = ntohl(*sign_len);
    
    //ricevo la firma del server
    unsigned char* server_signature = recv_packet<unsigned char>(sd,*sign_len);
    if(!server_signature){
        std::cout<<"Errore nella ricezione della firma digitale del server\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        free(nonce_c);
        free(K_ab);
        free(server_DH_pubkeyPEM);
        free(server_DH_pubkeyLEN);
        free(my_DH_pubkeyPEM);
        free(sign_len);
        close(sd);
        delete username;
        exit(1);
    }


    //ricevo la dimensione del certificato del server
    uint32_t* cert_len = recv_packet<uint32_t>(sd,sizeof(uint32_t));
    if(!cert_len){
        std::cout<<"Errore nella ricezione del certificato del server\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        delete username;
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


    //ricevo il certificato del server
    unsigned char* server_cert_msg = recv_packet<unsigned char>(sd,*cert_len);
    if(!server_cert_msg){
        std::cout<<"Errore nella ricezione del certificato del server\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        delete username;
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

    //leggo il certificato del server
    X509* server_certificate = read_certificate(std::string("Server_cert.pem"), server_cert_msg,*cert_len);
    if(!server_certificate){
        std::cout<<"Errore nella lettura del certificato del server\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        remove((std::string("Server_cert.pem")).c_str());
        delete username;
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
        std::cout<<"Errore nella creazione dello STORE\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        remove((std::string("Server_cert.pem")).c_str());
        delete username;
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


    //leggo la chiave pubblica del server
    EVP_PKEY* server_RSApubkey = validate_certificate(store,server_certificate);
    if(!server_RSApubkey){
        std::cout<<"Certificato non corretto\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        remove((std::string("Server_cert.pem")).c_str());
        free(nonce_c);
        delete username;
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
        std::cout<<"Errore nell'allocazione di memoria per la firma digitale\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        remove((std::string("Server_cert.pem")).c_str());
        delete username;
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

    //verifico la firma del server. Per verificarla utilizzo la chiave pubblica del server RSA!
    if(!verify_signature(EVP_sha256(),server_signature, *sign_len, server_RSApubkey,signed_msg, signed_msg_len)){
        std::cout<<"FIRMA NON VALIDA\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        remove((std::string("Server_cert.pem")).c_str());
        delete username;
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
    /******************************************************************************************************************************/












    /*********************************************************
     5) Il client: 
     - riceve il nonce_s del server 
     - invia al server il messaggio firmato (nonce_s + client_DHpubkey) 
    **********************************************************/

    //ricevo il nonce_s
    unsigned char* nonce_s = recv_packet<unsigned char>(sd,NONCE_LEN);
    if(!nonce_s){
        std::cout<<"Errore nella ricezione di nonce_s\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        remove((std::string("Server_cert.pem")).c_str());
        delete username;
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
        std::cout<<"Errore nell'allocazione del messaggio firmato\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        remove((std::string("Server_cert.pem")).c_str());
        delete username;
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


    //leggo la chiave privata RSA del client 
    EVP_PKEY* my_privkeyRSA = read_RSA_privkey(std::string("rsa_priv_client.pem"));
    if(!my_privkeyRSA){
        std::cout<<"Errore nella lettura della chiave RSA privata\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        remove((std::string("Server_cert.pem")).c_str());
        delete username;
        free(K_ab);
        free(sign_len);
        free(signed_msg);
        close(sd);
        exit(1);
    }


    //firmo nonce_s e my_DHpubkey
    unsigned char* client_signature = compute_signature(EVP_sha256(), signed_msg, NONCE_LEN+my_DHpubkeyLEN, my_privkeyRSA,sign_len);
    if(!client_signature){
        std::cout<<"Errore nella firma digitale\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        remove((std::string("Server_cert.pem")).c_str());
        delete username;
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
        std::cout<<"Errore di invio del pacchetto\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        remove((std::string("Server_cert.pem")).c_str());
        delete username;
        free(K_ab);
        free(sign_len);
        free(client_signature);
        close(sd);
        exit(1);
    }
    *sign_len = ntohl(*sign_len);
    if(!send_packet<unsigned char>(sd,client_signature, *sign_len)){
        std::cout<<"Errore di invio del pacchetto\n";
        remove((std::string("dh_serverpubkey.pem")).c_str());
        remove((std::string("dh_myPUBKEY.pem")).c_str());
        remove((std::string("Server_cert.pem")).c_str());
        delete username;
        free(K_ab);
        free(sign_len);
        free(client_signature);
        close(sd);
        exit(1);
    }
    free(client_signature);
    free(sign_len);


    //elimino le chiavi effimere che non verranno piu' utilizzate durante lo scambio di messaggi tra client e server
    if(remove((std::string("dh_serverpubkey.pem")).c_str())){
        std::cout<<"Impossibile eliminare il file effimero\n";
        delete username;
        free(K_ab);
        close(sd);
        exit(1);
    }
    if(remove((std::string("dh_myPUBKEY.pem")).c_str())){
        std::cout<<"Impossibile eliminare il file effimero\n";
        delete username;
        free(K_ab);
        close(sd);
        exit(1);
    }
    if(remove((std::string("Server_cert.pem")).c_str())){
        std::cout<<"Impossibile eliminare il file effimero\n";
        delete username;
        free(K_ab);
        close(sd);
        exit(1);
    }

    if(!recv_packet<unsigned char>(sd, REQ_LEN)) {
        std::cout<<"Errore di connessione con il server\n";
        delete username;
        free(K_ab);
        close(sd);
        exit(1);
    }

    std::cout<<"Connessione con il server completata\n";
    delete username;
    return K_ab;
    /*********************************************************
    7) la sessione con il server e' stata stabilita ed e' autentica e verificata! 
    ***********************************************************/ 
}

/*Funzione che da la possibilità all'utente di scegliere tra due opzioni. Ritorna:  
  - Y=2 in caso si scelga si 
  - N=1 
  - (ERR = 0)
*/
uint32_t select_yesno() {
    std::string buffer;

    //prendo in input la scelta dell'utente 
    std::getline(std::cin, buffer);
    std::cin>>buffer;
    static char ok_chars[] = "YNyn";

    //controllo che i caratteri inseriti siano validi
    if(buffer.find_first_not_of(ok_chars) != std::string::npos){
        std::cout<<"Input non valido\n";
        return 0;
    }
    else if(buffer == "N" || buffer == "n") {
        return 1;
    }
    else if(buffer == "Y" || buffer == "y") {
        return 2;
    } 
    else {
        std::cout<<"Input non valido\n";
        return 0;
    }
}


/*Funzione che controlla che chiede l'ID dell'operazione all'utente e che ne controlla la validità*/
uint32_t select_operation() {
    std::cout<<"-------------------\n";
    std::cout<<"Operazioni disponibili:\n";
    std::cout<<"[1]: List\n";
    std::cout<<"[2]: Upload\n";
    std::cout<<"[3]: Download\n";
    std::cout<<"[4]: Rename\n";
    std::cout<<"[5]: Delete\n";
    std::cout<<"[6]: Logout\n";
    std::cout<<"-------------------\n";
    std::string buffer;
    std::cout<<"Seleziona l'operazione desiderata: ";

    //prendo in input il numero 
    std::getline(std::cin, buffer);
    std::cin>>buffer;
    static char ok_chars[] = "123456";

    //controllo che il numero in input sia compreso tra 1 e 6 
    if(buffer.find_first_not_of(ok_chars) != std::string::npos){
        std::cout<<"Operazione non valida\n";
        return 0;
    }
    uint32_t operation_id = std::stoi(buffer);
    if(operation_id < 1 || operation_id > 6) {
        std::cout<<"Operazione non valida\n";
        return 0;
    }
    return operation_id;
}


/*Funzione che gestisce l'operazione di list*/
void list(int sd, unsigned char* key, uint64_t* counter){
    uint8_t id = 1;
    uint32_t num_packets = 0;
    std::string msg = "";
    msg.resize(SIZE_FILENAME);

    //creo una richiesta standard di list 
    if(!send_std_packet(msg, key,sd,counter,id,num_packets)){
        std::cout<<"L'operazione non è terminata con successo\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }

    //ricevo la risposta dal server 
    unsigned char* response = recv_packet<unsigned char>(sd,REQ_LEN);
    if(!response){
        std::cout<<"Errore nella ricezione della risposta dal server\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }
    unsigned char* plaintext = (unsigned char*)malloc(SIZE_FILENAME);
    if(!plaintext){
        std::cout<<"Errore nell'allocazione di memoria per il plaintext\n";
        free(response);
        return;
    }
    
    //leggo i parametri della risposta del server 
    if(!read_request_param(response,counter,&num_packets,&id,plaintext,key)){
        std::cout<<"Impossibile leggere correttamente la richiesta\n";
        free(response);
        free(plaintext);
        return;
    }
    plaintext[SIZE_FILENAME - 1] = '\0';
    free(response);

    //controllo che ID ricevuto non sia un errore 
    if(id == 8){ //ricevuto errore
        std::cout<<"Errore: "<<(char*)plaintext<<std::endl;
        return;
    }
    else if(id != 0){
        std::cout<<"Errore: pacchetto non riconosciuto"<<std::endl;
        return;
    }
    free(plaintext);
    std::string list;
    uint32_t* plaintext_len = (uint32_t*)malloc(sizeof(uint32_t));

    //ricevo la lista dei file presenti sul server sottoforma di pacchetto data
    for(uint32_t i = 0; i < num_packets; i++){
        unsigned char* plaintext = receive_data_packet(sd,counter,key,plaintext_len);
        if(!plaintext){
            free(plaintext);
            free(plaintext_len);
            #pragma optimize("", off)
            memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
            #pragma optimize("", on)
            free(key);
            free(counter);
            close(sd);
            exit(1);
        }
        plaintext[*plaintext_len - 1] = '\0';
        
        list = list.append((char*)plaintext);
        free(plaintext);
    }
    free(plaintext_len);
    std::cout<<"-------------------\n";
    std::cout<<list;

    //invio messaggio DONE
    list = std::string("");
    list.resize(SIZE_FILENAME);
    id = 7; //ID di done
    num_packets = 0;

    //invio un pacchetto standard di done
    if(!send_std_packet(list, key,sd,counter,id,num_packets)){
        std::cout<<"Errore nell'invio del pacchetto DONE\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }
    return;
}


/*Funzione che gestisce l'operazione di upload*/
void upload(int sd, unsigned char* key, uint64_t* counter){

    //chiedo all'utente il nome del file su cui desidera fare upload 
    std::cout<<"Inserisci il nome del file da caricare: ";
    std::string filename;
    std::cin>>filename;


    //ne controllo la validità
    if(!check_string(filename))
        return;

    uint8_t id;
    std::string msg;
    uint64_t file_len;
    uint32_t num_packets;

    //controllo che il file selezionato esista 
    FILE* file = fopen(filename.c_str(),"r");
    if(!file){
        std::cout<<"File non esistente"<<std::endl;
        return;
    }
    else{
        fseek(file,0,SEEK_END);

        //estrapolo la lunghezza del file 
        file_len = (ftell(file) > UINT32_MAX)? 0: ftell(file);

        if(!file_len && ftell(file)){
            std::cout<<"File troppo grande o vuoto"<<std::endl;
            return;
        }
        else{
            msg = std::string("");
            msg.resize(SIZE_FILENAME);
        }
        fclose(file);
    }
    filename.resize(SIZE_FILENAME);

    id = 2;
    num_packets = 0;
    num_packets = how_many_fragments(file_len);

    //invio un pacchetto di richiesta standard di upload
    if(!send_std_packet(filename, key,sd,counter,id,num_packets)){
        std::cout<<"Errore nell'invio del pacchetto standard\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }

    //ricevo la risposta dal server 
    unsigned char* response = recv_packet<unsigned char>(sd,REQ_LEN);
    if(!response){
        std::cout<<"Errore nella ricezione della risposta dal server\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }
    unsigned char* plaintext = (unsigned char*)malloc(SIZE_FILENAME);
    if(!plaintext){
        std::cout<<"Errore nell'allocazione di memoria per il plaintext\n";
        free(response);
        return;
    }
    
    //leggo i parametri della risposta del server 
    if(!read_request_param(response,counter,&num_packets,&id,plaintext,key)){
        std::cout<<"Impossibile leggere correttamente la richiesta\n";
        free(response);
        free(plaintext);
        return;
    }
    plaintext[SIZE_FILENAME - 1] = '\0';
    free(response);

    //controllo che l'ID ricevuto sia di ACK 
    if(id == 8){ //ricevuto errore
        std::cout<<"Errore: "<<(char*)plaintext<<std::endl;
        return;
    }
    else if(id != 0){
        std::cout<<"Errore: pacchetto non riconosciuto"<<std::endl;
        return;
    }
    free(plaintext);

    //effetto l'operazione di upload
    std::cout<<"Uploading "<<'"'<<filename<<'"'<<"..."<<std::endl;
    if(!read_transfer_op("",num_packets,file_len, filename,sd, key, counter)) {
        std::cout<<"Uh oh..."<<std::endl;
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }
    
    //attendo al ricezione del pacchetto done
    unsigned char* request = wait_for_done(sd);
    if(!request){
        std::cout<<"Upload failed"<<std::endl;
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }
    
    unsigned char* req_payload = (unsigned char*)malloc(SIZE_FILENAME);
    if(!req_payload){
        std::cout<<"Errore nell'allocazione di memoria\n";
        free(request);
        return;
    }

    //leggo i parametri della risposta ricevuta dal server 
    if(!read_request_param(request,counter,&num_packets,&id,req_payload,key)){
        std::cout<<"Impossibile leggere correttamente la richiesta\n";
        free(request);
        free(req_payload);
        return;
    }
    free(request);
    free(req_payload);
    //controllo che l'ID ricevuto non corrisponda ad un errore
    if(id != 7){
        //Implementa invio errore da client
        std::cout<<"Errore: il server non ha ricevuto il file\n";
        return;
    }
    std::cout<<std::endl;
    std::cout<<"Upload completato\n";
    return;
}


/*Funzione che gestisce l'operazione di download*/
void download(int sd, unsigned char* key, uint64_t* counter){

    //chiedo all'utente il file che desidera scaricare 
    std::cout<<"Inserisci il nome del file da scaricare: ";
    std::string filename;
    std::cin>>filename;


    //controllo la validità del filename
    if(!check_string(filename))
        return;

    filename.resize(SIZE_FILENAME);


    //invio una richiesta standard di download
    uint8_t id = 3;
    uint32_t num_packets = 0;
    if(!send_std_packet(filename, key,sd,counter,id,num_packets)){
        std::cout<<"Errore nell'invio del pacchetto standard\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }

    //ricevo la risposta del server 
    unsigned char* response = recv_packet<unsigned char>(sd,REQ_LEN);
    if(!response){
        std::cout<<"Errore nella ricezione della risposta dal server\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }
    unsigned char* plaintext = (unsigned char*)malloc(SIZE_FILENAME);
    if(!plaintext){
        std::cout<<"Errore nell'allocazione di memoria\n";
        free(response);
        return;
    }

    //leggo i parametri della risposta del server
    if(!read_request_param(response,counter,&num_packets,&id,plaintext,key)){
        std::cout<<"Impossibile leggere correttamente la richiesta\n";
        free(response);
        free(plaintext);
        return;
    }
    plaintext[SIZE_FILENAME - 1] = '\0';
    free(response);

    //controllo che ID ricevuto sia di ACK
    if(id == 8){ //ricevuto errore
        std::cout<<"Errore: "<<(char*)plaintext<<std::endl;
        return;
    }
    else if(id != 0){
        std::cout<<"Errore: pacchetto non riconosciuto"<<std::endl;
        return;
    }
    free(plaintext);

    //ricevo i pacchetti dal server
    std::cout<<"Downloading "<<'"'<<filename<<'"'<<"..."<<std::endl;
    if(!write_transfer_op(filename,num_packets,sd, key, counter)) {
        std::cout<<"Uh oh..."<<std::endl;
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }

    std::cout<<std::endl;
    std::cout<<"Download completato\n";

    //invio messaggio DONE
    filename = std::string("");
    filename.resize(SIZE_FILENAME);
    id = 7; //ID di done
    num_packets = 0;

    //invio un pacchetto di done al server 
    if(!send_std_packet(filename, key,sd,counter,id,num_packets)){
        std::cout<<"Errore nell'invio del pacchetto standard\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }
    return;
}


/*Funzione che gestisce l'operazione di rename*/
void rename(int sd, unsigned char* key, uint64_t* counter){
    //chiedo all'utente il file che si vuole rinominare 
    std::cout<<"Inserisci il nome del file da rinominare: ";
    std::string old_filename;
    std::cin>>old_filename;

    //controllo la conformità della stringa 
    if(!check_string(old_filename))
        return;
    
    old_filename.resize(SIZE_FILENAME);
    uint8_t id = 4;
    uint32_t num_packets = 1;

    //invio il pacchetto standard per la richiesta di RENAME
    if(!send_std_packet(old_filename,key,sd,counter,id,num_packets)){
        std::cout<<"Errore nell'invio del pacchetto standard\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }

    //leggo la risposta del server
    unsigned char* response = recv_packet<unsigned char>(sd,REQ_LEN);
    if(!response){
        std::cout<<"Errore nella ricezione della risposta dal server\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }

    unsigned char* plaintext = (unsigned char*)malloc(SIZE_FILENAME);
    if(!plaintext){
        std::cout<<"Errore nell'allocazione di memoria\n";
        free(response);
        return;
    }
    //estrapolo i parametri della risposta del server 
    if(!read_request_param(response,counter,&num_packets,&id,plaintext,key)){
        std::cout<<"Impossibile leggere correttamente la richiesta\n";
        free(response);
        free(plaintext);
        return;
    }
    
    free(response);
    plaintext[SIZE_FILENAME - 1] = '\0';

    //controllo che ID ricevuto non sia di errore 
    if(id == 8){ //ricevuto errore
        std::cout<<"Errore: "<<(char*)plaintext<<std::endl;
        return;
    }
    else if(id != 0){
        std::cout<<"Errore: pacchetto non riconosciuto"<<std::endl;
        return;
    }
    

    //chiedo all'utente il nuovo filename 
    std::cout<<"Rinominare in: ";
    std::string new_filename;
    std::cin>>new_filename;


    //ne controllo la validità
    if(!check_string(new_filename)) {
        new_filename = "Stringa non valida";
        new_filename.resize(SIZE_FILENAME);
        id = 8;
        if(!send_std_packet(new_filename,key,sd,counter,id,num_packets)){
            std::cout<<"Errore nell'invio del nuovo filename al server\n";
            free(plaintext);
            #pragma optimize("", off)
            memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
            #pragma optimize("", on)
            free(key);
            free(counter);
            close(sd);
            exit(1);
        }
        return;
    }


    //invio al server un pacchetto data contente il nuovo filename
    id = 4;
    new_filename.resize(SIZE_FILENAME);
    if(!send_std_packet(new_filename,key,sd,counter,id,num_packets)){
        std::cout<<"Errore nell'invio del nuovo filename al server\n";
        free(plaintext);
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }

    //aspetto la risposta dal server
    response = wait_for_done(sd);
    if(!response) {
        std::cout<<"Rename failed\n"<<std::endl;
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(plaintext);
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }

    //leggo la risposta del server e ne estrapolo i parametri 
    if(!read_request_param(response,counter,&num_packets,&id,plaintext,key)){
        std::cout<<"Impossibile leggere correttamente la richiesta\n";
        free(response);
        free(plaintext);
        return;
    }
    free(response);
    plaintext[SIZE_FILENAME - 1] ='\0';


    //controllo che ID ricevuto non sia di errore 
    if(id != 7){
        std::cout<<(char*)plaintext<<std::endl;
        free(plaintext);
        return;
    }
    else{
        free(plaintext);
        std::cout<<"Operazione terminata con successo\n";
        return;
    }
}


/*Funzione che gestisce l'operazione di rename*/
void delete_file(int sd, unsigned char* key, uint64_t* counter){
    //chiedo all'utente che file vuole eliminare
    std::cout<<"Inserisci il nome del file da eliminare: ";
    std::string filename;
    std::cin>>filename;

    //controllo se il nome del file è valido 
    if(!check_string(filename))
        return;

    filename.resize(SIZE_FILENAME);

    uint8_t id = 5;
    uint32_t num_packets = 0;
    if(!send_std_packet(filename, key,sd,counter,id,num_packets)){ //invio richiesta standard per effettuare una delete di dimensione num_packets
        std::cout<<"Errore nell'invio della richiesta standard\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }

    //ricevo il pacchetto di risposta 
    unsigned char* response = recv_packet<unsigned char>(sd,REQ_LEN);
    if(!response){
        std::cout<<"Errore nella malloc\n";
        return;
    }
    unsigned char* plaintext = (unsigned char*)malloc(SIZE_FILENAME);
    if(!plaintext){
        std::cout<<"Errore nella malloc\n";
        free(response);
        return;
    }

    //estrapolo i paramtri della risposta del server 
    if(!read_request_param(response,counter,&num_packets,&id,plaintext,key)){
        std::cout<<"Impossibile leggere correttamente la richiesta\n";
        free(response);
        free(plaintext);
        return;
    }
    plaintext[SIZE_FILENAME - 1] = '\0';
    free(response);

    //controllo che ID ricevuto sia corretto
    if(id == 8){ //ricevuto errore
        std::cout<<"Errore: "<<(char*)plaintext<<std::endl;
        return;
    }
    else if(id != 0){
        std::cout<<"Errore: pacchetto non riconosciuto"<<std::endl;
        return;
    }
    free(plaintext);

    //chiedo all'utente se vuole confermare l'eliminazione del file 
    uint32_t yesno = 0;
    while (yesno == 0) {
        std::cout<<"Eliminare definitivamente il file? [Y/n] ";
        yesno = select_yesno();
    }
    if (yesno == 1) { // NO
        filename = "";
        filename.resize(SIZE_FILENAME);
        id = 8;
        //in caso di no allora invio al server un pacchetto standard di errore per comunicare che la delete è stato annullata 
        if(!send_std_packet(filename,key,sd,counter,id,num_packets)){
            std::cout<<"Errore nell'invio della conferma di DELETE\n";
            #pragma optimize("", off)
            memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
            #pragma optimize("", on)
            free(key);
            free(counter);
            close(sd);
            exit(1);
        }
        std::cout<<"Delete annullata\n";
        return;
    }
    else if (yesno == 2) { // YES
        filename = "";
        filename.resize(SIZE_FILENAME);
        id = 0;
        //in caso di conferma invio al server un nuovo pacchetto per confermare che la delete deve essere effettuata 
        if(!send_std_packet(filename,key,sd,counter,id,num_packets)){
            std::cout<<"Errore nell'invio della conferma di DELETE\n";
            #pragma optimize("", off)
            memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
            #pragma optimize("", on)
            free(key);
            free(counter);
            close(sd);
            exit(1);
        }
    }
    else { // ERROR
        filename = "Errore sconosciuto";
        filename.resize(SIZE_FILENAME);
        id = 8;
        if(!send_std_packet(filename,key,sd,counter,id,num_packets)) {
            std::cout<<"Errore nell'invio della conferma di DELETE\n";
            #pragma optimize("", off)
            memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
            #pragma optimize("", on)
            free(key);
            free(counter);
            close(sd);
            exit(1);
        }
    }

    //parametri da leggere nel pacchetto di richiesta
    unsigned char* request = wait_for_done(sd);
    if(!request){
        std::cout<<"Delete failed\n"<<std::endl;
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }
    unsigned char* req_payload = (unsigned char*)malloc(SIZE_FILENAME);
    if(!req_payload){
        std::cout<<"Errore nell'allocazione di memoria\n";
        free(request);
        return;
    }

    //estrapolo i parametri della risposta del server 
    if(!read_request_param(request,counter,&num_packets,&id,req_payload,key)){
        std::cout<<"Impossibile leggere correttamente la richiesta\n";
        free(request);
        free(req_payload);
        return;
    }
    free(req_payload);
    free(request);

    //controllo che ID ricevuto non sia di errore 
    if(id != 7){
        std::cout<<"Errore: il server non ha eliminato il file\n";
        return;
    }
    std::cout<<"File eliminato\n";
    return;
}


/*Funzione che gestisce il logout*/
void logout(int sd, unsigned char* key, uint64_t* counter){

    uint8_t id = 6;
    uint32_t num_packets = 0;
    std::string msg = "";
    msg.resize(SIZE_FILENAME);

    //invio la richiesta di logout al server 
    if(!send_std_packet(msg, key,sd,counter,id,num_packets)){
        std::cout<<"Errore nell'invio della richiesta al server\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }

    //ricevo la risposta dal server
    unsigned char* response = recv_packet<unsigned char>(sd,REQ_LEN);
    if(!response){
        std::cout<<"Errore nella malloc\n";
        #pragma optimize("", off)
        memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        #pragma optimize("", on)
        free(key);
        free(counter);
        close(sd);
        exit(1);
    }
    unsigned char* plaintext = (unsigned char*)malloc(SIZE_FILENAME);
    if(!plaintext){
        std::cout<<"Errore nella malloc\n";
        free(response);
        return;
    }

    //estrapolo i paramtri della risposta 
    if(!read_request_param(response,counter,&num_packets,&id,plaintext,key)){
        std::cout<<"Impossibile leggere correttamente la richiesta\n";
        free(response);
        free(plaintext);
        return;
    }
    plaintext[SIZE_FILENAME - 1] = '\0';
    free(response);


    //controllo che ID ricevuto non sia di errore 
    if(id == 8){
        std::cout<<"Errore: "<<(char*)plaintext<<std::endl;
        return;
    }

    if(id != 0){
        std::cout<<"Errore: pacchetto non riconosciuto"<<std::endl;
        return;
    }
    free(plaintext);

    //chiedo conferma all'utente e invio la richiesta corrispondente al server ( id == 8 --> logout annullato )
    uint32_t yesno = 0;
    while (yesno == 0) {
        std::cout<<"Effettuare il logout? [Y/n] ";
        yesno = select_yesno();
    }
    if (yesno == 1) { // NO
        msg = "Logout annullato";
        msg.resize(SIZE_FILENAME);
        id = 8;

        //invio la richietsa standard con ID = 8 che annulla il logout 
        if(!send_std_packet(msg,key,sd,counter,id,num_packets)){
            std::cout<<"Errore nell'invio della conferma di logout\n";
            #pragma optimize("", off)
            memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
            #pragma optimize("", on)
            free(key);
            free(counter);
            close(sd);
            exit(1);
        }
        std::cout<<"Logout annullato\n";
        return;
    }
    else if (yesno == 2) { // YES
        msg = "";
        msg.resize(SIZE_FILENAME);
        id = 0;

        //invio la richiesta standard che conferma il logout 
        if(!send_std_packet(msg,key,sd,counter,id,num_packets)){
            std::cout<<"Errore nell'invio della conferma di logout\n";
            #pragma optimize("", off)
            memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
            #pragma optimize("", on)
            free(key);
            free(counter);
            close(sd);
            exit(1);
        }
    }
    else { // ERROR
        msg = "Errore sconosciuto";
        msg.resize(SIZE_FILENAME);
        id = 8;
        if(!send_std_packet(msg,key,sd,counter,id,num_packets)) {
            std::cout<<"Errore nell'invio della conferma di logout\n";
            #pragma optimize("", off)
            memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
            #pragma optimize("", on)
            free(key);
            free(counter);
            close(sd);
            exit(1);
        }
    }

    std::cout<<"Logout eseguito\n";

    #pragma optimize("", off)
    memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
    #pragma optimize("", on)

    free(key);
    free(counter);
    exit(0);
    return;
}


/*Funzione che permette all'utente di scegliere iterativamente quale operazione svolgere sul cloud storage specificando in input ID*/
void operation(int sd, unsigned char* key) {

    //alloco il counter e lo inizializzo a 0 
    uint64_t* counter = (uint64_t*)malloc(sizeof(uint64_t));
    if(!counter)
        return;
    *counter = 0;


    while(true) {
        uint32_t op_id = 0;
        while (op_id == 0) {
            op_id = select_operation();
        }
        switch (op_id) 
        {
        case 1:
            list(sd, key,counter);
            break;

        case 2:
            upload(sd, key,counter);
            break;

        case 3:
            download(sd, key,counter);
            break;

        case 4:
            rename(sd, key,counter);
            break;

        case 5:
            delete_file(sd, key,counter);
            break;

        case 6:
            logout(sd, key,counter);
            break;
        
        default:
            break;
        }
    }
}



int main(int n_args, char** args){
    int porta;
    int ret;
    int sd; //socket id
    socklen_t len;
    struct sockaddr_in server;

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
        perror("Socket creation error:");
        exit(1);
    }
    memset(&server,0,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(porta);
    if(inet_pton(AF_INET,IP,&server.sin_addr) != 1){
        perror("Socket connect error:");
        exit(1);
    }
    ret = connect(sd,(struct sockaddr*)&server,sizeof(server));
    if(ret == -1){
        perror("Socket connect error:");
        exit(1);
    }
    std::cout<< "░█████╗░██╗░░░░░██╗███████╗███╗░░██╗████████╗\n"
                "██╔══██╗██║░░░░░██║██╔════╝████╗░██║╚══██╔══╝\n"
                "██║░░╚═╝██║░░░░░██║█████╗░░██╔██╗██║░░░██║░░░\n"
                "██║░░██╗██║░░░░░██║██╔══╝░░██║╚████║░░░██║░░░\n"
                "╚█████╔╝███████╗██║███████╗██║░╚███║░░░██║░░░\n"
                "░╚════╝░╚══════╝╚═╝╚══════╝╚═╝░░╚══╝░░░╚═╝░░░"<<std::endl;
    unsigned char* K_ab = handshake(sd);
    
    operation(sd, K_ab);
    close(sd);
    return 0;
}
