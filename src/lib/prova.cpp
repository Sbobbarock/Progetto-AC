int encrypt(unsigned char *, int ,unsigned char *, int ,unsigned char *,unsigned char *,unsigned char *,unsigned char *);



u_int32_t select_operation() {
    std::cout<<"Operazioni disponibili\n";
    std::cout<<"1: List\n";
    std::cout<<"2: Upload\n";
    std::cout<<"3: Download\n";
    std::cout<<"4: Rename\n";
    std::cout<<"5: Delete\n";
    std::cout<<"6: Logout\n";
    u_int32_t operation_id;
    std::cin>>operation_id;
    if(operation_id < 1 || operation_id > 6) {
        std::cout<<"Operazione non valida\n";
        return 0;
    }
    return operation_id;
}

void list(){}

void upload(){}

void download(int sd, unsigned char* key){
    std::string filename;
    std::cin>>filename;
    if(!check_string(filename))
        return;

    filename.resize(SIZE_FILENAME);

    u_int64_t counter = 0;
    u_int8_t id = 3;
    unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_gcm()));
    if(!iv){
        std::cout<<"Errore nella malloc\n";
        return;
    }
    iv = nonce(iv,EVP_CIPHER_iv_length(EVP_aes_128_gcm()));

    u_int32_t next_len = 0;

    unsigned int aad_len = sizeof(u_int32_t)+sizeof(u_int8_t)+sizeof(u_int64_t) + EVP_CIPHER_iv_length(EVP_aes_128_gcm());
    unsigned char* aad = (unsigned char*)malloc(aad_len);
    if(!aad){
        free(iv);
        return;
    }
    memcpy(aad,&counter,sizeof(u_int64_t));
    memcpy(aad + sizeof(u_int64_t),&id,sizeof(u_int8_t));
    memcpy(aad + sizeof(u_int64_t) + sizeof(u_int8_t), &next_len, sizeof(u_int32_t));
    memcpy(aad + sizeof(u_int64_t) + sizeof(u_int8_t) + sizeof(u_int32_t), &iv, EVP_CIPHER_iv_length(EVP_aes_128_gcm()));

    unsigned char* ciphertext = (unsigned char*)malloc(SIZE_FILENAME + 16);
    if(!ciphertext){
        free(iv);
        free(aad);
        return;
    }
    
    unsigned char* tag = (unsigned char*)malloc(16);
    if(!tag){
        free(iv);
        free(aad);
        free(ciphertext);
        return;
    }

    int ciphertext_len = encrypt((unsigned char*)filename.c_str(),SIZE_FILENAME,aad,aad_len,key,iv,ciphertext,tag);
    std::cout<<ciphertext_len<<std::endl;
}
void rename(){}

void delete_file(){}

void logout(){}

void operation(int sd, unsigned char* key) {
    u_int32_t op_id = select_operation();
    while (op_id == 0) {
        op_id = select_operation();
    }
    switch (op_id) 
    {
    case 1:
        list();
        break;

    case 2:
        upload();
        break;

    case 3:
        download(sd, key);
        break;

    case 4:
        rename();
        break;

    case 5:
        delete_file();
        break;

    case 6:
        logout();
        break;
    
    default:
        break;
    }
}
