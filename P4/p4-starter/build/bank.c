#include "bank.h"
#include "net.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#define capacity 50000

int encrypt(unsigned char *key, unsigned char *ciphertext, unsigned char* plaintext, 
 int plaintext_len, unsigned char *iv, unsigned char *tag){
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

    /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())){
    return -2;
  }

    /* Initialise the encryption operation. */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)){ 
    return -2;
  }


    /* Initialise key and IV */
  if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)){ 
    return -2;
  }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
    return -2;
  }
  ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
    return -2;
  }
  ciphertext_len += len;

    /* Get the tag */
  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)){
    return -2;
  }

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt(unsigned char *key, unsigned char* plaintext, unsigned char *ciphertext,
 int ciphertext_len, unsigned char *iv, unsigned char *tag){

  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  int ret;


      /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new()))
    return -2;


      /* Initialise the decryption operation. */
  if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
    return -2;


      /* Initialise key and IV */
  if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    return -2;

      /*
       * Provide the message to be decrypted, and obtain the plaintext output.
       * EVP_DecryptUpdate can be called multiple times if necessary
       */
  if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
      return -2;
  plaintext_len = len;

      /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    return -2;

      /*
       * Finalise the decryption. A positive return value indicates success,
       * anything else is a failure - the plaintext is not trustworthy.
       */
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

      /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  if(ret > 0) {
          /* Success */
    plaintext_len += len;
    return plaintext_len;

  } else {
          /* Verify failed */
    return -1;
  }
}

//Add more functions as required
unsigned long hash_function (char *str){
  unsigned long i = 0;
  for (int j=0; str[j]; j++)
    i+=str[j];
  return i%capacity;
}

typedef struct item item;

struct item {
  char *account;
  double balance;
};

typedef struct Hashtable Hashtable;

struct Hashtable{
  item **items;
  int size;
  int count;
};

item *create_account(char *account, double balance){
  item *user = (item*)malloc(sizeof(item));
  user->account = (char*)malloc(strlen(account)+1);
  user->balance = balance; 
  strcpy(user->account, account);
  return user;
}

Hashtable *create_table(int size){
  Hashtable *table = (Hashtable*)malloc(sizeof(Hashtable));
  table->size = size;
  table->count = 0; 
  table->items = (item**) calloc(table->size, sizeof(item*));
  for (int i=0; i< table-> size; i++)
    table->items[i] = NULL; 
  return table;
}

void free_item (item *ifree){
  free(ifree->account);
  free(ifree);
}

void* insert (Hashtable *table, char* account, double balance){
  item *new = create_account(account, balance);
  unsigned long index = hash_function(account);
  item *current = table->items[index];
  if(current == NULL){
    if (table->count == table->size){
      free_item(new);
    }
    table->items[index] = new;
    table->count++;
  }
}

double search(Hashtable *table, char* account){
  int index = hash_function(account);
  item *find = table->items[index];
  if(find != NULL){
    if(strcmp(find->account, account) == 0)
      return find->balance;
  }
  return -1000.00;
}


Bank* bank_create(char *auth_file, char *ip, unsigned short port)
{

  Bank *bank = (Bank*) calloc(1, sizeof(Bank));
    
  // if not auth_file exists, create auth_file
  FILE *fp;
  if(access(auth_file, F_OK)!= -1){
    exit(255);
  } else {
    if ((fp = fopen(auth_file, "wb")) == NULL) {
      exit(255);
    }
    unsigned char key[16];
    if (!RAND_bytes (key,sizeof(key)-1)){
      exit(255);
    }
    fwrite(key, sizeof(key),1,fp);
    fclose(fp);
  }

  bank->auth_file = auth_file;
        
  if(bank == NULL) {
    perror("Could not allocate Bank");
    exit(255);
  }

  Hashtable *table = create_table(50000);

#define BOOL_CHK(x,msg) if (x) { perror(msg); exit(255); }


  /* setup network connection */
  BOOL_CHK(inet_pton(AF_INET, ip, &(bank->bank_addr.sin_addr)) != 1, "could not convert ip address");

  bank->bank_addr.sin_port = htons(port);
  bank->bank_addr.sin_family = AF_INET;

  int s = socket(AF_INET, SOCK_STREAM, 0);
  BOOL_CHK(s<0,"could not create socket");

  int enable = 1;
  BOOL_CHK(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0, "setsockopt(SO_REUSEADDR) failed");

  BOOL_CHK(bind(s, (struct sockaddr*)&(bank->bank_addr), sizeof(bank->bank_addr)) < 0, "could not bind");

  listen(s, 5);

  bank->sockfd = s;

#undef BOOL_CHK

  // Set up the protocol state
  // TODO set up more, as needed

  return bank;
}

void bank_free(Bank *bank){

  close(bank->sockfd);
  // TODO
}

/* sends data_len bytes from data to atm, returns size 0 on success, negative on failure */
int bank_send(Bank *bank, const char *data, size_t data_len) {
  if (bank->clientfd < 0) {
    return -1;
  }

  if (send_all(bank->clientfd, (const char*)&data_len, sizeof(data_len)) != sizeof(data_len)) {
    return -2;
  }

  if (send_all(bank->clientfd, data, data_len) != (ssize_t)data_len) {
    return -3;
  }
  return 0; 
}

/* receive a message (i.e., something sent via atm_send) and store it
 * in data. If the message exceeds max_data_len, a negative value is
 * returned and the message is discarded */
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len) {

  size_t msg_len;

  if (bank->clientfd < 0) {
    return -1;
  }

  if (recv_all(bank->clientfd, (char*)&msg_len, sizeof(msg_len)) != sizeof(msg_len)) {
    return -2;
  }

  if (msg_len > max_data_len) {
    /* message doesn't fit in data, read all of the message to discard it */
    char tmp[4096];
    do {
      size_t to_read = msg_len > sizeof(tmp) ? sizeof(tmp) : msg_len;
      if (recv_all(bank->clientfd, tmp, to_read) != sizeof(to_read)) {
        /* logic error somewhere, should probably crash/restart */
        return -3;
      }
      msg_len -= to_read;
    } while(msg_len > 0) ;
  }

  return recv_all(bank->clientfd, data, msg_len); 

}

void bank_process_remote_command(Bank *bank, char *command, size_t len) {
  bank_send(bank, "true", 5);
  // TODO: Implement the bank side of the ATM-bank protocol
}
