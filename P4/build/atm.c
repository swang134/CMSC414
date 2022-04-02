#include "atm.h"
#include "net.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

char *params[7]; // received params

int encrypt(unsigned char *key, unsigned char *ciphertext, unsigned char* plaintext, int plaintext_len, unsigned char *iv, unsigned char *tag){
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

int decrypt(unsigned char *key, unsigned char* plaintext, unsigned char *ciphertext, int ciphertext_len, unsigned char *iv, unsigned char *tag){

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



ATM* atm_create(char *ip, unsigned short port)
{
	ATM *atm = (ATM*) calloc(1, sizeof(ATM));
	if(atm == NULL) {
		perror("Could not allocate ATM");
		exit(1);
	}

#define BOOL_CHK(x,msg) if (x) { perror(msg); exit(255); }

	// Set up the network state

	BOOL_CHK(inet_pton(AF_INET, ip, &(atm->bank_addr.sin_addr)) != 1, "could not convert ip address");
	atm->bank_addr.sin_port = htons(port);
	atm->bank_addr.sin_family = AF_INET;

	atm->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	BOOL_CHK(atm->sockfd < 0, "could not create socket");

	BOOL_CHK(connect(atm->sockfd, (struct sockaddr*)&(atm->bank_addr), sizeof(atm->bank_addr)) < 0, "could not connect");

#undef BOOL_CHK
	

	// Set up the protocol state
	// TODO set up more, as needed

	return atm;
}

void atm_free(ATM *atm){
	close(atm->sockfd);
// TODO
}

/* send a message to the bank of size data_len stored in the buffer
 * data. return 0 on success, negative on error */
int atm_send(ATM *atm, const char *data, size_t data_len){

	if (atm->sockfd < 0) {
		return -1;
	}

	if (send_all(atm->sockfd, (const char*)&data_len, sizeof(data_len)) != sizeof(data_len)) {
		return -2;
	}

	if (send_all(atm->sockfd, data, data_len) != (ssize_t)data_len) {
		return -3;
	}
	return 0;
}

/* receive a message (i.e., something sent via bank_send) and store it
 * in data. If the message exceeds max_data_len, a negative value is
 * returned and the message is discarded */
ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len){

	size_t msg_len;

	if (atm->sockfd < 0) {
		return -1;
	}

	if (recv_all(atm->sockfd, (char*)&msg_len, sizeof(msg_len)) != sizeof(msg_len)) {
		return -2;
	}

	if (msg_len > max_data_len) {
		/* message doesn't fit in data, read all of the message to discard it */
		char tmp[4096];
		do {
			size_t to_read = msg_len > sizeof(tmp) ? sizeof(tmp) : msg_len;
			if (recv_all(atm->sockfd, tmp, to_read) != sizeof(to_read)) {
				/* logic error somewhere, should probably crash/restart */
				return -3;
			}
			msg_len -= to_read;
		} while(msg_len > 0) ;
	}

	return recv_all(atm->sockfd, data, msg_len);
}

char* params[7];
char* send_bank (char *message){
  //printf("hi: %s\n", message);
  unsigned char *plaintext;
  plaintext = (unsigned char*)message;
  unsigned char key[16];
  FILE *authFile, *card;
  unsigned char *ciphertext = NULL;
  ciphertext = malloc(strlen(message));
  unsigned char iv[12];
  unsigned char tag[16];
  if (!RAND_bytes(iv,sizeof(iv)-1)){
    exit(255);
  }

// Get Key from Auth File
  if(access(params[1], F_OK) == -1){
    exit(255);
  }
  if(access(params[1], R_OK) == -1){
    exit(255);
  }
  authFile = fopen(params[1], "rb");
  fread(key, 16, 1, authFile);
  fclose(authFile);

  int ciphertext_len = encrypt(key, ciphertext, plaintext, strlen(message), iv, tag);
  if(ciphertext_len < 0) 
    exit(255);

  card = fopen(params[4], "w+");
  fwrite(iv, 1, 12, card);
  fwrite("\n", sizeof(char), 1, card);
  fwrite(tag, 1, 16, authFile);
  printf("%s\n", ciphertext);

  char *abc = malloc(7);
  return ciphertext;
}
void atm_process_command(ATM *atm, char *command){

  switch(*params[5]){ // check mode
    /* 
     * Create new account with given balance
     * Balance must be >= 10.00
     * Card file must not already exist
     */

    case 'n':

      if (command = "true"){
        printf("{\"account\":\"%s\", \"initial_balance\":\"%s\"}\n",params[0],params[6]);
      }else{
        exit(255);
      }
      
    break;

    /* 
     * Deposit money
     * Amount must be > 0.00
     * Account must exist
     * Card file must be associated with the given account
     */
  
    case 'd':
      if (command = "true"){
        printf("{\"account\":\"%s\", \"despoit\":\"%s\"}\n",params[0],params[6]);
      }else{
        exit(255);
      }
      
    break;

    /*
     * Withdraw money
     * Amount must be > 0.00
     * Remaining balance must be non-negative
     * Card file must be associated with the given account
     */
    case 'w':
      if (command = "true"){
        printf("{\"account\":\"%s\", \"Withdraw\":\"%s\"}\n",params[0],params[6]);
      }else{
        exit(255);
      }
    break;

    /*
     * Current Balance
     * Account must exist
     * Card file must be associated wit hthe given account
     */
    case 'g':
      if (command = "true"){
        printf("{\"account\":\"%s\", \"balance\":\"%s\"}\n",params[0],params[6]);
      }else{
        exit(255);
      }
    break;
  }
  // Implement the ATM's side of the ATM-bank protocol

}
void atm_process_command_send(ATM *atm, char *command)
{
  puts("HI");
  const char s[2] = ",";
  int i = 0;
  FILE *cardFile;
  *params = malloc(strlen(command));
   
   /* get the first token */
  char *token = strtok(command, s);
   
   /* walk through other tokens */
  while( token != NULL ) {
      params[i] = (char *)malloc(strlen(token) +1);
      strcpy(params[i++], token);
      token = strtok(NULL, s);
  }

  for(int i = 0; i<7; i++){
    printf("%s\n", params[i]);
  }

  int size = strlen(params[0])+ strlen(params[5])+strlen(params[6])+6;
  char *message = malloc(size);
  snprintf(message, size, "%s,%s,%s",params[0], params[5],params[6] );
  printf("%s\n", message);
  
  char *msg = malloc(size);
  msg = send_bank(message);
  printf("%s\n", msg);

  switch(*params[5]){ // check mode
    /* 
     * Create new account with given balance
     * Balance must be >= 10.00
     * Card file must not already exist
     */

    case 'n':

      if(access(params[1], F_OK|R_OK) != -1){
        exit(255);
      }else{
        memcpy(command, msg, size+1);
      }
      
    break;

    /* 
     * Deposit money
     * Amount must be > 0.00
     * Account must exist
     * Card file must be associated with the given account
     */
  
    case 'd':
      if(access(params[1], F_OK|R_OK) == -1){
        exit(255);
      }else{
        memcpy(command, msg, size+1);
      }
    break;

    /*
     * Withdraw money
     * Amount must be > 0.00
     * Remaining balance must be non-negative
     * Card file must be associated with the given account
     */
    case 'w':
      if(access(params[1], F_OK|R_OK) == -1){
        exit(255);
      }else{
        memcpy(command, msg, size+1);printf("{\"account\":\"%s\", \"despoit\":\"%s\"}\n",params[0],params[6]);
      }
    break;

    /*
     * Current Balance
     * Account must exist
     * Card file must be associated wit hthe given account
     */
    case 'g':
      if(access(params[1], F_OK|R_OK) == -1){
        exit(255);
      }else{
        memcpy(command, msg, size+1);printf("{\"account\":\"%s\", \"despoit\":\"%s\"}\n",params[0],params[6]);
      }
    break;
  }
	// Implement the ATM's side of the ATM-bank protocol
}

// Add more functions as needed

