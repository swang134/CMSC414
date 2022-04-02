/*
 * The ATM interfaces with the user.  User commands should be
 * handled by atm_process_command.
 *
 * The ATM can read .card files, but not .pin files.
 *
 * You can add more functions as needed.
 */

#ifndef __ATM_H__
#define __ATM_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

typedef struct _ATM {
	// Networking state
	int sockfd;
	struct sockaddr_in bank_addr;

	// Protocol state
	// TODO add more, as needed
} ATM;

ATM* atm_create(char *ip, unsigned short port);
void atm_free(ATM *atm);
int atm_send(ATM *atm, const char *data, size_t data_len);
ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len);
unsigned char* atm_process_command_send(ATM *atm, char *command);
void atm_process_command(ATM *atm, char *command);
int encrypt(unsigned char *key, unsigned char *ciphertext, unsigned char* plaintext, int plaintext_len, unsigned char *iv, unsigned char *tag);
int decrypt(unsigned char *key, unsigned char* plaintext, unsigned char *ciphertext, int ciphertext_len, unsigned char *iv, unsigned char *tag);
int returnlen();

#endif
