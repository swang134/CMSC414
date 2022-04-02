/*
 * The Bank takes commands from the ATM, handled by
 * bank_process_remote_command.
 *
 * You can add more functions as needed.
 */

#ifndef __BANK_H__
#define __BANK_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <signal.h>


typedef struct item {
  char *account;
  double balance;
  FILE *card;
}item;

typedef struct Hashtable{
  item **items;
  int size;
  int count;
}Hashtable;

typedef struct _Bank {
	// Networking state
	int sockfd;
	int clientfd;
	struct sockaddr_in bank_addr;
	struct sockaddr_in remote_addr;
	char *auth_file; 
    struct Hashtable *table;
	// Protocol state
	// Specify struct for storing state of bank and acount holders

} Bank;

Bank* bank_create(char *auth_file, char *ip, unsigned short port);
void bank_free(Bank *bank);
int bank_send(Bank *bank, const char *data, size_t data_len);
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len);
void bank_process_remote_command(Bank *bank, char *command, size_t len);
int encrypt(unsigned char *key, unsigned char *ciphertext, unsigned char* plaintext, int plaintext_len, unsigned char *iv, unsigned char *tag);
int decrypt(unsigned char *key, unsigned char* plaintext, unsigned char *ciphertext, int ciphertext_len, unsigned char *iv, unsigned char *tag);

// Add more as required
void free_item (item *ifree);
unsigned long hash_function (char *str);
item *create_account(char *account, double balance);
ashtable *create_table(int size);
void* insert (Hashtable *table, char* account, double balance);
item search(Hashtable *table, char* account);

#endif
