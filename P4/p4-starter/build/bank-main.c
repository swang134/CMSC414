#include "bank.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <regex.h>
#include <signal.h>

#include "bank.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <regex.h>
#include <signal.h>

//By Shuyao Wang
// Default port and ip address are defined here
int match(const char *string, const char *pattern)
{
    regex_t re;
    if (regcomp(&re, pattern, REG_EXTENDED) != 0) 
        return 0;
    int status = regexec(&re, string, 0, NULL, 0);
        regfree(&re);
    if (status != 0) 
        return 0;
    return 1;
}

//By Shuyao Wang
int main(int argc, char** argv){
    
    //unsigned short port = 3000;
    //char *ip = "127.0.0.1";

    char *ip = NULL;
    char *port = NULL;
    char *sauth = NULL;
    int opinion;

    while ((opinion = getopt (argc, argv, "s:p:i:")) != -1) {
        if (optarg != NULL && strlen(optarg) > _POSIX_ARG_MAX){
        // If use inputs the number of args that is larger than the max argv that can be hold --> error
            printf("parameter # error");
            exit(255);
        }

        switch (opinion) {

            // check for the auth file
            case 's':
                
                // check for repeat command 
                if (sauth!= NULL){
                    printf("%s repeated s", sauth);
                    exit(255);
                }
                else 
                    sauth= optarg;

                // the file name can only be have letters and numbers, and one dots to seperate the file format
                // with 1 to 255 characters 
                // the reason we choose 256 as the max length is because in windows the max length
                // of file name is 256 characters. 
                if (match(sauth, "^[A-Za-z0-9]+.auth$")!= 1 || strlen(sauth) > 256){
                    printf("s format error");
                    exit(255);
                }
                break;
                //one thing I want check here is that we should check the file have vaild file format, but it is 
                //hard to implement here so I didn't do it. 

            // check for ip address
            case 'i':
                // check for repeat command 
                if (ip != NULL){
                    printf("repeated i");
                    exit(255);
                }
                else 
                    ip = optarg;

                //check for vaild ip address 
                if (match(ip, "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")!= 1 || strlen(ip) > 15){
                    printf("i format error");
                    exit(255);
                }
                break;

            // check for port
            case 'p':
                // check for repeat command 
                if (port != NULL){
                    printf("repeated p");
                    exit(255);
                }
                else 
                    port = optarg;

                //check for vaild port 
                if (match(port, "^[1-9][0-9]*$")!= 1 || atoi(port) < 1024 || atoi(port) > 65535){
                    printf("port format error");
                    exit(255);
                }
                break;
            case '?':
                exit(255);
        }
    }

    if (sauth == NULL){
       sauth = "bank.auth";
    }

    //defult value of auth_file
    if (ip == NULL){
        ip = "127.0.0.1";
    }

    //defult value of port 
    if (port == NULL){ 
        port = "3000";
    }

    /* no error checking is done on any of this. may need to modify this */
    Bank *b = bank_create(sauth, ip, atoi(port));

    /* process each incoming client, one at a time, until complete */
    for(;;) {

        unsigned int len = sizeof(b->remote_addr);
        b->clientfd = accept(b->sockfd, (struct sockaddr*)&b->remote_addr, &len);
        if (b->clientfd < 0) {
            perror("error on accept call");
            exit(255);
        }

        /* okay, connected to bank/atm. Send/recv messages to/from the bank/atm. */
        char buffer[10000];
        bank_recv(b, buffer, sizeof(buffer));
        printf("bank received:  %s\n", buffer);
        bank_process_remote_command(b, buffer,strlen(buffer));
        //bank_send(b, buffer, strlen(buffer)+1);


        /* when finished processing commands ...*/
        close(b->clientfd);
        b->clientfd = -1;
    }


    
    
    // Implement how atm protocol will work: sanitizing inputs and using different modes of operations

    return EXIT_SUCCESS;
}
