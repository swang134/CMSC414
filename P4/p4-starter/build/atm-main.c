#include "atm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <regex.h>

//regular expression checker 
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

// Default port and ip address are defined here

int main(int argc, char** argv){

    // Implement how atm protocol will work: sanitizing inputs and using different modes of operations
    // SW - sanitizing inputs and using different modes of operations
    char *acc = NULL;
    char *sauth = NULL;
    char *ip = NULL;
    char *port = NULL;
    char *card = NULL;
    char *mode= NULL;
    char *file = NULL; // use to store the inputs value 
    int opinion;
    // Input Validation
    while ((opinion = getopt (argc, argv, "a:s:i:p:c:n:d:w:g")) != -1) {
        //printf("%s\n",optarg);
        if (optarg != NULL && strlen(optarg) > _POSIX_ARG_MAX){
        // If use inputs the number of args that is larger than the max argv that can be hold --> error
            printf("parameter # error");
            exit(255);
        }

        switch (opinion) {

            // check for account name 
            case 'a':
                if (acc!= NULL){
                    printf("%s repeated a", acc);
                    exit(255);
                }
                else 
                    acc = optarg;

                // the file name can only be have letters and numbers, and one dots to seperate the file format
                // with 1 to 255 characters 
                // the reason we choose 256 as the max length is because in windows the max length
                // of file name is 256 characters. 
                if (match(acc, "^[A-Za-z0-9]+$")!= 1 || strlen(acc) > 256){
                    printf("a format error\n");
                    exit(255);
                }
                break;

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
                if (match(sauth, "^[A-Za-z0-9]+.[A-Za-z]+$")!= 1 || strlen(sauth) > 256){
                    printf("s format error\n");
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

            //check for card filename
            case 'c':
                                // check for repeat command 
                if (card!= NULL){
                    printf("repeated c");
                    exit(255);
                }
                else 
                    card = optarg;

                // the file name can only be have letters and numbers, and one dots to seperate the file format
                // with 1 to 255 characters 
                // the reason we choose 256 as the max length is because in windows the max length
                // of file name is 256 characters. 
                if (match(card, "^[A-Za-z0-9]+.[A-Za-z]+$")!= 1 || strlen(card) > 255){
                    printf("card issue");
                    exit(255);
                }
                break;
                //one thing I want check here is that we should check the file have vaild file format, but it is 
                //hard to implement here so I didn't do it. 

            // Check for mode
            case 'n':
                if (mode != NULL || file != NULL ){
                    printf("repeated n");
                    exit(255);
                }
                else{
                    file = optarg;
                    mode = "n";
                }
                if (match(file, "^[0-9]+.[0-9]{2}$")!= 1 || 
                    atof(file) < 10.00 || atof(file) > 4294967295.99) {
                    printf("money too much");
                    exit(255);
                } 
                break;

            case 'd':
                if (mode != NULL || file != NULL ){
                    printf("repeated d");
                    exit(255);
                }
                else{
                    file = optarg;
                    mode = "d";
                }
                if (match(file, "^[0-9]+.[0-9]{2}$")!= 1 || 
                    atof(file) < 0.00 || atof(file)> 4294967295.99) {
                    printf("money too much");
                    exit(255);
                } 
                break;

            case 'w':
                if (mode != NULL || file != NULL ){
                    printf("repeated w");
                    exit(255);
                }
                else{
                    file = optarg;
                    mode = "w";
                }
                if (match(file, "^[0-9]+.[0-9]{2}$")!= 1 || 
                    atof(file) < 0.00 || atof(file) > 4294967295.99) {
                    printf("money too much");
                    exit(255);
                } 
                break;
                
            case 'g':
                if (mode == NULL){
                    mode = "g";
                    file = "\0";
                }
                else
                    exit(255);
                break;

            // if the user input some input that does not in the given opinion --> return 255
            case '?':
                printf("mode not in opinion");
                exit(255);
        }
    }
    //Default values if none are passed in the command line
    if (mode == NULL || file == NULL){
        printf("need select mode");
        exit(255);
    }

    //account name is required 
    if (acc == NULL){
        printf("need input acc name");
        exit(255);
    }
    
    //defult value of auth_file
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
    // Check whether we can open and read the file
    //if (access(s, F_OK | R_OK) == -1) 
        //exit(255);

    // if it didn't give any mode opinion --> return 255
    if (mode == NULL){
        printf("no model selected");
        exit(255);
    }

    // Set defult card name --> account.card 
    if (card == NULL) {
        card = malloc(256);
        strncpy(card, acc, strlen(acc)+1);
        // 256 - strlen(.card) - end character = 250-5-1
        if (strlen(card) < 250) {
            strcat(card, ".card");
            printf("%s\n",card);
        } else{
            printf("defult card error");
            exit(255);
        }
    }

    ATM *atm = atm_create(ip, atoi(port));

    /* send messages */
    //const char *jsonformat = "{\"account\":$1, \"authfile\":$b, \"ip\":$C, \"port\":$four, \"card\":$ccccc, \"mode\":$^, \"file\":$g}";
    //const char *json = acc, sauth, ip, port,card, mode, file;
    //int size = strlen(acc) + strlen(sauth) + strlen(ip) + strlen(port) + strlen(card) + strlen(mode) + strlen(file) + strlen(jsonformat) + 1; // total strlen of parameter + json format str len
    //char *json = malloc(size);
    //snprintf(json, size, "{\"account\":%s$1, \"authfile\":%s$b, \"ip\":%s$C, \"port\":%s$four, \"card\":%s$ccccc, \"mode\":%s$^, \"file\":%s$g}", acc, sauth, ip, port,card, mode, file);
    
    int size = strlen(acc) + strlen(sauth) + strlen(ip) + strlen(port) + strlen(card) + strlen(mode) + strlen(file) + 7; // total strlen of parameter + json format str len
    char *json = malloc(size);
    snprintf(json, size, "%s,%s,%s,%s,%s,%s,%s", acc, sauth, ip, port,card, mode, file);
    
    atm_process_command(atm, json);
    //printf("%s\n", json);
    //char buffer[] = "Hello I am the atm and I would like to have money please";
    atm_send(atm, json, size);
    atm_recv(atm, json, size);
    printf("atm received %s\n", json);
    atm_free(atm);
    printf("all access");
    return EXIT_SUCCESS;
}

