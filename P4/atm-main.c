#include "atm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <regex.h>

// Default port and ip address are defined here

int main(int argc, char** argv){

	// Implement how atm protocol will work: sanitizing inputs and using different modes of operations
	// SW - sanitizing inputs and using different modes of operations
	char *a, *s, *i, *p, *c, *mode, *file; // use to store the inputs value 
    int opinion;
	int money;
	// Input Validation
    while ((opinion = getopt (argc, argv, "a:s:i:p:c:n:d:w:g")) != -1) {
        if (optarg != NULL && strlen(optarg) > 6) 
		// If use inputs the number of args that is larger than the max argv that can be hold --> error
            exit(255);

        switch (opinion) {

			// check for account name 
            case 'a':

				// check for repeat command 
                if (a != NULL)
                    exit(255);
                else 
                    a = optarg;
                
				// the user name can only be have letters and numbers, with 1 to 256 characters
				// the reason we choose 256 as the max length is because in windows the max length
				// of user name is 256 characters. 
                if (match(a, "^[A-Za-z0-9]{1,256}$")!= 1)
                    exit(255);
                break; 

			// check for the auth file
            case 's':
				
				// check for repeat command 
                if (s != NULL)
                    exit(255);
                else 
                    s = optarg;

                // the file name can only be have letters and numbers, and one dots to seperate the file format
				// with 1 to 255 characters 
				// the reason we choose 256 as the max length is because in windows the max length
				// of file name is 256 characters. 
                if (match(s, "^[A-Za-z0-9]+.auth$")!= 1 || strlen(s) > 256)
                    exit(255);
                break;
				//one thing I want check here is that we should check the file have vaild file format, but it is 
				//hard to implement here so I didn't do it. 

			// check for ip address
            case 'i':
                // check for repeat command 
                if (i != NULL)
                    exit(255);
                else 
                    i = optarg;

				//check for vaild ip address 
				 if (match(i, "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")!= 1 || strlen(i) > 15)
                    exit(255);
                break;

			// check for port
            case 'p':
                // check for repeat command 
                if (p != NULL)
                    exit(255);
                else 
                    p = optarg;

				//check for vaild port 
				 if (match(p, "^[1-9][0-9]*$")!= 1 || atoi(p) < 1024 || atoi(p) > 65535)
                    exit(255);
                break;

			//check for card filename
            case 'c':
                				// check for repeat command 
                if (c != NULL)
                    exit(255);
                else 
                    c = optarg;

                // the file name can only be have letters and numbers, and one dots to seperate the file format
				// with 1 to 255 characters 
				// the reason we choose 256 as the max length is because in windows the max length
				// of file name is 256 characters. 
                if (match(c, "^[A-Za-z0-9]+.[A-Za-z]+$")!= 1 || strlen(s) > 255)
                    exit(255);
                break;
				//one thing I want check here is that we should check the file have vaild file format, but it is 
				//hard to implement here so I didn't do it. 

			// Check for mode
            case 'n':
                if (mode != NULL || file != NULL )
                    exit(255);
                else{
                    file = optarg;
                    mode = "n";
                }
                sscanf(file, "%lf", &money);
                if (match(file, "^[0-9]+.[0-9]{2}$")!= 1 || 
                    money < 10.00 || money > 4294967295.99) {
                    exit(255);
                } 
                break;

            case 'd':
                if (mode != NULL || file != NULL )
                    exit(255);
                else{
                    file = optarg;
                    mode = "d";
                }
                sscanf(file, "%lf", &money);
                if (match(file, "^[0-9]+.[0-9]{2}$")!= 1 || 
                    money < 0.00 || money > 4294967295.99) {
                    exit(255);
                } 
                break;

            case 'w':
                if (mode != NULL || file != NULL )
                    exit(255);
                else{
                    file = optarg;
                    mode = "w";
                }
                sscanf(file, "%lf", &money);
                if (match(file, "^[0-9]+.[0-9]{2}$")!= 1 || 
                    money < 0.00 || money > 4294967295.99) {
                    exit(255);
                } 
                break;
				
            case 'g':
                if (mode != NULL) 
                   exit(255);
                else
                	mode = "g";
                break;

			// if the user input some input that does not in the given opinion --> return 255
            case '?':
                exit(255);
        }
    }
    //Default values if none are passed in the command line

	//account name is required 
    if (a == NULL)
        exit(255);
	
	//defult value of auth_file
    if (s == NULL)
        s = "bank.auth";

	//defult value of auth_file
	if (i == NULL)
        i = "127.0.0.1";

	//defult value of port 
    if (port == NULL) 
        port = "3000";

    // Check whether we can open and read the file
    if (access(s, F_OK | R_OK) == -1) 
        exit(255);

    // if it didn't give any mode opinion --> return 255
	if (strcmp(mode, "g") == 0 && argc != optind)
    exit(255);

    // Set defult card name --> account.card 
    char card_name[256];
    if (c == NULL) {
        strncpy(card_name, a, strlen(a)+1);
        if (strlen(card_name) <= 255) {
            strcat(card_name, ".card");
            c = card_name;
        } else
            exit(255);
    }

    ATM *atm = atm_create(p, i);

	/* send messages */

    int size = strlen(a) + strlen(s) + strlen(i) + strlen(p) +
        strlen(c) + strlen(mode) + strlen(file);
    char *cmds = malloc(size+7);
    snprintf(cmds, size, "%s;%s;%s;%s;%s;%s;%s", a, s, i, p,
        c, mode, file);
    
    atm_process_command(atm, cmds);

	char buffer[] = "Hello I am the atm and I would like to have money please";
	atm_send(atm, buffer, sizeof(buffer));
	atm_recv(atm, buffer, sizeof(buffer));
	printf("atm received %s\n", buffer);
	atm_free(atm);
    return EXIT_SUCCESS;
}

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


	