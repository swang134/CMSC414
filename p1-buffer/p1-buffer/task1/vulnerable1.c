/*
 * CMSC 414, Section 0201
 * Fall 2020
 * Project 1 | task1
 *
 * Build instructions:
 *   We will be building this with the Makefile provided; you may not make
 *   any changes to the Makefile.
 *
 * Submission instructions:
 *   You may not make changes to this file; only to exploit1.c
 *   You do not need to submit this file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* this header exports functions to execute the exploit and read/write
 * to/from it */
#include "comms.h"

void sensitive_function()
{
    puts("Full points! (Hey wait a minute.. How did you get here?)");
    exit(EXIT_SUCCESS);
}

void buffer_overflow()
{
    char secret[32];
    char buffer[32];

    sprintf(secret, "authorized personnel only");

    read_from_exploit(buffer, 64);

    if(strcmp(secret, "let me in... LET ME INNNN!!!") == 0)
        sensitive_function();
}

static char greeting[128];

int main()
{
    int local = 5;

    exec_exploit("./exploit1.x");

    read_from_exploit(greeting, sizeof(greeting)-1);

    write_to_exploit(greeting);

    puts("Waiting for input...");
    buffer_overflow();

    puts("Zero points. (Program terminated successfully; overflow failed.)");


    
    return EXIT_SUCCESS;
}