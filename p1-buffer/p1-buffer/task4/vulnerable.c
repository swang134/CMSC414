/*
 * CMSC 414, Section 0201
 * Fall 2020
 * Project 1 | task4
 *
 * Build instructions:
 *   We will be building this with the Makefile provided; you may not make
 *   any changes to the Makefile.
 *
 * Submission instructions:
 *   You may not make changes to this file;
 *   You do not need to submit this file.
 */

#include <stdio.h>
#include <stdlib.h>

/* this header exports functions to execute the exploit and read/write
 * to/from it */
#include "comms.h"


void buffer_overflow()
{
    char buffer[512];
    read_from_exploit(buffer, 512);
}

int main()
{
    int local = 5;
    char greeting[128];

    exec_exploit("./exploit.x");

    read_from_exploit(greeting, sizeof(greeting)-1);

    write_to_exploit(greeting);

    puts("Waiting for input...");
    buffer_overflow();
    
    puts("Zero points. (Program terminated successfully; overflow failed.)");

    return EXIT_SUCCESS;
}
