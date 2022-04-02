/*
 * CMSC 414, Section 0201
 * Fall 2020
 * Project 1 | task0
 *
 * Build instructions:
 *   We will turn standard protections off (ASLR, canaries, etc.).
 *   We will be building this with the Makefile provided; you may not make
 *   any changes to the Makefile.
 *
 * Submission instructions:
 *   You must submit *three* separate files (task0a.c, task0b.c, task0c.c),
 *   each of which implements a *fundamentally different* version of
 *   your_fcn(), each of which wins the "impossible game".
 */

#include <stdio.h>  // for puts()
#include <stdlib.h> // for EXIT_SUCCESS, srand, etc.
#include <sys/time.h> // for gettimeofday, to seed our random number generator

int your_fcn()
{
    /*
     * You must write THREE different versions of this function,
     * each of which result in you "winning" the impossible game.
     * This is the ONLY part of the file you are allowed to modify.
     */
    puts("You win!");
    exit(0);
}

int main()
{
    // Seed our random number generator
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srand(tv.tv_usec);

    // Get your guess
    int your_guess = your_fcn();

    // We'll guess at random
    int my_guess = rand();

    // Um.. nothing to see here..
    if(my_guess > your_guess)
        my_guess = your_guess - 1; // who are you calling a cheater?

    // Biggest guess wins
    if(your_guess > my_guess)
        puts("You lose!");
    else
        puts("You win!");

    return EXIT_SUCCESS;
}
