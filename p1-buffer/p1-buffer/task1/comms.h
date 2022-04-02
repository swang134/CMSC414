#ifndef COMMS_H
#define COMMS_H

#include <sys/types.h>

/* execute specified exploit program with reduced privileges */
void exec_exploit(const char *exploit);

/* read from exploit stdout up to sz bytes. Return number of bytes
 * read */
int read_from_exploit(char *msg, size_t sz);

/* write to exploit with same signature as printf */
int write_to_exploit(char *fmt, ...);

#endif
