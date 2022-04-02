#include "comms.h"

#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/errno.h>

static int g_child_in;
static int g_child_out;

void exec_exploit(const char *exploit) {
	int filedes[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, filedes) < 0) {
		fprintf(stderr, "Could not create pipe: %s\n", strerror(errno));
		abort();
	}

	int pid = fork();
	if (pid == 0) {
		/* child process */

		/* drop privileges */
		if (setgid(getgid()) == -1) {
			fprintf(stderr, "Could not setgid: %s\n", strerror(errno));
		}

		if (setuid(getuid()) == -1) {
			fprintf(stderr, "Could not gsetuid: %s\n", strerror(errno));
		}

		/* redirect child stdin, stdout to parent */
		if ((dup2(filedes[0], STDIN_FILENO) < 0) ||
		    dup2(filedes[0], STDOUT_FILENO) < 0) {
			fprintf(stderr, "dup2 failed: (%d,%d) %s\n", filedes[0], filedes[1], strerror(errno));
			abort();
		}
		close(filedes[0]);
		close(filedes[1]);

		/* do exec */
		execlp(exploit, exploit, NULL);
		fprintf(stderr, "exec failed: %s\n", strerror(errno));
		abort();
		exit(0);

	} else if (pid > 0) {
		/* parent process */
		g_child_in = filedes[1];
		g_child_out = filedes[1];

		close(filedes[0]);

		int flags = fcntl(g_child_in, F_GETFL, 0);
		if (flags == -1 ||
		    fcntl(g_child_in, F_SETFL, flags | O_NONBLOCK) == -1) {
			fprintf(stderr, "couldn't fcntl: %s\n", strerror(errno));
			abort();
		}

	} else {
		fprintf(stderr, "Error forking: %s\n", strerror(errno));
		abort();
	}
}

int read_from_exploit(char *msg, size_t sz) {
	/* see if child_in is ready to read, if so go ahead and read
	 * it. anything under 4k (so long as they use write) is atomic */

	fd_set set;
	do {
		FD_ZERO(&set);
		FD_SET(g_child_in, &set);

		int ret = select(g_child_in+1, &set, NULL, NULL, NULL);
		if (ret == -1) {
			fprintf(stderr, "bad select: %s\n", strerror(errno));
			abort();
		}
	} while(!FD_ISSET(g_child_in, &set));

	ssize_t res = read(g_child_in, msg, sz);

	if (res < 0) {
		fprintf(stderr, "read failed: %s\n", strerror(errno));
		abort();
	}
	return (int) res;
}

int write_to_exploit(char *fmt, ...) {


	char str[512];
	va_list args;
	va_start(args, fmt);
	int to_write = vsnprintf(str, sizeof(str), fmt, args);
	va_end(args);
	if (to_write > sizeof(str)) {
		to_write = sizeof(str);
	}

	if (to_write < 0) {
		fprintf(stderr, "goofed up vsnprintf: %s\n", strerror(errno));
		abort();
	}
	
	ssize_t res = write(g_child_out, str, (size_t)to_write);
	if (res < 0) {
		fprintf(stderr, "write failed: %s\n", strerror(errno));
		abort();
	}
	return (int) res;
}
