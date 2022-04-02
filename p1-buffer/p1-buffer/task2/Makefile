CC = gcc
CFLAGS = -Wall -O3

EXECS = rop-finder

all: $(EXECS)

rop-finder: rop-finder.x

%.x : %.c
	$(CC) $(CFLAGS) -o $@ $<

clean : 
	rm -f $(EXECS) *.o

.PHONY: clean all $(EXECS)
