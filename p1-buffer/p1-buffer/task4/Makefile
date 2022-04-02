CC = gcc
CFLAGS = -Wall -O0 -g -m32
NO_CANARY = -fno-stack-protector

EXPLOITS = exploit.x
VULNERABLE = vulnerable.x
EXECS = $(EXPLOITS) $(VULNERABLE)

all : $(EXECS) chown

nochown: $(EXPLOITS) $(VULNERABLE)

comms.o : comms.c comms.h
	$(CC) $(CFLAGS) $(NO_CANARY) -c -o $@ $<

chown: $(VULNERABLE)
	sudo chown root $^
	sudo chmod +s $^

vulnerable.x : vulnerable.c comms.o
	$(CC) $(CFLAGS) -no-pie -o $@ $^
# sudo chown root $@
# sudo chmod +s $@

# All the other executables have stack protector turned on
%.x : %.c
	$(CC) $(CFLAGS) -o $@ $<

clean : 
	rm -f $(EXECS) *.o

.PHONY: clean chown nochown
