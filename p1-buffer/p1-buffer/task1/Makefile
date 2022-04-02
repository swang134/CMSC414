CC = gcc
CFLAGS = -Wall -O0 -g -m32
NO_CANARY = -fno-stack-protector

EXPLOITS = exploit1.x exploit2.x exploit3.x exploit4.x
VULNERABLE = vulnerable1.x vulnerable2.x vulnerable3.x vulnerable4.x
EXECS = $(EXPLOITS) $(VULNERABLE)

all : $(EXECS) chown

nochown: $(EXPLOITS) $(VULNERABLE)

comms.o : comms.c comms.h
	$(CC) $(CFLAGS) $(NO_CANARY) -c -o $@ $<

chown: $(VULNERABLE)
	sudo chown root $^
	sudo chmod +s $^

vulnerable1.x : vulnerable1.c comms.o
	$(CC) $(CFLAGS) $(NO_CANARY) -o $@ $^
# sudo chown root $@
# sudo chmod +s $@

vulnerable2.x : vulnerable2.c comms.o
	$(CC) $(CFLAGS) $(NO_CANARY) -o $@ $^
# sudo chown root $@
# sudo chmod +s $@

vulnerable3.x : vulnerable3.c comms.o
	$(CC) $(CFLAGS) $(NO_CANARY) -o $@ $^
# sudo chown root $@
# sudo chmod +s $@

vulnerable4.x : vulnerable4.c comms.o
	$(CC) $(CFLAGS) $(NO_CANARY) -z execstack -o $@ $^
# sudo chown root $@
# sudo chmod +s $@

# All the other executables have stack protector turned on
%.x : %.c
	$(CC) $(CFLAGS) -o $@ $<

clean : 
	rm -f $(EXECS) *.o

.PHONY: clean chown nochown
