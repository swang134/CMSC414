CC = gcc
CFLAGS = -m32 -Wall -g -z execstack -fno-stack-protector

all : task0a.x task0b.x task0c.x

%.x : %.c
	$(CC) $(CFLAGS) -o $@ $<

clean :
	rm -f task0a.x task0b.x task0c.x
