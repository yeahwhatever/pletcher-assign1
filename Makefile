CC = gcc

CFLAGS = -Wall -W -g -ansi -pedantic -Werror

LL = -lgcrypt

all: uoenc uodec

uoenc:
	$(CC) uocrypt.c uoenc.c $(LL) $(CFLAGS) -o uoenc

uodec:
	$(CC) uocrypt.c uodec.c $(LL) $(CFLAGS) -o uodec

clean:
	rm -rf *.o uoenc uodec
