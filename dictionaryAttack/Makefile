CC = gcc
CFLAGS = -Wall -std=c99 -g -fPIE
LDFLAGS = -pie

crack: crack.o password.o md5.o block.o magic.o
	$(CC) $(LDFLAGS) -o crack crack.o password.o md5.o block.o magic.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o crack