CC=gcc
CFLAGS=-c -g -Wall

all: aesStefanCouture

aesStefanCouture: aesStefanCouture.o
	$(CC) aesStefanCouture.o -o aesStefanCouture

aesStefanCouture.o: aesStefanCouture.c aesStefanCouture.h
	$(CC) $(CFLAGS) aesStefanCouture.c

clean:
	rm -rf *.o aesStefanCouture

