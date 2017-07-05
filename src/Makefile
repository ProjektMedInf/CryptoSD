CFLAGS=-lsodium
CROSSFLAGS=-I./libsodium/include 

cryptosd: cryptosd.c
	gcc -o cryptosd.o cryptosd.c $(CFLAGS)

crosscompile: cryptosd.c
	@cc -s -static -O3 -o cryptosd.o $(CROSSFLAGS) cryptosd.c ./libsodium/lib/libsodium.a

.PHONY: clean
clean:
	rm -f *.o
