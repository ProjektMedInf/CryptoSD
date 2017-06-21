CFLAGS=-lsodium
CROSSFLAGS=-I./libsodium/include 

cryptosd: cryptosd.c
	gcc -o cryptosd $(CFLAGS) cryptosd.c

crosscompile: cryptosd.c
	@cc -s -static -O3 -o cryptosd $(CROSSFLAGS) cryptosd.c ./libsodium/lib/libsodium.a

.PHONY: clean
clean:
	rm -f cryptosd
