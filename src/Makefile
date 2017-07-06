CFLAGS=-lsodium
CROSSFLAGS=-I./libsodium_arm/include 

cryptosd.o: cryptosd.c
	gcc -o cryptosd.o cryptosd.c $(CFLAGS)

cryptosd_arm.o: cryptosd.c
	@cc -s -static -O3 -o cryptosd_arm.o $(CROSSFLAGS) cryptosd.c ./libsodium_arm/lib/libsodium.a

keygen.o: keygen.c
	gcc -o keygen.o keygen.c $(CFLAGS)

.PHONY: clean
clean:
	rm -f *.o
	rm -f user_pubkey user_seckey cam_pubkey cam_seckey
