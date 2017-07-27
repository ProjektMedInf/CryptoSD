#include <sodium.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv){
  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES];

  printf("Starting to generate public and private keys\n");
  crypto_box_keypair(pk, sk);

  FILE *pubkey = fopen("user_pubkey", "w");
  FILE *seckey = fopen("user_seckey", "w");

  fwrite(pk, sizeof(char), sizeof(pk), pubkey);
  fwrite(sk, sizeof(char), sizeof(sk), seckey);

  fclose(pubkey);
  fclose(seckey);

  printf("Keygeneration is done\n");

  return 0;
}
