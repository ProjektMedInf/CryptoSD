#include <sodium.h>
#include <stdlib.h>
#include <stdio.h>

#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 4
#define CIPHERTEXT_LEN (crypto_box_MACBYTES + MESSAGE_LEN)

int main(int argc, char **argv){
  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES];
  unsigned char cam_pk[crypto_box_PUBLICKEYBYTES];
  unsigned char cam_sk[crypto_box_SECRETKEYBYTES];

  printf("Starting to generate public and private keys for the camera and the user\n");
  crypto_box_keypair(pk, sk);
  crypto_box_keypair(cam_pk, cam_sk);

  FILE *pubkey = fopen("user_pubkey", "w");
  FILE *seckey = fopen("user_seckey", "w");
  FILE *cam_pubkey = fopen("cam_pubkey", "w");
  FILE *cam_seckey = fopen("cam_seckey", "w");

  fwrite(pk, sizeof(char), sizeof(pk), pubkey);
  fwrite(sk, sizeof(char), sizeof(sk), seckey);
  fwrite(cam_pk, sizeof(char), sizeof(cam_pk), cam_pubkey);
  fwrite(cam_sk, sizeof(char), sizeof(cam_sk), cam_seckey);

  fclose(pubkey);
  fclose(seckey);
  fclose(cam_pubkey);
  fclose(cam_seckey);

  printf("Keygeneration is done\n");

  return 0;
}
