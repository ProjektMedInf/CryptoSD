/**
 * @file cryptosd.c
 * @author stiefel40k
 * @date 21.06.2017
 *
 * @brief main module of the CryptoSd project
 * TODO: Generate random key for every file, and encrypt it with a public key --> dump the encrypted key to the end of the file
 * 
 **/
#include <stdio.h>     
#include <stdlib.h>
#include <time.h>
#include <sodium.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <syslog.h>

/**
 * Pritns the usage and exits with 255.
 * @param progName name of the program (argv[0])
 **/
void printUsage(char *progName);

/**
 * Checks if the file has a valid length
 * @param keyFile pointer to the FILE object
 * @param keyType what kind of keyfile it is. (used only for logging)
 * @param validLength the expected length of the file
 * @return the length of the file on success otherwise it terminates the program
 **/
int checkKeyFile(FILE *keyFile, char *keyType, int validLength);

/**
 * The main function which performs the parsing of the CLAs and performs the decryption or the encryption.
 * @param argc The CLA counter
 * @param argv The CLA vector
 * @return 0 on success otherwise a number bigger than 0
 **/
int main (int argc, char **argv){
  unsigned char nonce[crypto_stream_chacha20_NONCEBYTES] = {};
  unsigned char key[crypto_stream_chacha20_KEYBYTES] = {};
  unsigned char encryptedKey[sizeof(key) + crypto_box_SEALBYTES];
  char *progName = argv[0];
  int opt, j;
  int i=0;

  int dflag = 0;
  int eflag = 0;
  char *ipath = NULL;
  char *opath = NULL; 
  char *ppath = NULL;
  char *spath = NULL; 

  // parse parameters
  while((opt = getopt(argc, argv, "dek:i:s:p:")) != -1){
    switch(opt) {
      case 'd':
        dflag = 1;
        break;
      case 'e':
        eflag = 1;
        break;
      case 'i':
        ipath = optarg;
        opath = malloc(sizeof(char) * strlen(ipath) + 5);
        memset(opath, '\0', strlen(ipath) + 1);
        while(*ipath != '\0'){
          opath[i++] = *ipath++;
        }
        ipath = optarg;
        strcat(opath, ".out");
        break;
      case 'p':
        ppath = optarg;
        break;
      case 's':
        spath = optarg;
        break;
      default:
        printUsage(progName);
    }
  }

  // check if every needed parameter has been provided
  if ((dflag && eflag) || !(dflag || eflag)){
    syslog(LOG_ERR, "Either -e or -d must be set but not both \n");
    printUsage(progName);
    exit(255);
  }

  if (ipath == NULL){
    syslog(LOG_ERR, "-i is mandatory\n");
    printUsage(progName);
    exit(255);
  }


  if (ppath == NULL){
    syslog(LOG_ERR, "-p is mandatory\n");
    exit(255);
  }

  // read in key and input file
  FILE *pfd = fopen(ppath, "r");

  if (pfd == NULL){
    syslog(LOG_ERR, "Error during opening publickeyfile\n");
    exit(1);
  }

  // check if publickeyfile is valid regarding its size
  int pfSize = checkKeyFile(pfd, "publickeyfile", crypto_box_PUBLICKEYBYTES);

  FILE *ifd = fopen(ipath, "r");

  if (ifd == NULL){
    syslog(LOG_ERR, "Error during opening inputfile.\n");
    exit(1);
  }

  fseek(ifd, 0, SEEK_END);
  int ifSize = ftell(ifd);
  rewind(ifd);

  unsigned char *publickey = (char *)malloc(pfSize);
  if(publickey == NULL){
    syslog(LOG_ERR, "Error during initializing secretkey buffer\n");
    exit(1);
  }

  unsigned char *ifdBuffer = (char *)malloc(ifSize);
  if(ifdBuffer == NULL){
    syslog(LOG_ERR, "Error during initializing input buffer.\n");
    exit(1);
  }

  fread(publickey, pfSize, 1, pfd);
  fread(ifdBuffer, ifSize, 1, ifd);

  fclose(pfd);
  fclose(ifd);

  if(eflag){
    // do encryption
    // fill nonce and key with random data
    randombytes_buf(nonce, sizeof(nonce));
    randombytes_buf(key, sizeof(key));

    if(crypto_box_seal(encryptedKey, key, sizeof(key), publickey) != 0){
      syslog(LOG_ERR, "Error during encrypting the encryption key\n");
      exit(2);
    }

    crypto_stream_chacha20_xor(ifdBuffer, ifdBuffer, ifSize, nonce, key);

    FILE *ofd = fopen(opath, "w");

    if (ofd == NULL){
      syslog(LOG_ERR, "Error during opening outputfile. (Write)\n");
      exit(2);
    }

    // write the encrypted stream to the outputfile
    if(fwrite(ifdBuffer, sizeof(char), ifSize, ofd) != ifSize){
      syslog(LOG_ERR, "An error occured during writing the encrypted file.\n");
      exit(2);
    }

    if(fsync(fileno(ofd)) == -1){
      syslog(LOG_ERR, "An error occured during flushing the encrypted file.\n");
      exit(2);
    }

    fclose(ofd);

    ofd = fopen(opath, "a");

    if (ofd == NULL){
      syslog(LOG_ERR, "Error during opening outputfile. (Append)\n");
      exit(2);
    }

    // write the used key in encrypted form to the end of the outputfile
    if(fwrite(encryptedKey, sizeof(char), sizeof(encryptedKey), ofd) != sizeof(encryptedKey)){
      syslog(LOG_ERR, "An error occured during writing the used key to the encrypted file\n");
      exit(2);
    }

    // write the used nonce to the end of the outputfile
    if(fwrite(nonce, sizeof(char), sizeof(nonce), ofd) != sizeof(nonce)){
      syslog(LOG_ERR, "An error occured during writing the used nonce to the encrypted file\n");
      exit(2);
    }

    if(fsync(fileno(ofd)) == -1){
      syslog(LOG_ERR, "An error occured during flushing the encrypted file with the nonce\n");
      exit(2);
    }

    fclose(ofd);
  } else{

    if (spath == NULL){
      syslog(LOG_ERR, "-s is mandatory in case of decryption mode\n");
      exit(255);
    }

    FILE *sfd = fopen(spath, "r");

    if (sfd == NULL){
      syslog(LOG_ERR, "Error during opening secretkeyfile\n");
      exit(1);
    }

    // check if secretkeyfile is valid regarding its size
    int sfSize = checkKeyFile(sfd, "secretkeyfile", crypto_box_SECRETKEYBYTES);

    unsigned char *secretkey = (char *)malloc(sfSize);
    if(secretkey == NULL){
      syslog(LOG_ERR, "Error during initializing publickey buffer\n");
      exit(1);
    }

    fread(secretkey, sfSize, 1, sfd);

    fclose(sfd);

    // do decryption
    // reading nonce
    j = 0;
    for(i = ifSize - sizeof(nonce); i < ifSize; i++){
      nonce[j++] = ifdBuffer[i];
    }

    // reading encrypted key
    j = 0;
    for(i = ifSize - sizeof(encryptedKey) - sizeof(nonce); i < ifSize - sizeof(nonce); i++){
      encryptedKey[j++] = ifdBuffer[i];
    }

    if(crypto_box_seal_open(key, encryptedKey, sizeof(encryptedKey), publickey, secretkey) != 0){
      syslog(LOG_ERR, "Error during decrypting the encryption key\n");
      exit(2);
    }

    crypto_stream_chacha20_xor(ifdBuffer, ifdBuffer, ifSize - sizeof(encryptedKey) - sizeof(nonce), nonce, key);
    FILE *ofd = fopen(opath, "w");

    if (ofd == NULL){
      syslog(LOG_ERR, "Error during opening outputfile.\n");
      exit(2);
    }

    // write out the decrypted stream to the outputfile
    if(fwrite(ifdBuffer, sizeof(char), ifSize - sizeof(encryptedKey) - sizeof(nonce), ofd) != ifSize - sizeof(encryptedKey) - sizeof(nonce)){
      syslog(LOG_ERR, "An error occured during writing the decrypted file.\n");
      exit(2);
    }

    fclose(ofd);

    free(secretkey);
  }
  free(opath);
  free(publickey);
  free(ifdBuffer);

  return 0;
} 

void printUsage(char *progName){
  fprintf(stderr, "Usage: %s -s <secretkeyfile> -p <publickeyfile> -i <inputfile> -d|-e\n", progName);
  exit(255);
}

int checkKeyFile(FILE *keyFile, char *keyType, int validLength){
  fseek(keyFile, 0, SEEK_END);
  int fSize = ftell(keyFile);
  if(fSize != validLength){
    fprintf(stderr, "Checking %s failed.", keyType);
    syslog(LOG_ERR, "This seems to be an invalid keyfile.\n");
  }
  rewind(keyFile);
  return fSize;
}
