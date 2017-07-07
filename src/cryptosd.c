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

/**
 * Pritns the usage and exits with 255.
 * @param progName name of the program (argv[0])
 **/
void printUsage(char *progName);

/**
 * Prints an error message to sdterr and exists with the given exitcode
 * if it is not 0.
 * @param msg the error message
 * @param doExit the exitcode to be used
 **/
void printError(char *msg, int doExit);

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
  unsigned char iHaveNoFuckingClueWhyINeedThisHereButThisMustBeTheFirstVariable[crypto_box_PUBLICKEYBYTES];

  unsigned char nonce[crypto_stream_chacha20_NONCEBYTES] = {};
  unsigned char key[crypto_stream_chacha20_KEYBYTES] = {};
  unsigned char encryptedKey[sizeof(key) + crypto_box_MACBYTES];
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
    printError("Either -e or -d must be set but not both\n", 0);
    printUsage(progName);
  }

  if (ipath == NULL){
    printError("-i is mandatory\n", 0);
    printUsage(progName);
  }


  if (spath == NULL){
    printError("-s is mandatory\n", 0);
    printUsage(progName);
  }

  if (ppath == NULL){
    printError("-p is mandatory\n", 0);
    printUsage(progName);
  }

  // read in key and input file
  FILE *sfd = fopen(spath, "r");

  if (sfd == NULL){
    printError("Error during opening secertkeyfile\n", 1);
  }

  // check if secretkeyfile is valid regarding its size
  int sfSize = checkKeyFile(sfd, "secretkeyfile", crypto_box_SECRETKEYBYTES);

  FILE *pfd = fopen(ppath, "r");

  if (pfd == NULL){
    printError("Error during opening publickeyfile\n", 1);
  }

  // check if publickeyfile is valid regarding its size
  int pfSize = checkKeyFile(pfd, "publickeyfile", crypto_box_PUBLICKEYBYTES);

  FILE *ifd = fopen(ipath, "r");

  if (ifd == NULL){
    printError("Error during opening inputfile\n", 1);
  }

  fseek(ifd, 0, SEEK_END);
  int ifSize = ftell(ifd);
  rewind(ifd);

  unsigned char *publickey = (char *)malloc(pfSize);
  if(publickey == NULL){
    printError("Error during initializing secretkey buffer\n", 1);
  }

  unsigned char *secretkey = (char *)malloc(sfSize);
  if(secretkey == NULL){
    printError("Error during initializing publickey buffer\n", 1);
  }

  unsigned char *ifdBuffer = (char *)malloc(ifSize);
  if(ifdBuffer == NULL){
    printError("Error during initializing input buffer\n", 1);
  }

  fread(publickey, pfSize, 1, pfd);
  fread(secretkey, sfSize, 1, sfd);
  fread(ifdBuffer, ifSize, 1, ifd);

  fclose(sfd);
  fclose(pfd);
  fclose(ifd);

  if(eflag){
    // do encryption
    // fill nonce and key with random data
    randombytes_buf(nonce, sizeof(nonce));
    randombytes_buf(key, sizeof(key));

    if(crypto_box_easy(encryptedKey, key, sizeof(key), nonce, publickey, secretkey) != 0){
      printError("Error during encrypting the encryption key\n", 2);
    }

    crypto_stream_chacha20_xor(ifdBuffer, ifdBuffer, ifSize, nonce, key);

    FILE *ofd = fopen(opath, "w");

    if (ofd == NULL){
      printError("Error during opening keyfile\n", 2);
    }

    // write the encrypted stream to the outputfile
    if(fwrite(ifdBuffer, sizeof(char), ifSize, ofd) != ifSize){
      printError("An error occured during writing the encrypted file\n", 2);
    }

    if(fsync(fileno(ofd)) == -1){
      printError("An error occured during flushing the encrypted file\n", 0);
    }

    fclose(ofd);

    ofd = fopen(opath, "a");

    if (ofd == NULL){
      printError("Error during opening keyfile\n", 1);
    }

    // write the used key in encrypted form to the end of the outputfile
    if(fwrite(encryptedKey, sizeof(char), sizeof(encryptedKey), ofd) != sizeof(encryptedKey)){
      printError("An error occured during writing the used key to the encrypted file\n", 2);
    }

    // write the used nonce to the end of the outputfile
    if(fwrite(nonce, sizeof(char), sizeof(nonce), ofd) != sizeof(nonce)){
      printError("An error occured during writing the used nonce to the encrypted file\n", 2);
    }

    if(fsync(fileno(ofd)) == -1){
      printError("An error occured during flushing the encrypted file with the nonce\n", 0);
    }

    fclose(ofd);
  } else{
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

    if(crypto_box_open_easy(key, encryptedKey, sizeof(encryptedKey), nonce, publickey, secretkey) != 0){
      printError("Error during decrypting the encryption key\n", 2);
    }

    crypto_stream_chacha20_xor(ifdBuffer, ifdBuffer, ifSize - sizeof(encryptedKey) - sizeof(nonce), nonce, key);
    FILE *ofd = fopen(opath, "w");

    if (ofd == NULL){
      printError("Error during opening outputfile\n", 2);
    }

    // write out the decrypted stream to the outputfile
    if(fwrite(ifdBuffer, sizeof(char), ifSize - sizeof(encryptedKey) - sizeof(nonce), ofd) != ifSize - sizeof(encryptedKey) - sizeof(nonce)){
      printError("An error occured during writing the decrypted file\n", 2);
    }

    fclose(ofd);
  }
  free(opath);
  free(secretkey);
  free(publickey);
  free(ifdBuffer);

  return 0;
} 

void printUsage(char *progName){
  fprintf(stderr, "Usage: %s -s <secretkeyfile> -p <publickeyfile> -i <inputfile> -d|-e\n", progName);
  exit(255);
}

void printError(char *msg, int doExit){
  fprintf(stderr, msg);
  if(doExit){
    exit(doExit);
  }
}

int checkKeyFile(FILE *keyFile, char *keyType, int validLength){
  fseek(keyFile, 0, SEEK_END);
  int fSize = ftell(keyFile);
  if(fSize != validLength){
    fprintf(stderr, "Checking %s failed.", keyType);
    printError("This seems to be an invalid keyfile.\n", 1);
  }
  rewind(keyFile);
  return fSize;
}
