#include <stdio.h>     
#include <stdlib.h>
#include <time.h>
#include <sodium.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
unsigned char key[crypto_stream_chacha20_NONCEBYTES];
char *progName;

void printUsage(void);
void printError(char *msg, int doExit);

/**
 * The main function which performs the parsing of the CLAs and performs the decryption or the encryption.
 * @param argc The CLA counter
 * @param argv The CLA vector
 * @return 0 on success otherwise a number bigger than 0
 **/
int main (int argc, char **argv){
  progName = argv[0];
  int opt, j;
  int i=0;

  int dflag = 0;
  int eflag = 0;
  char *kpath = NULL;
  char *ipath = NULL;
  char *opath = NULL; 

  // parse parameters
  while((opt = getopt(argc, argv, "dek:i:")) != -1){
    switch(opt) {
      case 'd':
        dflag = 1;
        break;
      case 'e':
        eflag = 1;
        break;
      case 'k':
        kpath = optarg;
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
      default:
        printUsage();
    }
  }

  // check if every needed parameter has been provided
  if ((dflag && eflag) || !(dflag || eflag)){
    printError("Either -e or -d must be set but not both\n", 0);
    printUsage();
  }

  if (ipath == NULL){
    printError("-i is mandatory\n", 0);
    printUsage();
  }


  if (kpath == NULL){
    printError("-k is mandatory\n", 0);
    printUsage();
  }

  // read in key and input file
  FILE *kfd = fopen(kpath, "r");

  if (kfd == NULL){
    printError("Error during opening keyfile\n", 1);
  }

  // check if keyfile is valid regarding its size
  fseek(kfd, 0, SEEK_END);
  int kfSize = ftell(kfd);
  if(kfSize != crypto_secretbox_KEYBYTES){
    printError("This seems to be an invalid keyfile.\n", 1);
  }
  rewind(kfd);

  FILE *ifd = fopen(ipath, "r");

  if (ifd == NULL){
    printError("Error during opening keyfile\n", 1);
  }

  fseek(ifd, 0, SEEK_END);
  int ifSize = ftell(ifd);
  rewind(ifd);

  char *key = (char *)malloc(kfSize + 1);
  if(key == NULL){
    printError("Error during initializing key buffer\n", 1);
  }
  char *ifdBuffer = (char *)malloc(ifSize + 1);
  if(key == NULL){
    printError("Error during initializing input buffer\n", 1);
  }

  fread(key, kfSize, 1, kfd);
  fread(ifdBuffer, ifSize, 1, ifd);

  fclose(kfd);
  fclose(ifd);

  if(eflag){
    // do encryption
    // fill nonce and key with random data
    randombytes_buf(nonce, sizeof(nonce));

    crypto_stream_chacha20_xor(ifdBuffer, ifdBuffer, ifSize, nonce, key);

    FILE *ofd = fopen(opath, "w");

    if (ofd == NULL){
      printError("Error during opening keyfile\n", 2);
    }

    // write the encrypted stream to the outputfile
    if(fwrite(ifdBuffer, sizeof(char), ifSize, ofd) != ifSize){
      printError("An error occured during writing the encrypted file\n", 2);
    }

    fclose(ofd);

    ofd = fopen(opath, "a");

    if (ofd == NULL){
      printError("Error during opening keyfile\n", 1);
    }

    // write the used nonce to the end of the outputfile
    if(fwrite(nonce, sizeof(char), sizeof(nonce), ofd) != sizeof(nonce)){
      printError("An error occured during writing the encrypted file\n", 2);
    }

    fclose(ofd);
  } else{
    // do decryption
    // reading nonce
    j = 0;
    for(i = ifSize - sizeof(nonce); i < ifSize; i++){
      nonce[j++] = ifdBuffer[i];
    }

    crypto_stream_chacha20_xor(ifdBuffer, ifdBuffer, ifSize, nonce, key);
    FILE *ofd = fopen(opath, "w");

    if (ofd == NULL){
      printError("Error during opening keyfile\n", 2);
    }

    // write out the decrypted stream to the outputfile
    if(fwrite(ifdBuffer, sizeof(char), ifSize - sizeof(nonce), ofd) != ifSize - sizeof(nonce)){
      printError("An error occured during writing the decrypted file\n", 2);
    }

    fclose(ofd);
  }
  free(opath);
  free(key);
  free(ifdBuffer);

  return 0;
} 

/**
 * Pritns the usage and exits with 255.
 **/
void printUsage(void){
  fprintf(stderr, "Usage: %s -k <keyfile> -i <inputfile> -d|-e\n", progName);
  exit(255);
}

/**
 * Prints an error message to sdterr and exists with the given exitcode
 * if it is not 0.
 * @param msg the error message
 * @param doExit the exitcode to be used
 **/
void printError(char *msg, int doExit){
  fprintf(stderr, msg);
  if(doExit){
    exit(doExit);
  }
}
