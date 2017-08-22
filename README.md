# CryptoSD
Encrypt files on an SD card

# Building

This section describes all requirements to successfully build CryptoSD.

Requirements:

* Docker
* Libsodium
  * Building for ARM: ARM compiled libsodium in `src/libsodium`
  * Building for local system: libsodium installed as system library

## Build CryptoSD binary

For cross compiling of the armv5 platform we use a docker container, which can be pulled with the following command:

```
docker pull multiarch/crossbuild
```

To compile CryptoSD for ARM, simply run:

```
docker run --rm -v $(pwd):/workdir -e CROSS_TRIPLE=arm-linux-gnueabi multiarch/crossbuild make crosscompile
```

To compile CryptoSD for local system, simply run:

```
make
```

# Description

This project includes a daemon which monitors if a new image has been taken, and if so it starts the encryption and after that the deletion process.
And it also contains the encryption module. The encryption module need a few command line parameters.
The encryption can be started with:
```
./cryptosd -e -i <path_to_input> -p <path_to_public_key>
```
The `-e` flag is responsible to put the program into encryption mode.

To decrypt a given file you can call:
```
./cryptosd -d -i <path_to_input> -p <path_to_public_key> -s <path_to_secret_key>
```
You can also find a key generator, which can easily generate key pairs.
Just compile it with the Makefile and run it without any parameters.

## How does the encryption work

During the encryption the program generates a random key, with which the file will be encrypted.
This key is then encrypted with the given public key and is stored at the end of the file.

For the decryption the used has to provide the key pair which has been used during the encryption.
The program then extracts the encrypted random key, decrypts it, and then it uses it to decrypt the file itself.

As well as the file- and the public-key-encryption uses the libsodium
implementation of the ChaCha20 stream cipher.
