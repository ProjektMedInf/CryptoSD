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

## Daemon

The deamon can be started without any parameters.
It looks for the key at `/mnt/sd/key` and looks for the cryptosd executable at `/et/cryptosd`.

There are two implementations of the daemon.
One is using the `inotify` library call, however, this was the early version of the daemon, and is not complete at all.
The other version is currently the functioning one, and it runs without using the `inotify` library call.

It would have been nicer with `inotify`, however the Linux running on the SD-Card doesn't see the new pictures until the whole partition has not been remounted.
And as we have to remount the whole partition it doesn't pay out to use `inotify`.

As the Linux doesn't see the new images there is a second big issue.
If you happen to make a picture during the encryption, both of the images are going to be overwritten, and somehow you lose both of them.
Don't ask me why, I don't get it either...
So one should wait 1 or 2 minutes (or more depending on the quality) between taking photos.
Sorry about that. :)
