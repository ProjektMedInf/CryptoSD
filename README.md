# CryptoSD
Encrypt files on an SD card

# Building

This section describes all requirements to sucessfully build CryptoSD.

Requirements:

* Docker
* Libsodium
  * Building for ARM: ARM compiled libsodium in `src/libsodium`
  * Building for local system: libsodium installed as system library

## Build CryptoSD binary

For crosscompiling of the armv5 platform we use a docker container, which can be pulled with the following command:

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
