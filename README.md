# CryptoSD
Encrypt files on an SD card

# Building

This section describes all requirements to sucessfully build CryptoSD.

Requiremed software:

* Docker

## Build CryptoSD binary

For crosscompiling of the armv5 platform we use a docker container, which can be pulled with the following command:

```
sudo docker pull multiarch/crossbuild
```

To compile CryptoSD, simply run:

```
docker run --rm -v $(pwd):/workdir -e CROSS_TRIPLE=arm-linux-gnueabi multiarch/crossbuild make crosscompile
```
