# Threshold Ring Signature Applications from VOLE-in-the-Head

## Description

This repository extends the VOLE-in-the-Head framework of [FAEST](https://github.com/faest-sign/faest-avx)
to implement standalone and linkable ring signatures from VOLEitH and AES encryption. We add
support for higher degree quicksilver polynomials, disjunctions over large rings and support for
multi-block public key and tag functions.

## Requirements
Requires
* Support for Intel AVX2 instructions
* GNU make
* gcc 13.1.0 or higher

## Submodules
Pull the submodules
```
git submodule init
git submodule update
```

## Optional Build Environment
We provide a docker file `DockerfileDevEnv` for convenience.

To initialize the docker build
```
(sudo) docker build -t example/instance -f DockerfileDevEnv .
```
To run the docker instance subsequently
```
(sudo) docker run -it --rm --name=example --mount type=bind,source=${PWD},target=/src example/instance bash
```
Run `cd src` to find the repository mounted in the docker instance.

## Compilation

To build and run benchmarks
```
./makeRunTests.sh
```
The compilation script calls the underlying build system with supported parameters.
It can be modified for different thread settings by modifying the `make -j<number_of_threads>`
parameters. The script builds standalone ring signature and linkable ring signatures for security levels 128, 192 and 256. Ring signatures are compiled with AES & AES-EM. linkable ring signatures are compiled with AES.

Note: The VOLEitH parameters hardcoded in `makeRunTests.sh` are based on settings proposed in [BBM+24](https://eprint.iacr.org/2024/490.pdf). We highlight τ and T as the tree repetition factor and internal node threshold respectively which drive the proof size.

| Security |  τ |  w |  T  |
|:--------:|:--:|:--:|:---:|
|    128   | 11 |  7 | 102 |
|    192   | 16 | 12 | 162 |
|    256   | 22 |  6 | 245 |


## Ring Settings
The ring size and 1-hotvector dimension for the
OR proof are user-defined in
`config.h.in`.

* The ring size is expressed in powers of 2
`FAEST_RING_2_POW` (L32).
* The 1-hotvector dimension `FAEST_RING_HOTVECTOR_DIM` (L33) must divide the ring power.