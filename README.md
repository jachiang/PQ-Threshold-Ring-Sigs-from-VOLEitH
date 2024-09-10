# Platform Specific FAEST Implementation for x86-64 (With ISA Extensions) -- Modified for CCS Submission

## Versions

The major version number of the FAEST implementation matches the major version number of the FAEST specification it implements.
The implementation is currently at version 1.0.

## Compilation

Building requires GNU make.
Requires gcc 13.1.0 or higher
Do not forget to pull the submodules
To build all default settings, run `make -j<number_of_threads>`.
Note: it can take a long time to compile them all.
To build just a single setting, run `make -j<number_of_threads> <setting_name>`.
To build tests as well, run `make -j<number_of_threads> all-<setting_name>`.
The output will be in `Additional_Implementations/<setting_name>`.

## Settings

There are many different settings of the FAEST implementation, which are all compiled independently from each other.
Each setting is given a name: `sec<security_parameter>_<primitives>_<𝜏>_<w>_<seeds>_<platform_setting>`.

### Security Parameter

The security parameter can be 128, 192, or 256.

### Primitives

FAEST is built out of hashes, PRGs, and a OWF.
These can be set from the following options:
- c: AES in CTR mode.
- e: AES/Rijndael in Even–Mansour mode. Not available as a PRG for 192-bit security parameter.
- s: SHAKE. Only available for the leaves of the GGM tree.

Additionally for OWF, there are the following options:
- r3: Rain with 3 rounds.
- r4: Rain with 4 rounds.
- mq1: MQ over GF(2)
- mq8: MQ over GF(2^8)

There are 4 independent primitives that can be set from these options.
1. The one-way function that the signer proves knowledge of a preimage to.
2. The PRG used to expand the seeds used to generate the VOLE correlation.
3. The PRG used to expand the GGM tree.
4. The hash/PRG used to commit to the leaves of the GGM tree.

The letters for these 4 settings are concatenated together in the setting name.

### 𝜏

𝜏 is the number of bits that need to be sent in the signature for each bit of the witness.
Increasing 𝜏 gives faster but longer signatures.

### w

This is the number of bits of the third challenge to require to be 0, enforced by resampling the signature repeatedly until they are 0.
Increasing w makes sampling the third challenge more expensive to choose, but speeds up the rest of the signing algorithm.

### seeds

This is the maximum number of seeds to use when opening the all-but-τ vector commitment.
If more seeds are needed for the opening, the signer will instead resample the third challenge.
It can also be set to `pprf`, which means to use the older scheme based on puncturable-pseudorandom functions, which always uses the same number of seeds.

### Platform Settings

We plans for three sets of extensions that the implementation can use:

- AVX2: The AVX2, AES-NI, PCLMULQDQ, and BMI1 instruction set extensions.
- AVX2_VAES: The above, plus VAES and VPCLMULQDQ.
- AVX512: The above, plus AVX512F and AVX512BW.

Currently we have only implemented the AVX2 set.
