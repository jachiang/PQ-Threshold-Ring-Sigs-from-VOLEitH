# Additional Implementations

## AVX2

Instruction sets: AVX2, PCLMULQDQ, AES.
These are available on almost any x86-64 system nowadays.

## AVX2_VAES

Like AVX2, but with the addition of VPCLMULQDQ and VAES instruction sets.
These are available on fairly recent systems, including AMD Zen 3.

## TODO: AVX512??

Like AVX2_VAES, but also with AVX512 (or some subset) instruction sets.
Maybe GF2P8 as well.
Available on recent high-end Intel, as well as AMD Zen 4.
