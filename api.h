#define CRYPTO_SECRETKEYBYTES FAEST_SECRET_KEY_BYTES
#define CRYPTO_PUBLICKEYBYTES FAEST_PUBLIC_KEY_BYTES
#define CRYPTO_BYTES FAEST_SIGNATURE_BYTES

#define CRYPTO_ALGNAME "FAEST" // TODO: settings

// TODO: need to build this file automatically, once for each setting.

int crypto_sign_keypair(unsigned char* pk, unsigned char* sk);
int crypto_sign(
	unsigned char *sm, unsigned long long *smlen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk);
int crypto_sign_open(
	unsigned char *m, unsigned long long *mlen,
	const unsigned char *sm, unsigned long long smlen,
	const unsigned char *pk);
