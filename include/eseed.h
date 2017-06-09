#include <openssl/seed.h>

typedef struct {
	SEED_KEY_SCHEDULE ks;
} EOPENSSL_SEED_KEY;

int seed_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int seed_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int seed_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

