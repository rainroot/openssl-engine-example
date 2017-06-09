#include <openssl/rc4.h>

#define EOPENSSL_RC4_KEY_SIZE   16

typedef struct {
    unsigned char key[EOPENSSL_RC4_KEY_SIZE];
    RC4_KEY ks;
} EOPENSSL_RC4_KEY;

#define eopenssl_rc4(ctx) ((EOPENSSL_RC4_KEY *)(ctx)->cipher_data)

int rc4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int rc4_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

