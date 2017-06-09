#include <openssl/des.h>

#define EOPENSSL_DES_KEY_SIZE   8

typedef struct {
    union {
        double align;
        DES_key_schedule ks;
    } ks;
    union {
        void (*cbc) (const void *, void *, size_t,
                    const DES_key_schedule *, unsigned char *);
    } stream;
} EOPENSSL_DES_KEY;

int des_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int des_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
