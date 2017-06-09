#include <openssl/des.h>

typedef struct {
    union {
        double align;
        DES_key_schedule ks[3];
    } ks;
    union {
        void (*cbc) (const void *, void *, size_t,
                     const DES_key_schedule *, unsigned char *);
    } stream;
} EOPENSSL_DES_EDE_KEY;

# define ks1 ks.ks[0]
# define ks2 ks.ks[1]
# define ks3 ks.ks[2]

# define eopenssl_des3(ctx) ((EOPENSSL_DES_EDE_KEY *)(ctx)->cipher_data)

int des_ede3_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int des_ede_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

