#include <openssl/aes.h>


int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int aes_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t len);
int aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t len);


typedef struct {
    union {
        double align;
        AES_KEY ks;
    } ks;
    block128_f block;
    union {
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;
} EOPENSSL_AES_KEY;

#  define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER aes_##keylen##_##mode = { \
        nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        aes_init_key,                   \
        aes_##mode##_cipher,            \
        NULL,                           \
        sizeof(EOPENSSL_AES_KEY),            \
        NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_aes_##keylen##_##mode(void) \
{ return &aes_##keylen##_##mode; }

# define BLOCK_CIPHER_generic_pack(nid,keylen,flags)             \
        BLOCK_CIPHER_generic(nid,keylen,16,16,cbc,cbc,CBC,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)     \
        BLOCK_CIPHER_generic(nid,keylen,16,0,ecb,ecb,ECB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)      \
        BLOCK_CIPHER_generic(nid,keylen,1,16,ofb128,ofb,OFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)   \
        BLOCK_CIPHER_generic(nid,keylen,1,16,cfb128,cfb,CFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)   \
        BLOCK_CIPHER_generic(nid,keylen,1,16,cfb1,cfb1,CFB,flags)       \
        BLOCK_CIPHER_generic(nid,keylen,1,16,cfb8,cfb8,CFB,flags)       \
        BLOCK_CIPHER_generic(nid,keylen,1,16,ctr,ctr,CTR,flags)


