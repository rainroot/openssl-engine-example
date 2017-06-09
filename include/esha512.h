#include <openssl/sha.h>

int sha512_init(EVP_MD_CTX *ctx);
int sha512_update(EVP_MD_CTX *ctx, const void *data, size_t count);
int sha512_final(EVP_MD_CTX *ctx, unsigned char *md);

