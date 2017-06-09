#include <openssl/sha.h>

int sha1_init(EVP_MD_CTX *ctx);
int sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count);
int sha1_final(EVP_MD_CTX *ctx, unsigned char *md);

