#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>

int sha256_init(EVP_MD_CTX *ctx)
{
    return SHA256_Init(ctx->md_data);
}

int sha256_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA256_Update(ctx->md_data, data, count);
}

int sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA256_Final(md, ctx->md_data);
}
