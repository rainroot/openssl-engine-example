#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>

int sha512_init(EVP_MD_CTX *ctx)
{
    return SHA512_Init(ctx->md_data);
}

int sha512_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA512_Update(ctx->md_data, data, count);
}

int sha512_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA512_Final(md, ctx->md_data);
}
