#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>

int sha1_init(EVP_MD_CTX *ctx)
{
    return SHA1_Init(ctx->md_data);
}

int sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return SHA1_Update(ctx->md_data, data, count);
}

int sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return SHA1_Final(md, ctx->md_data);
}
