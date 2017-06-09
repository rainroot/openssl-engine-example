#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>


int seed_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	if(iv){}
	if(enc){}
    fprintf(stderr, "(ENGINE_OPENSSL_SEED) seed_init_key() called\n");

    SEED_set_key(key, ctx->cipher_data);
    return 1;
}

int seed_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    fprintf(stderr, "(ENGINE_OPENSSL_SEED) seed_ecb_cipher() called\n");

    EOPENSSL_SEED_KEY *dat = (EOPENSSL_SEED_KEY *) ctx->cipher_data;
    size_t i, bl;

    bl = ctx->cipher->block_size;

    if(inl < bl)
        return 1;

    inl -= bl;

    for(i=0; i <= inl; i+=bl)
        SEED_ecb_encrypt(in + i, out + i, &dat->ks, ctx->encrypt);

    return 1;
}

int seed_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    fprintf(stderr, "(ENGINE_OPENSSL_SEED) seed_cbc_cipher() called\n");

    EOPENSSL_SEED_KEY *dat = (EOPENSSL_SEED_KEY *) ctx->cipher_data;

    while(inl>=EVP_MAXCHUNK)
    {
        SEED_cbc_encrypt(in, out, (long)EVP_MAXCHUNK, &dat->ks, ctx->iv, ctx->encrypt);
        inl-=EVP_MAXCHUNK;
        in +=EVP_MAXCHUNK;
        out+=EVP_MAXCHUNK;
    }
    if (inl)
        SEED_cbc_encrypt(in, out, (long)inl, &dat->ks, ctx->iv, ctx->encrypt);

     return 1;
}

