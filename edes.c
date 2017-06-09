#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>

int des_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	if(iv){}
	if(enc){}
    fprintf(stderr, "(ENGINE_OPENSSL_DES) des_init_key() called\n");

    DES_cblock *deskey = (DES_cblock *)key;
    EOPENSSL_DES_KEY *dat = (EOPENSSL_DES_KEY *) ctx->cipher_data;

    dat->stream.cbc = NULL;

#ifdef EVP_CHECK_DES_KEY
    if (DES_set_key_checked(deskey, dat->ks.ks) != 0)
        return 0;
#else
    DES_set_key_unchecked(deskey, ctx->cipher_data);
#endif
    return 1;
}

int des_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    fprintf(stderr, "(ENGINE_OPENSSL_DES) des_cipher() called\n");

    EOPENSSL_DES_KEY *dat = (EOPENSSL_DES_KEY *) ctx->cipher_data;

    if (dat->stream.cbc != NULL) {
        (*dat->stream.cbc) (in, out, inl, &dat->ks.ks, ctx->iv);
        return 1;
    }
    while (inl >= EVP_MAXCHUNK) {
        DES_ncbc_encrypt(in, out, (long)EVP_MAXCHUNK, ctx->cipher_data,
                         (DES_cblock *)ctx->iv, ctx->encrypt);
        inl -= EVP_MAXCHUNK;
        in += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }
    if (inl)
        DES_ncbc_encrypt(in, out, (long)inl, ctx->cipher_data,
                         (DES_cblock *)ctx->iv, ctx->encrypt);

    return 1;
}
