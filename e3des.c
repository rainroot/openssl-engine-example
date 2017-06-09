#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>

int des_ede3_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	if(iv){}
	if(enc){}
    fprintf(stderr, "(ENGINE_OPENSSL_DES3) eopenssl_des_ede3_init_key() called\n");

    DES_cblock *deskey = (DES_cblock *)key;
    EOPENSSL_DES_EDE_KEY *dat = eopenssl_des3(ctx);

    dat->stream.cbc = NULL;

# ifdef EVP_CHECK_DES_KEY
    if (DES_set_key_checked(&deskey[0], &dat->ks1)
        || DES_set_key_checked(&deskey[1], &dat->ks2)
        || DES_set_key_checked(&deskey[2], &dat->ks3))
        return 0;
# else
    DES_set_key_unchecked(&deskey[0], &dat->ks1);
    DES_set_key_unchecked(&deskey[1], &dat->ks2);
    DES_set_key_unchecked(&deskey[2], &dat->ks3);
# endif

    return 1;
}

int des_ede_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    fprintf(stderr, "(ENGINE_OPENSSL_DES3) des_ede_cbc_cipher() called\n");

    EOPENSSL_DES_EDE_KEY *dat = eopenssl_des3(ctx);

    if (dat->stream.cbc) {
        (*dat->stream.cbc) (in, out, inl, dat->ks.ks, ctx->iv);
        return 1;
    }

    while (inl >= EVP_MAXCHUNK) {
        DES_ede3_cbc_encrypt(in, out, (long)EVP_MAXCHUNK,
                            &dat->ks1, &dat->ks2, &dat->ks3,
                            (DES_cblock *)ctx->iv, ctx->encrypt);
        inl -= EVP_MAXCHUNK;
        in += EVP_MAXCHUNK;
        out += EVP_MAXCHUNK;
    }
    if (inl)
        DES_ede3_cbc_encrypt(in, out, (long)inl, &dat->ks1, &dat->ks2, &dat->ks3, (DES_cblock *)ctx->iv, ctx->encrypt);

    return 1;
}
