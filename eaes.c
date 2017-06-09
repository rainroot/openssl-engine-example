#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>

int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	if(iv){}
	printf("# %s %d #\n",__func__,__LINE__);
    fprintf(stderr, "(ENGINE_OPENSSL_AES) aes_init_key() called\n");

    int ret, mode;
    EOPENSSL_AES_KEY *dat = (EOPENSSL_AES_KEY *) ctx->cipher_data;

    mode = ctx->cipher->flags & EVP_CIPH_MODE;
    if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE)
        && !enc)
# ifdef HWAES_CAPABLE
        if (HWAES_CAPABLE) {
            ret = HWAES_set_decrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
            dat->block = (block128_f) HWAES_decrypt;
            dat->stream.cbc = NULL;
#  ifdef HWAES_cbc_encrypt
            if (mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) HWAES_cbc_encrypt;
#  endif
        } else
# endif
# ifdef BSAES_CAPABLE
        if (BSAES_CAPABLE && mode == EVP_CIPH_CBC_MODE) {
            ret = AES_set_decrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
            dat->block = (block128_f) AES_decrypt;
            dat->stream.cbc = (cbc128_f) bsaes_cbc_encrypt;
        } else
# endif
# ifdef VPAES_CAPABLE
        if (VPAES_CAPABLE) {
            ret = vpaes_set_decrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
            dat->block = (block128_f) vpaes_decrypt;
            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) vpaes_cbc_encrypt : NULL;
        } else
# endif
        {
            ret = AES_set_decrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
            dat->block = (block128_f) AES_decrypt;
            dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
                (cbc128_f) aes_cbc_cipher : NULL;
    } else
# ifdef HWAES_CAPABLE
    if (HWAES_CAPABLE) {
        ret = HWAES_set_encrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
        dat->block = (block128_f) HWAES_encrypt;
        dat->stream.cbc = NULL;
#  ifdef HWAES_cbc_encrypt
        if (mode == EVP_CIPH_CBC_MODE)
            dat->stream.cbc = (cbc128_f) HWAES_cbc_encrypt;
        else
#  endif
#  ifdef HWAES_ctr32_encrypt_blocks
        if (mode == EVP_CIPH_CTR_MODE)
            dat->stream.ctr = (ctr128_f) HWAES_ctr32_encrypt_blocks;
        else
#  endif
            (void)0;            /* terminate potentially open 'else' */
    } else
# endif
# ifdef BSAES_CAPABLE
    if (BSAES_CAPABLE && mode == EVP_CIPH_CTR_MODE) {
        ret = AES_set_encrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
        dat->block = (block128_f) AES_encrypt;
        dat->stream.ctr = (ctr128_f) bsaes_ctr32_encrypt_blocks;
    } else
# endif
# ifdef VPAES_CAPABLE
    if (VPAES_CAPABLE) {
        ret = vpaes_set_encrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
        dat->block = (block128_f) vpaes_encrypt;
        dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) vpaes_cbc_encrypt : NULL;
    } else
# endif
    {
        ret = AES_set_encrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
        dat->block = (block128_f) AES_encrypt;
        dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
            (cbc128_f) aes_cbc_cipher : NULL;
# ifdef AES_CTR_ASM
        if (mode == EVP_CIPH_CTR_MODE)
            dat->stream.ctr = (ctr128_f) AES_ctr32_encrypt;
# endif
    }

    if (ret < 0) {
        EVPerr(EVP_F_AES_INIT_KEY, EVP_R_AES_KEY_SETUP_FAILED);
        return 0;
    }

    return 1;
}

int aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t len)
{
	printf("# %s %d #\n",__func__,__LINE__);
    fprintf(stderr, "(ENGINE_OPENSSL_AES) aes_cbc_cipher() called\n");

    EOPENSSL_AES_KEY *dat = (EOPENSSL_AES_KEY *) ctx->cipher_data;

    if (dat->stream.cbc)
        (*dat->stream.cbc) (in, out, len, &dat->ks, ctx->iv, ctx->encrypt);
    else if (ctx->encrypt)
        CRYPTO_cbc128_encrypt(in, out, len, &dat->ks, ctx->iv, dat->block);
    else
        CRYPTO_cbc128_decrypt(in, out, len, &dat->ks, ctx->iv, dat->block);

    return 1;
}

int aes_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t len)
{
	printf("# %s %d #\n",__func__,__LINE__);
    fprintf(stderr, "(ENGINE_OPENSSL_AES) aes_ecb_cipher() called\n");

    size_t bl = ctx->cipher->block_size;
    size_t i;
    EOPENSSL_AES_KEY *dat = (EOPENSSL_AES_KEY *) ctx->cipher_data;

    if (len < bl)
        return 1;

    for (i = 0, len -= bl; i <= len; i += bl)
        (*dat->block) (in + i, out + i, &dat->ks);

    return 1;
}

