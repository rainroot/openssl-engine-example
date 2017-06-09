#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>

int rc4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	if(iv){}
	if(enc){}
    memcpy(&eopenssl_rc4(ctx)->key[0], key, EVP_CIPHER_CTX_key_length(ctx));
    RC4_set_key(&eopenssl_rc4(ctx)->ks, EVP_CIPHER_CTX_key_length(ctx), eopenssl_rc4(ctx)->key);

    return 1;
}

int rc4_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    RC4(&eopenssl_rc4(ctx)->ks, inl, in, out);
 
    return 1;
}
