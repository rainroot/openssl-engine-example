static const EVP_CIPHER cipher_aes_ecb = {
		NID_aes_128_ecb,
		16, 16, 16,
		EVP_CIPH_ECB_MODE,
		aes_init_key,
		aes_ecb_cipher,
		NULL,
		sizeof(EOPENSSL_AES_KEY),
		NULL,
		NULL,
		NULL,
		NULL
};
static const EVP_CIPHER cipher_aes_192_ecb = {
		NID_aes_192_ecb,
		16, 24, 16,
		EVP_CIPH_ECB_MODE,
		aes_init_key,
		aes_ecb_cipher,
		NULL,
		sizeof(EOPENSSL_AES_KEY),
		NULL,
		NULL,
		NULL,
		NULL
};
static const EVP_CIPHER cipher_aes_256_ecb = {
		NID_aes_256_ecb,
		16, 32, 16,
		EVP_CIPH_ECB_MODE,
		aes_init_key,
		aes_ecb_cipher,
		NULL,
		sizeof(EOPENSSL_AES_KEY),
		NULL,
		NULL,
		NULL,
		NULL
};
static const EVP_CIPHER cipher_aes_cbc = {
		NID_aes_128_cbc,
		16, 16, 16,
		EVP_CIPH_CBC_MODE,
		aes_init_key,
		aes_cbc_cipher,
		NULL,
		sizeof(EOPENSSL_AES_KEY),
		EVP_CIPHER_set_asn1_iv,
		EVP_CIPHER_get_asn1_iv,
		NULL,
		NULL
};
static const EVP_CIPHER cipher_aes_192_cbc = {
		NID_aes_192_cbc,
		16, 24, 16,
		EVP_CIPH_CBC_MODE,
		aes_init_key,
		aes_cbc_cipher,
		NULL,
		sizeof(EOPENSSL_AES_KEY),
		EVP_CIPHER_set_asn1_iv,
		EVP_CIPHER_get_asn1_iv,
		NULL,
		NULL
};
static const EVP_CIPHER cipher_aes_256_cbc = {
		NID_aes_256_cbc,
		16, 32, 16,
		EVP_CIPH_CBC_MODE,
		aes_init_key,
		aes_cbc_cipher,
		NULL,
		sizeof(EOPENSSL_AES_KEY),
		EVP_CIPHER_set_asn1_iv,
		EVP_CIPHER_get_asn1_iv,
		NULL,
		NULL
};

static const EVP_CIPHER cipher_seed_ecb = {
    NID_seed_ecb,
    16, 16, 16,
    EVP_CIPH_ECB_MODE,
    seed_init_key,
    seed_ecb_cipher,
    NULL,
    sizeof(EOPENSSL_SEED_KEY),
    NULL,
    NULL,
    NULL,
	NULL
};

static const EVP_CIPHER cipher_seed_cbc = {
    NID_seed_cbc,
    16, 16, 16,
    EVP_CIPH_CBC_MODE,
    seed_init_key,
    seed_cbc_cipher,
    NULL,
    sizeof(EOPENSSL_SEED_KEY),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
	NULL
};

static const EVP_CIPHER cipher_des_cbc = {
    NID_des_cbc,
    8, 8, 8,
    EVP_CIPH_CBC_MODE,
    des_init_key,
    des_cipher,
    NULL,
    sizeof(EOPENSSL_DES_KEY),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
	NULL
};

static const EVP_CIPHER cipher_des_ede3_cbc = {
    NID_des_ede3_cbc,
    8, 24, 8,
    EVP_CIPH_CBC_MODE,
    des_ede3_init_key,
    des_ede_cbc_cipher,
    NULL,
    sizeof(EOPENSSL_DES_EDE_KEY),
    EVP_CIPHER_set_asn1_iv,
    EVP_CIPHER_get_asn1_iv,
    NULL,
	NULL
};

static const EVP_MD digest_sha1 = {
    NID_sha1,
    NID_sha1WithRSAEncryption,
    SHA_DIGEST_LENGTH,
    0,
    sha1_init,
    sha1_update,
    sha1_final,
    NULL,
    NULL,
    EVP_PKEY_RSA_method,
    SHA_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA_CTX),
	NULL	
};

static const EVP_MD digest_sha256 = {
    NID_sha256,
    NID_sha256WithRSAEncryption,
    SHA256_DIGEST_LENGTH,
    0,
    sha256_init,
    sha256_update,
    sha256_final,
    NULL,
    NULL,
    EVP_PKEY_RSA_method,
    SHA256_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA256_CTX),
	NULL
};

static const EVP_MD digest_sha512 = {
    NID_sha512,
    NID_sha512WithRSAEncryption,
    SHA512_DIGEST_LENGTH,
    0,
    sha512_init,
    sha512_update,
    sha512_final,
    NULL,
    NULL,
    EVP_PKEY_RSA_method,
    SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA512_CTX),
	NULL
};

static const EVP_CIPHER cipher_rc4 = {
    NID_rc4,
    1, EOPENSSL_RC4_KEY_SIZE, 0,
    EVP_CIPH_VARIABLE_LENGTH,
    rc4_init_key,
    rc4_cipher,
    NULL,
    sizeof(EOPENSSL_RC4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};

static const EVP_CIPHER cipher_rc4_40 = {
    NID_rc4_40,
    1, 5, 0,
    EVP_CIPH_VARIABLE_LENGTH,
    rc4_init_key,
    rc4_cipher,
    NULL,
    sizeof(EOPENSSL_RC4_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};

