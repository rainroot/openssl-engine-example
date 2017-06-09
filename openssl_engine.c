#include <common.h>
#include <eopenssl_common.h>
#include <rainroot_eopenssl.h>
#include <engine_init.h>

static const char *engine_id = "openssl_engine";
static const char *engine_name = "Crypto rc4, rc4_40, des, 3des, aes, seed | Digest sha1, sha256, sha512 engine for demonstration purposes";
static const ENGINE_CMD_DEFN eopenssl_cmd_defns[] = {
	{CMD_SO_PATH, "SO_PATH", "Specifies the path to the 'openssl-engine' shared library", ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
};
const char *EOPENSSL_LIBPATH = NULL;


static int eopenssl_init(ENGINE *e)
{
	if(e){}
	int ret = 1;

	return ret;
}

static int eopenssl_finish(ENGINE *e)
{
	if(e){}
	int ret = 1;

	return ret;
}

static int eopenssl_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
	if(e){}
	if(i){}
	if(f){}
	int ret = 0;
	switch (cmd) {
	case CMD_SO_PATH:
		if (p && (strlen((const char *)p) < 1)) {
			p = NULL;
		}
		if (EOPENSSL_LIBPATH) {
			OPENSSL_free((void *)EOPENSSL_LIBPATH);
		}
		if (p) {
			EOPENSSL_LIBPATH = strdup((const char *)p);
			ret = 1;			
		}
		break;
	}

	return ret;
}


static int digest_nids[] = { NID_sha1, NID_sha256, NID_sha512, 0 };
static int digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
	if(e){}	
    int ok = 1;

    if (!digest) {
    	*nids = digest_nids;
      	return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
    }

    switch (nid) {
    case NID_sha1:
        *digest = &digest_sha1;
        break;
    case NID_sha256:
        *digest = &digest_sha256;
        break;
    case NID_sha512:
        *digest = &digest_sha512;
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }

    return ok;
}

static int ciphers_nids[] = { NID_rc4, NID_rc4_40,
                               NID_des_cbc, NID_des_ede3_cbc,
                               NID_aes_128_ecb, NID_aes_192_ecb, NID_aes_256_ecb,
                               NID_aes_128_cbc, NID_aes_192_cbc, NID_aes_256_cbc,
                               NID_seed_ecb, NID_seed_cbc, 0 };

static int ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
	if(e){}
    int ok = 1;
    if (!cipher) {
        *nids = ciphers_nids;
        return (sizeof(ciphers_nids) - 1) / sizeof(ciphers_nids[0]);
    }

    switch (nid) {
    case NID_rc4:
    	*cipher = &cipher_rc4;
        break;
    case NID_rc4_40:
    	*cipher = &cipher_rc4_40;
        break;
    case NID_des_cbc:
        *cipher = &cipher_des_cbc;
        break;
    case NID_des_ede3_cbc:
        *cipher = &cipher_des_ede3_cbc;
        break;
    case NID_aes_128_cbc:
        *cipher = &cipher_aes_cbc;
        break;
    case NID_aes_192_cbc:
        *cipher = &cipher_aes_192_cbc;
        break;
    case NID_aes_256_cbc:
        *cipher = &cipher_aes_256_cbc;
        break;
    case NID_aes_128_ecb:
        *cipher = &cipher_aes_ecb;
        break;
    case NID_aes_192_ecb:
        *cipher = &cipher_aes_192_ecb;
        break;
    case NID_aes_256_ecb:
        *cipher = &cipher_aes_256_ecb;
        break;
	case NID_seed_ecb:
        *cipher = &cipher_seed_ecb;
        break;
    case NID_seed_cbc:
        *cipher = &cipher_seed_cbc;
        break;
    default:
        ok = 0;
        *cipher = NULL;
        break;
    }

    return ok;
}

static int bind(ENGINE *e, const char *id)
{
    int ret = 0;
	static int loaded = 0;


	if (id && strcmp(id, engine_id)) {
			fprintf(stderr, "SHA1, SHA256, SHA512, MD5 | rc4, rc4-40, des, 3des, aes, aria, seed engine called with the unexpected id %s\n", id);
			fprintf(stderr, "The expected id is %s\n", engine_id);
			goto end;
	}

	if (loaded) {
			fprintf(stderr, "SHA1, SHA256, SHA512, MD5 | rc4, rc4-40, des, 3des, aes, aria, seed engine already loaded\n");
			goto end;
	}

	loaded = 1;

	if (!ENGINE_set_id(e, engine_id)) {
			fprintf(stderr, "ENGINE_set_id failed\n");
			goto end;
	}
	if (!ENGINE_set_name(e, engine_name)) {
			printf("ENGINE_set_name failed\n");
			goto end;
	}
	if (!ENGINE_set_init_function(e, eopenssl_init)) {
			printf("ENGINE_set_init_function failed\n");
			goto end;
	}
	if (!ENGINE_set_finish_function(e, eopenssl_finish)) {
			printf("ENGINE_set_finish_function failed\n");
			goto end;
	}
	if (!ENGINE_set_ctrl_function(e, eopenssl_ctrl)) {
			printf("ENGINE_set_ctrl_function failed\n");
			goto end;
	}
	if (!ENGINE_set_cmd_defns(e, eopenssl_cmd_defns)) {
			printf("ENGINE_set_cmd_defns failed\n");
			goto end;
	}
	if (!ENGINE_set_digests(e, digests)) {
			printf("ENGINE_set_digests failed\n");
			goto end;
	}
	if (!ENGINE_set_ciphers(e, ciphers)) {
			printf("ENGINE_set_ciphers failed\n");
			goto end;
	}

	ret = 1;

end:
	return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
