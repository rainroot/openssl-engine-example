#include <openssl/engine.h>

#define EVP_MAXCHUNK ((size_t)1<<(sizeof(long)*8-2))

#define CMD_SO_PATH		ENGINE_CMD_BASE


