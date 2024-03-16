/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License. (see LICENSE)
 */

#include <janet.h>
#include <ffi.h>
#include <stdbool.h>
#include <string.h>

#include "errors.h"
#include "versioning.h"
#include "utility.h"
#include "rng.h"
#include "block_cipher.h"
#include "hash.h"
#include "mac.h"
#include "cipher.h"
#include "bcrypt.h"
#include "pbkdf.h"
#include "scrypt.h"
#include "kdf.h"

extern const unsigned char *src_janet___botan_lib_embed;
extern size_t src_janet___botan_lib_embed_size;

JANET_MODULE_ENTRY(JanetTable *env) {
    janet_cfuns(env, "botan", versioning_cfuns);
    janet_cfuns(env, "botan", utility_cfuns);
    submod_rng(env);
    janet_cfuns(env, "botan/block-cipher", block_cipher_cfuns);
    janet_cfuns(env, "botan/hash", hash_cfuns);
    janet_cfuns(env, "botan/mac", mac_cfuns);
    janet_cfuns(env, "botan/cipher", cipher_cfuns);
    janet_cfuns(env, "botan", bcrypt_cfuns);
    janet_cfuns(env, "botan", pbkdf_cfuns);
    janet_cfuns(env, "botan", scrypt_cfuns);
    janet_cfuns(env, "botan", kdf_cfuns);
    janet_dobytes(env,
                  src_janet___botan_lib_embed,
                  src_janet___botan_lib_embed_size,
                  "botan_lib.janet",
                  NULL);
}
