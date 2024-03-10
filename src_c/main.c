/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the Simplified BSD License. (see LICENSE)
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

extern const unsigned char *src_janet___botan_lib_embed;
extern size_t src_janet___botan_lib_embed_size;

JANET_MODULE_ENTRY(JanetTable *env) {
    janet_cfuns(env, "botan", versioning_cfuns);
    janet_cfuns(env, "botan", utility_cfuns);
    janet_cfuns(env, "botan/rng", rng_cfuns);
    janet_cfuns(env, "botan/block-cipher", block_cipher_cfuns);
    janet_cfuns(env, "botan/hash", hash_cfuns);
    janet_cfuns(env, "botan/mac", mac_cfuns);
    janet_dobytes(env,
                  src_janet___botan_lib_embed,
                  src_janet___botan_lib_embed_size,
                  "botan_lib.janet",
                  NULL);
}
