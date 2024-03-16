/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License. (see LICENSE)
 */

#include <janet.h>
#include <ffi.h>
#include <stdbool.h>
#include <string.h>

#include "botan_errors.h"
#include "botan_versioning.h"
#include "botan_utility.h"
#include "botan_rng.h"
#include "botan_block_cipher.h"
#include "botan_hash.h"
#include "botan_mac.h"
#include "botan_cipher.h"
#include "botan_bcrypt.h"
#include "botan_pbkdf.h"
#include "botan_scrypt.h"
#include "botan_kdf.h"

extern const unsigned char *src_janet___botan_lib_embed;
extern size_t src_janet___botan_lib_embed_size;

JANET_MODULE_ENTRY(JanetTable *env) {
    submod_versioning(env);
    submod_utility(env);
    submod_rng(env);
    submod_block_cipher(env);
    submod_hash(env);
    submod_mac(env);
    submod_cipher(env);
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
