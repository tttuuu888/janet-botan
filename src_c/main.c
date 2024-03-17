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
#include "botan_mpi.h"

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
    submod_bcrypt(env);
    submod_pbkdf(env);
    submod_scrypt(env);
    submod_kdf(env);
    submod_mpi(env);
    janet_dobytes(env,
                  src_janet___botan_lib_embed,
                  src_janet___botan_lib_embed_size,
                  "botan_lib.janet",
                  NULL);
}
