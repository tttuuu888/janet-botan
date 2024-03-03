/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the Simplified BSD License. (see LICENSE)
 */

#include <janet.h>
#include <ffi.h>
#include <stdbool.h>
#include <string.h>

#include "versioning.h"
#include "utility.h"
#include "rng.h"

JANET_MODULE_ENTRY(JanetTable *env) {
    janet_cfuns(env, "botan", versioning_cfuns);
    janet_cfuns(env, "botan", utility_cfuns);
    janet_cfuns(env, "botan/rng", rng_cfuns);
}
