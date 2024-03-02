/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the Simplified BSD License. (see LICENSE)
 */

#include <janet.h>
#include <ffi.h>

#include "versioning.h"
#include "utility.h"

JANET_MODULE_ENTRY(JanetTable *env) {
    janet_cfuns(env, "botan", versioning_cfuns);
    janet_cfuns(env, "botan", utility_cfuns);
}
