/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Botan-janet is released under the Simplified BSD License. (see LICENSE)
 */

#include <janet.h>
#include <ffi.h>

#include "versioning.h"

JANET_MODULE_ENTRY(JanetTable *env) {
    janet_cfuns(env, "botan", default_cfuns);
}
