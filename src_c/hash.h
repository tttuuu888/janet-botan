/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the Simplified BSD License. (see LICENSE)
 */

#ifndef HASH_H
#define HASH_H

static Janet cfun_hash_init(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    const char *name = janet_getcstring(argv, 0);
    botan_hash_t hash;
    int ret = botan_hash_init(&hash, name, 0);
    if (ret) {
        janet_panic(getBotanError(ret));
    }
    return janet_wrap_pointer(hash);
}

static Janet cfun_hash_destroy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_t hash = janet_getpointer(argv, 0);
    int ret = botan_hash_destroy(hash);
    if (ret) {
        janet_panic(getBotanError(ret));
    }
    return janet_wrap_nil();
}

static JanetReg hash_cfuns[] = {
    {"hash/init", cfun_hash_init, "(hash/init name)\n\n"
     "Creates a hash of the given name, e.g., \"SHA-384\"."
    },
    {"hash/destroy", cfun_hash_destroy, "(hash/destroy name)\n\n"
     "Destroy the object created by `hash/init`."
    },
    {NULL, NULL, NULL}
};

#endif /* HASH_H */
