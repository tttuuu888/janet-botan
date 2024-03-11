/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License. (see LICENSE)
 */

#ifndef HASH_H
#define HASH_H

static Janet cfun_hash_init(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    const char *name = janet_getcstring(argv, 0);
    botan_hash_t hash;

    int ret = botan_hash_init(&hash, name, 0);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_pointer(hash);
}

static Janet cfun_hash_destroy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_t hash = janet_getpointer(argv, 0);

    int ret = botan_hash_destroy(hash);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_hash_name(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_t hash = janet_getpointer(argv, 0);
    char name_buf[32] = {0,};
    size_t name_len = 32;

    int ret = botan_hash_name(hash, name_buf, &name_len);
    JANET_BOTAN_ASSERT(ret);


    name_len -= 1;              /* A length except the last null character */
    return janet_wrap_string(janet_string(name_buf, name_len));
}

static Janet cfun_hash_copy_state(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_t hash = janet_getpointer(argv, 0);
    botan_hash_t hash2;

    int ret = botan_hash_copy_state(&hash2, hash);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_pointer(hash2);
}

static Janet cfun_hash_clear(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_t hash = janet_getpointer(argv, 0);

    int ret = botan_hash_clear(hash);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_hash_output_length(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_t hash = janet_getpointer(argv, 0);
    size_t output_len;

    int ret = botan_hash_output_length(hash, &output_len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)output_len);
}

static Janet cfun_hash_update(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_hash_t hash = janet_getpointer(argv, 0);
    JanetByteView input = janet_getbytes(argv, 1);

    int ret = botan_hash_update(hash, input.bytes, input.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_hash_final(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_hash_t hash = janet_getpointer(argv, 0);
    size_t output_len;

    int ret = botan_hash_output_length(hash, &output_len);
    JANET_BOTAN_ASSERT(ret);

    uint8_t *output = janet_string_begin(output_len);
    ret = botan_hash_final(hash, output);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_string(janet_string_end(output));
}

static JanetReg hash_cfuns[] = {
    {"hash/init", cfun_hash_init, "(hash/init name)\n\n"
     "Creates a hash of the given name, e.g., \"SHA-384\"."
    },
    {"hash/destroy", cfun_hash_destroy, "(hash/destroy hash)\n\n"
     "Destroy the object created by `hash/init`."
    },
    {"hash/name", cfun_hash_name, "(hash/name hash)\n\n"
     "Return the name of the hash function."
    },
    {"hash/copy", cfun_hash_copy_state, "(hash/copy hash)\n\n"
     "Return a new hash object copied from `hash`."
    },
    {"hash/clear", cfun_hash_clear, "(hash/clear hash)\n\n"
     "Reset the state of `hash` back to clean, "
     "as if no input has been supplied."
    },
    {"hash/output-length", cfun_hash_output_length,
     "(hash/output-length hash)\n\n"
     "Return the output length of the `hash`"
    },
    {"hash/update", cfun_hash_update, "(hash/update hash input)\n\n"
     "Add input to the hash computation."
    },
    {"hash/final", cfun_hash_final, "(hash/final hash)\n\n"
     "Finalize the hash and return the output"
    },
    {NULL, NULL, NULL}
};

#endif /* HASH_H */
