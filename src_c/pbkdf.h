/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License. (see LICENSE)
 */

#ifndef PBKDF_H
#define PBKDF_H

static Janet cfun_pbkdf(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 5);
    const char *algo = janet_getcstring(argv, 0);
    JanetByteView pw = janet_getbytes(argv, 1);
    size_t out_len = janet_getsize(argv, 2);
    JanetBuffer *out = janet_buffer(out_len);

    size_t iter = 100000;
    uint8_t *salt;
    size_t salt_len;
    int ret;

    if (argc >= 4) {
        iter = janet_getsize(argv, 3);
    }

    if (argc == 5) {
        JanetByteView salt_data = janet_getbytes(argv, 4);
        salt = (uint8_t *)salt_data.bytes;
        salt_len = salt_data.len;
    } else {
        botan_rng_t rng;
        salt_len = 12;
        salt = janet_smalloc(salt_len);

        ret = botan_rng_init(&rng, "system");
        JANET_BOTAN_ASSERT(ret);

        ret = botan_rng_get(rng, salt, salt_len);
        JANET_BOTAN_ASSERT(ret);

        ret = botan_rng_destroy(rng);
        JANET_BOTAN_ASSERT(ret);
    }

    ret = botan_pwdhash(algo, iter, 0, 0,
                        out->data, out_len,
                        (char *)pw.bytes, pw.len,
                        salt, salt_len);
    JANET_BOTAN_ASSERT(ret);

    if (argc != 5) {
        janet_sfree(salt);
    }

    out->count = out_len;
    return janet_wrap_string(janet_string(out->data, out->count));
}

static JanetReg pbkdf_cfuns[] = {
    {"pbkdf", cfun_pbkdf,
     "(pbkdf algo passphrase out_len &opt iterations salt)\n\n"
     "Derive a key from a `passphrase` for a number of "
     "`iterations`(default 100000) using the given PBKDF algorithm, e.g., "
     "\"PBKDF2(SHA-512)\". The `salt` can be provided or otherwise is "
     "randomly chosen. Returns `out_len` bytes of output (or potentially "
     "less depending on the algorithm and the size of the request). "
     "Returns tuple of salt, iterations, and psk"
    },
    {NULL, NULL, NULL}
};

#endif /* PBKDF_H */
