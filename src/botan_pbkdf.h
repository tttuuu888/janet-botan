/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_PBKDF_H
#define BOTAN_PBKDF_H

static Janet pbkdf(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 5);
    const char *algo = janet_getcstring(argv, 0);
    JanetByteView pw = janet_getbytes(argv, 1);
    size_t out_len = janet_getsize(argv, 2);
    JanetBuffer *out = janet_buffer(out_len);

    size_t iter = janet_optsize(argv, argc, 3, 100000);
    uint8_t *salt;
    size_t salt_len;
    int ret;

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

    out->count = out_len;
    Janet output[3] = {
        janet_wrap_string(janet_string(salt, salt_len)),
        janet_wrap_number((double)iter),
        janet_wrap_string(janet_string(out->data, out->count))
    };

    if (argc != 5) {
        janet_sfree(salt);
    }

    return janet_wrap_tuple(janet_tuple_n(output, 3));
}

static Janet pbkdf_timed(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 5);
    const char *algo = janet_getcstring(argv, 0);
    JanetByteView pw = janet_getbytes(argv, 1);
    size_t out_len = janet_getsize(argv, 2);
    JanetBuffer *out = janet_buffer(out_len);

    size_t ms_to_run = 300;
    size_t iter;
    uint8_t *salt;
    size_t salt_len;
    int ret;

    if (argc >= 4) {
        ms_to_run = janet_getsize(argv, 3);
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

    ret = botan_pwdhash_timed(algo, ms_to_run,
                              &iter, 0, 0,
                              out->data, out_len,
                              (char *)pw.bytes, pw.len,
                              salt, salt_len);
    JANET_BOTAN_ASSERT(ret);

    out->count = out_len;

    Janet output[3] = {
        janet_wrap_string(janet_string(salt, salt_len)),
        janet_wrap_number((double)iter),
        janet_wrap_string(janet_string(out->data, out->count))
    };

    if (argc != 5) {
        janet_sfree(salt);
    }

    return janet_wrap_tuple(janet_tuple_n(output, 3));
}

static JanetReg pbkdf_cfuns[] = {
    {"pbkdf", pbkdf,
     "(pbkdf algo passphrase out-len &opt iterations salt)\n\n"
     "Derive a key from a `passphrase` for a number of "
     "`iterations`(default 100000) using the given PBKDF algorithm, e.g., "
     "\"PBKDF2(SHA-512)\". The `salt` can be provided or otherwise is "
     "randomly chosen. Returns `out-len` bytes of output (or potentially "
     "less depending on the algorithm and the size of the request). "
     "Returns tuple of salt, iterations, and psk"
    },
    {"pbkdf-timed", pbkdf_timed,
     "(pbkdf-timed algo passphrase out-len &opt ms-to-run salt)\n\n"
     "Derive a key from a `passphrase` for a number of "
     "Runs for as many iterations as needed to consumed `ms-to-run` "
     "milliseconds on whatever we’re running on. Returns tuple of salt, "
     "iterations, and psk. Default value of `ms-to-run` is 300 and `salt` "
     "is 12 bytes of random values."
    },
    {NULL, NULL, NULL}
};

static void submod_pbkdf(JanetTable *env) {
    janet_cfuns(env, "botan", pbkdf_cfuns);
}

#endif /* BOTAN_PBKDF_H */
