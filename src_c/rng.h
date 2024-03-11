/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License. (see LICENSE)
 */

#ifndef RNG_H
#define RNG_H

static Janet cfun_rng_init(int32_t argc, Janet *argv) {
    janet_arity(argc, 0, 1);
    const char *type = (argc == 0) ? "system" : janet_getcstring(argv, 0);
    bool valid_type = false;
    if (strcmp(type, "system") == 0 ||
        strcmp(type, "user") == 0 ||
        strcmp(type, "user-threadsafe") == 0 ||
        strcmp(type, "null") == 0 ||
        strcmp(type, "hwrnd") == 0 ||
        strcmp(type, "rdrand") == 0) {
        valid_type = true;
    }

    const char *type_input = valid_type ? type : "system";
    botan_rng_t rng;

    int ret = botan_rng_init(&rng, type_input);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_pointer(rng);
}

static Janet cfun_rng_destroy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_rng_t rng = janet_getpointer(argv, 0);

    int ret = botan_rng_destroy(rng);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_rng_get(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    int ret;
    botan_rng_t rng;
    if (argc == 1)
        ret = botan_rng_init(&rng, "system");
    else
        rng = janet_getpointer(argv, 1);
    int64_t len = janet_getinteger64(argv, 0);
    JanetArray *out = janet_array(len);
    uint8_t *out_raw = janet_smalloc(len);

    ret = botan_rng_get(rng, out_raw, len);
    JANET_BOTAN_ASSERT(ret);


    for(int i=0; i<len; i++)
        out->data[i] = janet_wrap_number(out_raw[i]);

    janet_sfree(out_raw);
    out->count = len;

    if (argc == 1)
        ret = botan_rng_destroy(rng);

    return janet_wrap_array(out);
}

static Janet cfun_rng_reseed(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_rng_t rng = janet_getpointer(argv, 0);
    int64_t bits = janet_getinteger64(argv, 1);

    int ret = botan_rng_reseed(rng, bits);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_rng_reseed_from_rng(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    botan_rng_t rng = janet_getpointer(argv, 0);
    botan_rng_t src = janet_getpointer(argv, 1);
    int64_t bits = janet_getinteger64(argv, 2);

    int ret = botan_rng_reseed_from_rng(rng, src, bits);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static Janet cfun_rng_add_entropy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_rng_t rng = janet_getpointer(argv, 0);
    const char *seed = (const char *)janet_getstring(argv, 1);
    int len = strlen(seed);

    int ret = botan_rng_add_entropy(rng, (const uint8_t *)seed, len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_nil();
}

static JanetReg rng_cfuns[] = {
    {"rng/init", cfun_rng_init, "(rng/init &opt type)\n\n"
     "Initialize a random number generator from the given `type`:\n\n"
     "\"system\": System-RNG (defaulting to \"system\" type rng)\n\n"
     "\"user\": AutoSeeded-RNG\n\n"
     "\"user-threadsafe\": serialized AutoSeeded-RNG\n\n"
     "\"null\": Null-RNG (always fails)\n\n"
     "\"hwrnd\" or \"rdrand\": Processor-RNG (if available)"
    },
    {"rng/destroy", cfun_rng_destroy, "(rng/destroy rng)\n\n"
     "Destroy the `rng` object created by `rng/init`"
    },
    {"rng/get", cfun_rng_get, "(rng/get len &opt rng)\n\n"
     "Generate random bytes of length len from a random number generator `rng`."
     "(defaulting to \"system\" type rng)"
    },
    {"rng/reseed", cfun_rng_reseed, "(rng/reseed rng bits)\n\n"
     "Reseeds the random number generator `rng` with bits number of `bits` from"
     " the System-RNG."
    },
    {"rng/reseed-from-rng", cfun_rng_reseed_from_rng,
     "(rng/reseed-from-rng rng src bits)\n\n"
     "Reseeds the random number generator `rng` with bits number of `bits` taken "
     "from given the source rng `src`"
    },
    {"rng/add-entropy", cfun_rng_add_entropy,
     "(rng/add-entropy rng seed)\n\n"
     "Adds the provided `seed` array or tuple to the `rng`."
    },
    {NULL, NULL, NULL}
};

#endif /* RNG_H */
