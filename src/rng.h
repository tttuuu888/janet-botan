/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the Simplified BSD License. (see LICENSE)
 */

#ifndef RNG_H
#define RNG_H

static Janet cfun_rng_create(int32_t argc, Janet *argv) {
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
    return janet_wrap_pointer(rng);
}

static Janet cfun_rng_destroy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    botan_rng_t rng = janet_getpointer(argv, 0);
    int ret = botan_rng_destroy(rng);
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
    /* int64_t bits = janet_getinteger64(argv, 0); */
    /* int ret = botan_rng_reseed2(rng); */
    return janet_wrap_nil();
}


static JanetReg rng_cfuns[] = {
    {"rng/create", cfun_rng_create, "(rng/create &opt type)\n\n"
     "Initialize a random number generator from the given `type`:\n\n"
     "\"system\": System-RNG (defaulting to \"system\" type rng)\n\n"
     "\"user\": AutoSeeded-RNG\n\n"
     "\"user-threadsafe\": serialized AutoSeeded-RNG\n\n"
     "\"null\": Null-RNG (always fails)\n\n"
     "\"hwrnd\" or \"rdrand\": Processor-RNG (if available)"
    },
    {"rng/destroy", cfun_rng_destroy, "(rng/destroy rng)\n\n"
     "Destroy the `rng` object created by `rng/create`"
    },
    {"rng/generate", cfun_rng_get, "(rng/generate len &opt rng)\n\n"
     "Generate random bytes of length len from a random number generator `rng`."
     "(defaulting to \"system\" type rng)"
    },
    {"rng/generate", cfun_rng_get, "(rng/generate len &opt rng)\n\n"
     "Generate random bytes of length len from a random number generator `rng`."
     "(defaulting to \"system\" type rng)"
    },
    {"rng/reseed", cfun_rng_reseed, "(rng/reseed rng bits)\n\n"
     "Reseeds the random number generator `rng` with bits number of `bits` from"
     " the System-RNG."
    },
    {NULL, NULL, NULL}
};

#endif /* RNG_H */
