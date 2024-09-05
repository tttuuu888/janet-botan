/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_RNG_H
#define BOTAN_RNG_H

typedef struct botan_rng_obj {
    botan_rng_t rng;
} botan_rng_obj_t;

/* Abstract Object functions */
static int rng_gc_fn(void *data, size_t len);
static int rng_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet rng_new(int32_t argc, Janet *argv);
static Janet rng_get(int32_t argc, Janet *argv);
static Janet rng_reseed(int32_t argc, Janet *argv);
static Janet rng_reseed_from_rng(int32_t argc, Janet *argv);
static Janet rng_add_entropy(int32_t argc, Janet *argv);

static JanetAbstractType rng_obj_type = {
    "botan/rng",
    rng_gc_fn,
    NULL,
    rng_get_fn,
    JANET_ATEND_GET
};

static JanetMethod rng_methods[] = {
    {"get", rng_get},
    {"reseed", rng_reseed},
    {"reseed-from-rng", rng_reseed_from_rng},
    {"add-entropy", rng_add_entropy},
    {NULL, NULL},
};

static JanetAbstractType *get_rng_obj_type() {
    return &rng_obj_type;
}

/* Abstract Object functions */
static int rng_gc_fn(void *data, size_t len) {
    botan_rng_obj_t *obj = (botan_rng_obj_t *)data;

    int ret = botan_rng_destroy(obj->rng);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int rng_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), rng_methods, out);
}

/* Janet functions */
static Janet rng_new(int32_t argc, Janet *argv) {
    botan_rng_obj_t *obj = janet_abstract(&rng_obj_type, sizeof(botan_rng_obj_t));
    memset(obj, 0, sizeof(botan_rng_obj_t));

    janet_arity(argc, 0, 1);
    const char *type = janet_optcstring(argv, argc, 0, "system");
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

    int ret = botan_rng_init(&obj->rng, type_input);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet rng_get(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_rng_obj_t *obj = janet_getabstract(argv, 0, get_rng_obj_type());
    botan_rng_t rng = obj->rng;
    size_t len = janet_getsize(argv, 1);

    int ret;
    JanetBuffer *out = janet_buffer(len);

    ret = botan_rng_get(rng, out->data, len);
    JANET_BOTAN_ASSERT(ret);

    out->count = len;
    return janet_wrap_string(janet_string(out->data, out->count));
}

static Janet rng_reseed(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_rng_obj_t *obj = janet_getabstract(argv, 0, get_rng_obj_type());
    botan_rng_t rng = obj->rng;
    size_t bits = janet_getsize(argv, 1);

    int ret = botan_rng_reseed(rng, bits);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet rng_reseed_from_rng(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 3);
    botan_rng_obj_t *obj = janet_getabstract(argv, 0, get_rng_obj_type());
    botan_rng_t rng = obj->rng;
    botan_rng_obj_t *obj2 = janet_getabstract(argv, 1, get_rng_obj_type());
    botan_rng_t src = obj2->rng;
    size_t bits = janet_getsize(argv, 2);

    int ret = botan_rng_reseed_from_rng(rng, src, bits);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet rng_add_entropy(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    botan_rng_obj_t *obj = janet_getabstract(argv, 0, get_rng_obj_type());
    botan_rng_t rng = obj->rng;
    JanetByteView seed = janet_getbytes(argv, 1);

    int ret = botan_rng_add_entropy(rng, (const uint8_t *)seed.bytes, seed.len);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static JanetReg rng_cfuns[] = {
    {"rng/new", rng_new, "(rng/new &opt type)\n\n"
     "Initialize a random number generator from the given `type`:\n\n"
     "\"system\": System-RNG (defaulting to \"system\" type rng)\n\n"
     "\"user\": AutoSeeded-RNG\n\n"
     "\"user-threadsafe\": serialized AutoSeeded-RNG\n\n"
     "\"null\": Null-RNG (always fails)\n\n"
     "\"hwrnd\" or \"rdrand\": Processor-RNG (if available)\n\n"
     "Returns `rng-obj`"
    },
    {"rng/get", rng_get, "(rng/get rng-obj len)\n\n"
     "Returns random bytes of length `len` from a random number generator `rng-obj`."
    },
    {"rng/reseed", rng_reseed, "(rng/reseed rng-obj bits)\n\n"
     "Reseeds the random number generator `rng` with bits number of `bits` "
     "from the System-RNG. Returns `rng-obj`."
    },
    {"rng/reseed-from-rng", rng_reseed_from_rng,
     "(rng/reseed-from-rng rng-obj src bits)\n\n"
     "Reseeds the random number generator `rng` with bits number of `bits` "
     "taken from given the source rng `src`. Returns `rng-obj`."
    },
    {"rng/add-entropy", rng_add_entropy,
     "(rng/add-entropy rng-obj seed)\n\n"
     "Adds the provided `seed` array or tuple to the `rng`. Returns `rng-obj`."
    },
    {NULL, NULL, NULL}
};

static void submod_rng(JanetTable *env) {
    janet_cfuns(env, "botan", rng_cfuns);
    janet_register_abstract_type(get_rng_obj_type());
}

#endif /* BOTAN_RNG_H */
