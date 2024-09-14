/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_HOTP_H
#define BOTAN_HOTP_H

typedef struct botan_hotp_obj {
    botan_hotp_t hotp;
} botan_hotp_obj_t;

/* Abstract Object functions */
static int hotp_gc_fn(void *data, size_t len);
static int hotp_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet hotp_new(int32_t argc, Janet *argv);
static Janet hotp_generate(int32_t argc, Janet *argv);
static Janet hotp_check(int32_t argc, Janet *argv);

static JanetAbstractType hotp_obj_type = {
    "botan/hotp",
    hotp_gc_fn,
    NULL,
    hotp_get_fn,
    JANET_ATEND_GET
};

static JanetMethod hotp_methods[] = {
    {"generate", hotp_generate},
    {"check", hotp_check},
    {NULL, NULL},
};

static JanetAbstractType *get_hotp_obj_type() {
    return &hotp_obj_type;
}

/* Abstract Object functions */
static int hotp_gc_fn(void *data, size_t len) {
    botan_hotp_obj_t *obj = (botan_hotp_obj_t *)data;

    int ret = botan_hotp_destroy(obj->hotp);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int hotp_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), hotp_methods, out);
}

/* Janet functions */
static Janet hotp_new(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 3);

    botan_hotp_obj_t *obj = janet_abstract(&hotp_obj_type, sizeof(botan_hotp_obj_t));
    memset(obj, 0, sizeof(botan_hotp_obj_t));

    JanetByteView key = janet_getbytes(argv, 0);
    const char *hash = janet_optcstring(argv, argc, 1, "SHA-1");
    size_t digits = janet_optsize(argv, argc, 2, 6);

    int ret = botan_hotp_init(&obj->hotp, key.bytes, key.len, hash, digits);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet hotp_generate(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);

    botan_hotp_obj_t *obj = janet_getabstract(argv, 0, get_hotp_obj_type());
    botan_hotp_t hotp = obj->hotp;
    uint64_t counter = janet_getuinteger64(argv, 1);

    uint32_t code = 0;
    int ret = botan_hotp_generate(hotp, &code, counter);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)code);
}

static Janet hotp_check(int32_t argc, Janet *argv) {
    janet_arity(argc, 3, 4);

    botan_hotp_obj_t *obj = janet_getabstract(argv, 0, get_hotp_obj_type());
    botan_hotp_t hotp = obj->hotp;
    uint32_t code = (uint32_t)janet_getsize(argv, 1);
    uint64_t counter = janet_getuinteger64(argv, 2);
    size_t resync_range = janet_optsize(argv, argc, 3, 0);

    uint64_t next_ctr = 0;
    int ret = botan_hotp_check(hotp, &next_ctr, code, counter, resync_range);
    JANET_BOTAN_ASSERT(ret);

    Janet result[2];
    if (ret == 0) {
        result[0] = janet_wrap_boolean(true);
        result[1] = janet_wrap_number((double)next_ctr);
    } else {
        result[0] = janet_wrap_boolean(false);
        result[1] = janet_wrap_number((double)counter);
    }

    return janet_wrap_tuple(janet_tuple_n(result, 2));
}

static JanetReg hotp_cfuns[] = {
    {"hotp/new", hotp_new,
     "(hotp/new key &opt hash digits)\n\n"
     "Instantiate a new HOTP instance with the given parameters. If omitted, "
     "the default value for `hash` is \"SHA-1\" and the default value for "
     "`digits` is 6. Returns `htop-obj`."
    },
    {"hotp/generate", hotp_generate,
     "(hotp/generate hotp-obj counter)\n\n"
     "Generate an HOTP code for the provided `counter`."
    },
    {"hotp/check", hotp_check,
     "(hotp/check hotp-obj code counter &opt resync-range)\n\n"
     "Check if provided `code` is the correct code for `counter`. If omitted, "
     "the default value for `resync-range` is 0. If `resync-range` is greater "
     "than zero, HOTP also checks up to `resync-range` following `counter` "
     "values.\n\nReturns a tuple of (boolean number) where the boolean "
     "indicates if the code was valid, and the number indicates the next "
     "counter value that should be used. If the `code` did not verify, the "
     "next counter value is always identical to the counter that was passed "
     "in. If the `code` did verify and `resync-range` was zero, then the next "
     "counter will always be counter+1."
    },

    {NULL, NULL, NULL}
};

static void submod_hotp(JanetTable *env) {
    janet_cfuns(env, "botan", hotp_cfuns);
}

#endif /* BOTAN_HOTP_H */
