/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-botan is released under the MIT License, see the LICENSE file.
 */

#ifndef BOTAN_TOTP_H
#define BOTAN_TOTP_H

typedef struct botan_totp_obj {
    botan_totp_t totp;
} botan_totp_obj_t;

/* Abstract Object functions */
static int totp_gc_fn(void *data, size_t len);
static int totp_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
static Janet totp_new(int32_t argc, Janet *argv);
static Janet totp_generate(int32_t argc, Janet *argv);
static Janet totp_check(int32_t argc, Janet *argv);

static JanetAbstractType totp_obj_type = {
    "botan/totp",
    totp_gc_fn,
    NULL,
    totp_get_fn,
    JANET_ATEND_GET
};

static JanetMethod totp_methods[] = {
    {"generate", totp_generate},
    {"check", totp_check},
    {NULL, NULL},
};

static JanetAbstractType *get_totp_obj_type() {
    return &totp_obj_type;
}

/* Abstract Object functions */
static int totp_gc_fn(void *data, size_t len) {
    botan_totp_obj_t *obj = (botan_totp_obj_t *)data;

    int ret = botan_totp_destroy(obj->totp);
    JANET_BOTAN_ASSERT(ret);

    return 0;
}

static int totp_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), totp_methods, out);
}

/* Janet functions */
static Janet totp_new(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 4);

    botan_totp_obj_t *obj = janet_abstract(&totp_obj_type, sizeof(botan_totp_obj_t));
    memset(obj, 0, sizeof(botan_totp_obj_t));

    JanetByteView key = janet_getbytes(argv, 0);

    const char *hash = "SHA-1";
    if (argc >= 2) {
        hash = janet_getcstring(argv, 1);
    }

    size_t digits = 6;
    if (argc >= 3) {
        digits = janet_getsize(argv, 2);
    }

    size_t timestep = 30;
    if (argc == 4) {
        timestep = janet_getsize(argv, 3);
    }

    int ret = botan_totp_init(&obj->totp, key.bytes, key.len, hash, digits, timestep);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_abstract(obj);
}

static Janet totp_generate(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);

    botan_totp_obj_t *obj = janet_getabstract(argv, 0, get_totp_obj_type());
    botan_totp_t totp = obj->totp;

    uint64_t timestamp = (uint64_t)time(NULL);
    if (argc == 2) {
        timestamp = janet_getuinteger64(argv, 1);
    }

    uint32_t code = 0;
    int ret = botan_totp_generate(totp, &code, timestamp);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_number((double)code);
}

static Janet totp_check(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 4);

    botan_totp_obj_t *obj = janet_getabstract(argv, 0, get_totp_obj_type());
    botan_totp_t totp = obj->totp;
    uint32_t code = (uint32_t)janet_getsize(argv, 1);

    uint64_t timestamp = (uint64_t)time(NULL);
    if (argc >= 3) {
        timestamp = janet_getuinteger64(argv, 2);
    }

    size_t acceptable_drift = 0;
    if (argc == 4) {
        acceptable_drift = janet_getsize(argv, 3);
    }

    int ret = botan_totp_check(totp, code, timestamp, acceptable_drift);
    JANET_BOTAN_ASSERT(ret);

    return janet_wrap_boolean(ret == 0);
}

static JanetReg totp_cfuns[] = {
    {"totp/new", totp_new,
     "(totp/new key &opt hash digits timestep)\n\n"
     "Instantiate a new TOTP instance with the given parameters. If omitted, "
     "the default value for `hash` is \"SHA-1\", the default value for "
     "`digits` is 6 and the default value for `timestep` is 30."
    },
    {"totp/generate", totp_generate,
     "(totp/generate totp &opt timestamp)\n\n"
     "Generate an TOTP code for the provided `timestamp`. If omitted, current "
     "timestamp is used."
    },
    {"totp/check", totp_check,
     "(totp/check totp code &opt timestamp acceptable-drift)\n\n"
     "Return true if the provided OTP `code` is correct for the provided "
     "`timestamp`. If required, use clock `acceptable-drift` to deal with the "
     "client and server having slightly different clocks. If omitted, current "
     "timestamp is used for `timestamp` and the default value for "
     "`acceptable-drift` is 0."
    },

    {NULL, NULL, NULL}
};

static void submod_totp(JanetTable *env) {
    janet_cfuns(env, "botan", totp_cfuns);
}

#endif /* BOTAN_TOTP_H */
